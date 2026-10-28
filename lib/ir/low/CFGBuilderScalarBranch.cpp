//===- CFGBuilderScalarBranch.cpp - Exact scalar control transfers --------===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
/// \file
/// Recovers exact constant branch targets before tail-call conversion.
/// Unknown live-ins, mutable loads and partial writes never invent facts.

#include "LowScalarExpression.h"
#include "LowScalarTargets.h"

#include "neverd/ir/low/CFGBuilder.h"
#include "neverd/ir/low/LowScalarConstant.h"
#include "neverd/loader/ReadOnlyBytes.h"

#include <algorithm>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace neverd {

bool CFGBuilder::recoverComputedScalarBranches(const BinaryImage &Img,
                                               Decoder &Dec, LowFunc &Func,
                                               size_t &RemainingWork) {
  if (Img.Arch != Arch::X86 && Img.Arch != Arch::X64)
    return false;
  if (std::none_of(Insns.begin(), Insns.end(), [](const auto &Entry) {
        const auto &R = Entry.second;
        return R.ComputedScalarTargets ||
               (R.IsBranch && R.IsIndirect && !R.IsCall && !R.IsCond &&
                !R.IsRet && !R.RejectedComputedTargets &&
                R.JumpTableTargets.empty());
      }))
    return false;
  const auto Targets = finiteScalarBranchTargets(Func, RemainingWork);
  bool Changed = false;
  std::vector<va_t> Explore;
  for (auto &[Address, Rec] : Insns) {
    if (!Rec.IsBranch || !Rec.IsIndirect || Rec.IsCall || Rec.IsCond ||
        Rec.IsRet || Rec.RejectedComputedTargets ||
        (!Rec.ComputedScalarTargets && !Rec.JumpTableTargets.empty()))
      continue;
    std::vector<va_t> Values;
    if (Targets)
      if (const auto Found = Targets->find(Address); Found != Targets->end())
        Values = Found->second;
    // Singleton transfers belong to exact-branch recovery. This owner
    // publishes switches with a runtime selector, not constant selectors
    // whose code identity needs a different downstream binding.
    const bool Valid =
        Values.size() > 1 &&
        std::all_of(Values.begin(), Values.end(), [&](va_t T) {
          return T != InvalidVA && !isTailCallTarget(T) &&
                 Img.hasExecutableCodeOwnerRange(T, getInsnAlignment()) &&
                 Img.readVA(T, getInsnAlignment());
        });
    if (!Valid) {
      if (Rec.ComputedScalarTargets) {
        Rec.JumpTableTargets.clear();
        Rec.ComputedScalarTargets = false;
        Rec.RejectedComputedTargets = true;
        Changed = true;
      }
      continue;
    }
    if (Rec.ComputedScalarTargets && Rec.JumpTableTargets == Values)
      continue;
    Rec.ComputedScalarTargets = true;
    Rec.JumpTableTargets = Values;
    ResolvedTableInfo.erase(Address);
    for (va_t Target : Values) {
      BlockStarts.insert(Target);
      Explore.push_back(Target);
    }
    Changed = true;
  }
  if (Changed) {
    for (va_t Target : Explore)
      if (!ExploredAddrs.count(Target))
        explore(Img, Dec, Target);
    exploreAddressTakenRoots(Img, Dec);
    splitBlocks();
    rebuildBlocks(Func);
  }
  return Changed;
}

bool CFGBuilder::recoverScalarConstantBranches(const BinaryImage &Img,
                                               Decoder &Dec, LowFunc &Func,
                                               size_t &RemainingWork,
                                               ScalarImageFacts &ImageScalars) {
  // ARM32 state-changing branches require a separate instruction-mode proof.
  if (Img.Arch != Arch::X86 && Img.Arch != Arch::X64 &&
      Img.Arch != Arch::AArch64)
    return false;
  if (std::none_of(Insns.begin(), Insns.end(), [](const auto &Entry) {
        const auto &Rec = Entry.second;
        return Rec.ScalarBranchInput ||
               (Rec.IsBranch && Rec.IsIndirect && !Rec.IsCond && !Rec.IsCall &&
                !Rec.IsRet && !Rec.RejectedScalarBranch &&
                !Rec.RejectedComputedTargets && Rec.JumpTableTargets.empty());
      }))
    return false;

  bool Changed = false;
  // All image metadata is fixed throughout discovery. Cache failures as well
  // as successes so repeated instructions/rounds do not rescan the image.
  auto Spend = [&](size_t Work) {
    if (Work > RemainingWork) {
      RemainingWork = 0;
      return false;
    }
    RemainingWork -= Work;
    return true;
  };
  auto Restore = [&](InsnRecord &Rec) {
    if (!Rec.ScalarBranchInput)
      return false;
    for (LowOp &Op : Rec.Ops)
      if (Op.Opcode == NdOp::BRANCH && Op.NumInputs == 1) {
        Op.Opcode = NdOp::INDIR_BR;
        Op.Inputs[0] = *Rec.ScalarBranchInput;
        Rec.IsIndirect = true;
        Rec.BranchTarget = InvalidVA;
        Rec.Immediate.reset();
        Rec.ScalarBranchInput.reset();
        Rec.RejectedScalarBranch = true;
        return true;
      }
    return false;
  };

  for (;;) {
    std::map<va_t, std::optional<uint64_t>> Targets;
    bool Complete = true;
    for (const LowBlock &Block : Func.Blocks) {
      if (!Spend(1)) {
        Complete = false;
        break;
      }
      if (Block.InstructionBoundaries.empty())
        continue;
      const auto Last = Insns.find(Block.InstructionBoundaries.back().Address);
      if (Last == Insns.end()) {
        Complete = false;
        break;
      }
      const auto &Terminator = Last->second;
      if (!Terminator.ScalarBranchInput &&
          (!Terminator.IsBranch || !Terminator.IsIndirect ||
           Terminator.IsCond || Terminator.IsCall || Terminator.IsRet ||
           Terminator.RejectedScalarBranch ||
           Terminator.RejectedComputedTargets ||
           !Terminator.JumpTableTargets.empty()))
        continue;
      // Byte facts preserve architectural subregister overlap exactly. Temps
      // have identities, not byte offsets, and live for one instruction only.
      std::map<uint64_t, uint8_t> Registers;
      std::map<uint64_t, std::pair<uint16_t, uint64_t>> Temps;
      auto ValueOf = [&](const NdVar &Value) -> std::optional<uint64_t> {
        if (!Spend(1 + Value.Size) || !Value.Size || Value.Size > 8)
          return std::nullopt;
        if (Value.isConst())
          return Value.Offset & (UINT64_MAX >> ((8 - Value.Size) * 8));
        if (Value.isTemp()) {
          const auto At = Temps.find(Value.Offset);
          return At != Temps.end() && At->second.first == Value.Size
                     ? std::optional<uint64_t>{At->second.second}
                     : std::nullopt;
        }
        if (!Value.isReg() || Value.Offset > UINT64_MAX - Value.Size)
          return std::nullopt;
        uint64_t Result = 0;
        for (uint16_t I = 0; I < Value.Size; ++I) {
          const auto At = Registers.find(Value.Offset + I);
          if (At == Registers.end())
            return std::nullopt;
          Result |= uint64_t{At->second} << (I * 8);
        }
        return Result;
      };
      for (const LowInstructionBoundary &Boundary :
           Block.InstructionBoundaries) {
        if (!Spend(1 + Temps.size())) {
          Complete = false;
          break;
        }
        Temps.clear();
        const auto At = Insns.find(Boundary.Address);
        if (At == Insns.end()) {
          Complete = false;
          break;
        }
        const InsnRecord &Rec = At->second;
        for (const LowOp &Op : Rec.Ops) {
          if (!Spend(1)) {
            Complete = false;
            break;
          }
          if (Rec.IsBranch && !Rec.IsCond && !Rec.IsCall && !Rec.IsRet &&
              !Rec.RejectedScalarBranch && !Rec.RejectedComputedTargets &&
              Rec.JumpTableTargets.empty() && Op.NumInputs == 1 &&
              (Op.Opcode == NdOp::INDIR_BR ||
               (Op.Opcode == NdOp::BRANCH && Rec.ScalarBranchInput))) {
            Targets[Rec.Addr] =
                ValueOf(Rec.ScalarBranchInput.value_or(Op.Inputs[0]));
          }
          if (Op.Opcode == NdOp::CALL || Op.Opcode == NdOp::INDIR_CALL) {
            if (!Spend(Registers.size() + Temps.size())) {
              Complete = false;
              break;
            }
            Registers.clear();
            Temps.clear();
          }
          const NdVar &Output = Op.Output;
          if (!Output.isReg() && !Output.isTemp())
            continue;
          auto Result = lowScalarConstantResult(Op, ValueOf);
          if (Op.Opcode == NdOp::LOAD && Op.NumInputs == 1 && Output.Size &&
              Output.Size <= sizeof(uint64_t) &&
              Op.Inputs[0].Size >= Img.getPointerSize() &&
              Op.MemoryOrdering == NdMemoryOrdering::None &&
              Op.MemoryAddressSpace == NdMemoryAddressSpace::Default) {
            if (auto Address = ValueOf(Op.Inputs[0])) {
              const auto Key = std::make_pair(*Address, Output.Size);
              auto [It, Inserted] = ImageScalars.try_emplace(Key);
              if (Inserted)
                It->second = readImmutableImageScalar(
                    Img, *Address, Output.Size, &RemainingWork);
              Result = It->second;
            }
          }
          if (!Spend(1 + Output.Size)) {
            Complete = false;
            break;
          }
          if (Output.isTemp()) {
            if (Result)
              Temps[Output.Offset] = {Output.Size, *Result};
            else
              Temps.erase(Output.Offset);
          } else if (Output.Offset <= UINT64_MAX - Output.Size) {
            for (uint16_t I = 0; I < Output.Size; ++I)
              if (Result)
                Registers[Output.Offset + I] = uint8_t(*Result >> (I * 8));
              else
                Registers.erase(Output.Offset + I);
          } else
            Registers.clear();
        }
        if (!Complete)
          break;
        if (Rec.IsOpaqueTerminator || Rec.IsInstructionGuard) {
          if (!Spend(Registers.size() + Temps.size())) {
            Complete = false;
            break;
          }
          Registers.clear();
          Temps.clear();
        }
      }
      if (!Complete || RemainingWork == 0) {
        Complete = false;
        break;
      }
      const auto Target = Targets.find(Terminator.Addr);
      if (Target != Targets.end() && !Target->second)
        for (size_t I = 0; I < Block.Ops.size(); ++I) {
          const LowOp &Op = Block.Ops[I];
          if (Op.Addr == Terminator.Addr && Op.NumInputs == 1 &&
              (Op.Opcode == NdOp::INDIR_BR ||
               (Op.Opcode == NdOp::BRANCH && Terminator.ScalarBranchInput))) {
            Target->second = constantScalarExpression(
                llvm::ArrayRef<LowOp>(Block.Ops).take_front(I),
                Terminator.ScalarBranchInput.value_or(Op.Inputs[0]),
                Terminator.Addr, RemainingWork);
            break;
          }
        }
    }
    if (!Complete) {
      // No prefix of an incomplete proof can retain authority after new edges
      // have been explored. Restoring is bounded by the decoded instruction
      // inventory and cannot start more exploration.
      bool Restored = false;
      for (auto &[Addr, Rec] : Insns)
        Restored |= Restore(Rec);
      if (Restored)
        rebuildBlocks(Func);
      return Changed || Restored;
    }

    bool RoundChanged = false;
    std::vector<va_t> Explore;
    for (const auto &[Addr, Target] : Targets) {
      auto &Rec = Insns.at(Addr);
      // An exact transfer has the same reachability authority as a decoded
      // direct branch. A next-entry bound limits speculative address roots,
      // not discontiguous or backward control flow. explore() still keeps
      // independent function entries as tail calls and checks code ownership
      // for every instruction it reaches.
      const bool Valid =
          Target && *Target != InvalidVA &&
          (*Target % getInsnAlignment()) == 0 &&
          Img.hasExecutableCodeOwnerRange(*Target, getInsnAlignment()) &&
          Img.readVA(*Target, getInsnAlignment());
      if (Rec.ScalarBranchInput) {
        if (!Valid || *Target != Rec.BranchTarget)
          RoundChanged |= Restore(Rec);
        continue;
      }
      if (!Valid)
        continue;
      for (LowOp &Op : Rec.Ops) {
        if (Op.Opcode != NdOp::INDIR_BR || Op.NumInputs != 1)
          continue;
        Rec.ScalarBranchInput = Op.Inputs[0];
        Op.Opcode = NdOp::BRANCH;
        Op.Inputs[0] = NdVar::cst(*Target, Img.getPointerSize());
        Rec.IsIndirect = false;
        Rec.BranchTarget = *Target;
        Rec.Immediate = *Target;
        BlockStarts.insert(*Target);
        Explore.push_back(*Target);
        RoundChanged = true;
        break;
      }
    }
    if (!RoundChanged)
      return Changed;
    Changed = true;
    for (va_t Target : Explore)
      if (!ExploredAddrs.count(Target))
        explore(Img, Dec, Target);
    exploreAddressTakenRoots(Img, Dec);
    splitBlocks();
    rebuildBlocks(Func);
  }
}

} // namespace neverd
