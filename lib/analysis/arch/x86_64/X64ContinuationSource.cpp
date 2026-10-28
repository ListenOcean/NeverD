//===- X64ContinuationSource.cpp - Explicit native continuation C --------===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
/// \file
/// State transport and physical transfers before ordinary source conversion.

#include "neverd/analysis/arch/x86_64/X64ContinuationSource.h"

#include "BinaryContinuationInstructions.h"
#include "NativeStackControl.h"
#include "X64ControlTransitions.h"
#include "X64MachineFlags.h"
#include "X64Recovery.h"
#include "X64TaskPriority.h"

#include "neverd/ir/SourceABI.h"
#include "neverd/ir/TargetRegInfo.h"
#include "neverd/ir/intrinsics/Intrinsics.h"
#include "neverd/ir/low/LowScalarConstant.h"
#include "neverd/lift/X86/X86Regs.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Support/Errc.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace neverd::analysis {
namespace {
using State = X64ContinuationStateV1;
using StateV2 = X64ContinuationStateV2;
using StateV4 = X64ContinuationStateV4;
using Exit = X64ContinuationExitV1;
using Flags = detail::X64MachineFlags;
constexpr uint64_t StatePointer = uint64_t{1} << 32;
constexpr uint64_t ScratchBase = uint64_t{1} << 61;

InterpreterMachineStateProfile
flagsProfile(const X64ContinuationSourceOptions &Options) {
  return (Options.Profile == X64ContinuationProfile::KernelSmapNoFaultV3 ||
          Options.Profile ==
              X64ContinuationProfile::KernelFaultAddressNoFaultV4)
             ? InterpreterMachineStateProfile::KernelX64SmapNoFaultV2
             : InterpreterMachineStateProfile::KernelX64NoFaultV1;
}

bool hasControlState(const X64ContinuationSourceOptions &Options) {
  return Options.Profile == X64ContinuationProfile::KernelControlsNoFaultV2 ||
         Options.Profile == X64ContinuationProfile::KernelSmapNoFaultV3 ||
         Options.Profile == X64ContinuationProfile::KernelFaultAddressNoFaultV4;
}

static_assert(std::is_standard_layout_v<State>);
static_assert(offsetof(State, RFlags) == 128);
static_assert(offsetof(State, PC) == 136);
static_assert(offsetof(State, FSBase) == 144);
static_assert(offsetof(State, GSBase) == 152);
static_assert(offsetof(State, ZMM) == 160);
static_assert(offsetof(State, Undefined) == 2208);
static_assert(sizeof(State) == 2272);
static_assert(std::is_standard_layout_v<StateV2>);
static_assert(offsetof(StateV2, Core) == 0);
static_assert(offsetof(StateV2, CR8) == 2272);
static_assert(offsetof(StateV2, KernelGSBase) == 2280);
static_assert(offsetof(StateV2, MXCSR) == 2288);
static_assert(sizeof(StateV2) == 2304);
static_assert(std::is_standard_layout_v<StateV4>);
static_assert(offsetof(StateV4, Core) == 0);
static_assert(offsetof(StateV4, CR2) == 2304);
static_assert(sizeof(StateV4) == 2320);

llvm::Error invalid(const llvm::Twine &Text) {
  return llvm::createStringError(llvm::errc::invalid_argument, "%s",
                                 Text.str().c_str());
}

NdVar constant(uint64_t Value, uint16_t Bytes = 8) {
  return NdVar::scalar(Value, Bytes);
}

std::optional<unsigned> flagBit(NdVar V) {
  if (V.Size == 1)
    for (const auto &[Offset, Bit] : Flags::Flags)
      if (V.Offset == Offset)
        return Bit;
  return std::nullopt;
}

std::optional<uint64_t> stateOffset(NdVar V) {
  if (V.Offset < x86reg::RIP && V.Size <= 8 && V.Offset % 8 + V.Size <= 8)
    return offsetof(State, GPR) + V.Offset;
  if (V.Offset >= x86reg::VectorBase && V.Size <= 16 &&
      V.Offset < x86reg::OpmaskBase &&
      (V.Offset - x86reg::VectorBase) % x86reg::VectorRegStride + V.Size <=
          x86reg::VectorRegStride)
    return offsetof(State, ZMM) + V.Offset - x86reg::VectorBase;
  return std::nullopt;
}

bool supportedValue(NdVar V, bool WideDivision = false) {
  if (!V.Size)
    return true;
  if (V.isReg())
    return flagBit(V).has_value() || stateOffset(V).has_value();
  if (V.isTemp())
    return V.Size <= 16 && V.Offset < ScratchBase - V.Size;
  return V.isConst() && V.Size <= (WideDivision ? 16 : 8);
}

bool flagIntrinsic(const LowOp &Op) {
  if (Op.Opcode != NdOp::INTRINSIC || !Op.NumInputs || !Op.Inputs[0].isConst())
    return false;
  const auto I = static_cast<Intrinsic>(Op.Inputs[0].Offset);
  return I == Intrinsic::Pushf || I == Intrinsic::Cli || I == Intrinsic::Sti ||
         I == Intrinsic::Clac || I == Intrinsic::Stac;
}

bool alignmentIntrinsic(LowOp Op) {
  if (Op.Opcode != NdOp::INTRINSIC)
    return false;
  // The address is materialized with the live FS/GS base before emission.
  Op.MemoryAddressSpace = NdMemoryAddressSpace::Default;
  SpecializationOptions Options;
  Options.ExplicitMachineState = true;
  Options.NormalNonfaultingExecution = true;
  return x64::alignment::supportsOperation(Op, Options);
}

SpecializationOptions
controlOptions(const X64ContinuationSourceOptions &Options) {
  SpecializationOptions Controls;
  Controls.Architecture = Arch::X64;
  Controls.ExplicitMachineState = true;
  Controls.NormalNonfaultingExecution = true;
  Controls.X64FlagsProfile = flagsProfile(Options);
  if (hasControlState(Options)) {
    Controls.X64MXCSRMask = Options.MXCSRMask;
    Controls.X64LegacyGSState = true;
  }
  return Controls;
}

bool controlIntrinsic(LowOp Op, const X64ContinuationSourceOptions &Options) {
  if (!hasControlState(Options))
    return false;
  Op.MemoryAddressSpace = NdMemoryAddressSpace::Default;
  const auto Controls = controlOptions(Options);
  return detail::taskPriorityOperation(Op).has_value() ||
         x64::mxcsr::supportsScalarOperation(Op, Controls) ||
         x64::legacygs::supportsOperation(Op, Controls);
}

bool faultAddressIntrinsic(const LowOp &Op,
                           const X64ContinuationSourceOptions &Options) {
  if (Options.Profile != X64ContinuationProfile::KernelFaultAddressNoFaultV4 ||
      Op.Opcode != NdOp::INTRINSIC || !Op.NumInputs ||
      !Op.Inputs[0].isConst() || Op.Inputs[0].Size != 2 ||
      Op.MemoryAddressSpace != NdMemoryAddressSpace::Default)
    return false;
  const auto Id = static_cast<Intrinsic>(Op.Inputs[0].Offset);
  return (Id == Intrinsic::ReadCr2 && Op.NumInputs == 1 &&
          Op.Output.Size == 8) ||
         (Id == Intrinsic::WriteCr2 && Op.NumInputs == 2 && !Op.Output.Size &&
          Op.Inputs[1].Size == 8);
}

bool fenceIntrinsic(const LowOp &Op,
                    const X64ContinuationSourceOptions &Options) {
  return hasControlState(Options) && Op.Opcode == NdOp::INTRINSIC &&
         !Op.Output.Size && Op.NumInputs == 1 && Op.Inputs[0].isConst() &&
         Op.Inputs[0].Size == 2 &&
         Op.Inputs[0].Offset == uint64_t(Intrinsic::Lfence) &&
         Op.MemoryAddressSpace == NdMemoryAddressSpace::Default;
}

bool writePrefetchIntrinsic(const LowOp &Op,
                            const X64ContinuationSourceOptions &Options) {
  return Options.NativeWritePrefetch && Op.Opcode == NdOp::INTRINSIC &&
         !Op.Output.Size && Op.NumInputs == 2 && Op.Inputs[0].isConst() &&
         Op.Inputs[0].Size == 2 &&
         Op.Inputs[0].Offset == uint64_t(Intrinsic::PrefetchW) &&
         Op.Inputs[1].Size == 8;
}

bool unsignedWideDivisionIntrinsic(const LowOp &Op) {
  return Op.Opcode == NdOp::INTRINSIC && Op.NumInputs &&
         Op.Inputs[0].isConst() &&
         Op.Inputs[0].Offset ==
             uint64_t(Intrinsic::X86RequireDivPrecondition) &&
         intrinsicX86DivPreconditionShapeIsValid(
             Intrinsic::X86RequireDivPrecondition,
             x86DivPreconditionLowShape(Op, Arch::X64)) &&
         Op.Inputs[1].Size == 16 &&
         Op.Inputs[3].Offset == uint64_t(X86DivKind::Unsigned);
}

bool wideDivisionArithmetic(const LowOp &Op) {
  if (Op.Output.Size != 16)
    return false;
  if (Op.Opcode == NdOp::INT_ZEXT)
    return Op.NumInputs == 1 && Op.Inputs[0].Size == 8;
  if (Op.NumInputs != 2 || Op.Inputs[0].Size != 16 || Op.Inputs[1].Size != 16)
    return false;
  if (Op.Opcode == NdOp::INT_LEFT)
    return Op.Inputs[1].isConst() && Op.Inputs[1].Offset == 64;
  return Op.Opcode == NdOp::INT_OR || Op.Opcode == NdOp::INT_DIV ||
         Op.Opcode == NdOp::INT_REM;
}

bool supportedOperation(const LowOp &Op,
                        const X64ContinuationSourceOptions &Options,
                        bool WideDivision) {
  const bool AtomicAdd =
      hasControlState(Options) && Op.Opcode == NdOp::ATOMIC_ADD &&
      Op.NumInputs == 2 && Op.Output.isTemp() &&
      (Op.Output.Size == 1 || Op.Output.Size == 2 || Op.Output.Size == 4 ||
       Op.Output.Size == 8) &&
      Op.Inputs[0].Size == 8 && Op.Inputs[1].Size == Op.Output.Size &&
      Op.MemoryOrdering == NdMemoryOrdering::SequentiallyConsistent;
  if (Op.NumInputs > std::size(Op.Inputs) ||
      !supportedValue(Op.Output, WideDivision) ||
      (Op.MemoryOrdering != NdMemoryOrdering::None && !AtomicAdd) ||
      !isKnownMemoryAddressSpace(Op.MemoryAddressSpace))
    return false;
  for (unsigned I = 0; I < Op.NumInputs; ++I)
    if (!supportedValue(Op.Inputs[I], WideDivision))
      return false;
  if (Op.MemoryAddressSpace != NdMemoryAddressSpace::Default &&
      Op.Opcode != NdOp::LOAD && Op.Opcode != NdOp::STORE && !AtomicAdd &&
      !alignmentIntrinsic(Op) && !controlIntrinsic(Op, Options) &&
      !writePrefetchIntrinsic(Op, Options))
    return false;
  if (AtomicAdd)
    return true;
  if (WideDivision &&
      (unsignedWideDivisionIntrinsic(Op) || wideDivisionArithmetic(Op)))
    return true;
  switch (Op.Opcode) {
  case NdOp::COPY:
  case NdOp::LOAD:
  case NdOp::STORE:
  case NdOp::SELECT:
  case NdOp::CONCAT:
  case NdOp::SUBBYTES:
  case NdOp::BRANCH:
  case NdOp::COND_BR:
  case NdOp::INDIR_BR:
  case NdOp::NOP:
  case NdOp::POPCOUNT:
  case NdOp::LZCOUNT:
  case NdOp::INT_CARRY:
  case NdOp::INT_SOVF:
  case NdOp::INT_SBOR:
    return true;
  case NdOp::INT_AND:
    // The lifter masks CL into an operand-width count. The constant-analysis
    // query below intentionally accepts only equal-width operands; mixed-width
    // bitwise operations still use the existing LowToMed/backend semantics.
    return Op.NumInputs == 2 && Op.Output.Size && Op.Output.Size <= 8 &&
           Op.Inputs[0].Size && Op.Inputs[0].Size <= Op.Output.Size &&
           Op.Inputs[1].Size && Op.Inputs[1].Size <= Op.Output.Size;
  case NdOp::INT_XOR:
    // Scalar and legacy whole-vector XOR share the existing integer lowering.
    return Op.NumInputs == 2 && Op.Output.Size && Op.Output.Size <= 16 &&
           Op.Inputs[0].Size == Op.Output.Size &&
           Op.Inputs[1].Size == Op.Output.Size;
  case NdOp::INTRINSIC:
    return flagIntrinsic(Op) || alignmentIntrinsic(Op) ||
           controlIntrinsic(Op, Options) ||
           faultAddressIntrinsic(Op, Options) || fenceIntrinsic(Op, Options) ||
           writePrefetchIntrinsic(Op, Options);
  default:
    // Admission and arithmetic widths use the scalar owner. The operation
    // itself is still emitted through LowToMed and the existing backends.
    return bool(lowScalarConstantResult(
        Op, [](const NdVar &) { return std::optional<uint64_t>{1}; }));
  }
}

struct Writer {
  LowFunc &Function;
  LowBlock *Block;
  const X64ContinuationSourceOptions &Options;
  uint64_t Next = ScratchBase;

  NdVar temporary(uint16_t Bytes = 8) {
    const NdVar V = NdVar::tmp(Next, Bytes);
    Next += 16;
    return V;
  }

  void emit(NdOp Code, NdVar Output, std::initializer_list<NdVar> Inputs) {
    LowOp Op;
    Op.Opcode = Code;
    Op.Output = Output;
    for (NdVar V : Inputs)
      Op.addInput(V);
    Block->Ops.push_back(Op);
  }

  void append(llvm::ArrayRef<LowOp> Ops) {
    Block->Ops.insert(Block->Ops.end(), Ops.begin(), Ops.end());
  }

  void rejectIf(NdVar Bad) {
    const int NextId = static_cast<int>(Function.Blocks.size());
    LowBlock NextBlock;
    NextBlock.Id = NextId;
    NextBlock.StartAddr = Function.Entry + NextId;
    NextBlock.Preds = {Block->Id};
    Function.Blocks[2].Preds.push_back(Block->Id);
    Block->Succs = {NextId, 2};
    emit(NdOp::COND_BR, {}, {NdVar::cst(Function.Blocks[2].StartAddr, 8), Bad});
    Function.Blocks.push_back(std::move(NextBlock));
    Block = &Function.Blocks.back();
  }

  NdVar address(uint64_t Offset) {
    const NdVar V = temporary();
    emit(NdOp::INT_ADD, V, {NdVar::reg(StatePointer, 8), constant(Offset)});
    return V;
  }

  NdVar load(uint64_t Offset, uint16_t Bytes = 8) {
    const NdVar V = temporary(Bytes);
    emit(NdOp::LOAD, V, {address(Offset)});
    return V;
  }

  void store(uint64_t Offset, NdVar V) {
    emit(NdOp::STORE, {}, {address(Offset), V});
  }

  NdVar read(NdVar V) {
    if (V.isConst())
      return constant(V.Offset, V.Size);
    if (!V.isReg())
      return V;
    if (const auto Bit = flagBit(V)) {
      const NdVar Shifted = temporary(), Masked = temporary();
      emit(NdOp::INT_RIGHT, Shifted,
           {load(offsetof(State, RFlags)), constant(*Bit)});
      emit(NdOp::INT_AND, Masked, {Shifted, constant(1)});
      const NdVar Result = temporary(1);
      emit(NdOp::INT_NOTEQUAL, Result, {Masked, constant(0)});
      return Result;
    }
    return load(*stateOffset(V), V.Size);
  }

  void write(NdVar Destination, NdVar Value, bool LowSlice = false) {
    if (!Destination.isReg()) {
      emit(NdOp::COPY, Destination, {Value});
      return;
    }
    if (const auto Bit = flagBit(Destination)) {
      const NdVar Kept = temporary(), Extended = temporary();
      const NdVar Shifted = temporary(), Packed = temporary();
      emit(NdOp::INT_AND, Kept,
           {load(offsetof(State, RFlags)), constant(~(uint64_t{1} << *Bit))});
      emit(NdOp::INT_ZEXT, Extended, {Value});
      emit(NdOp::INT_LEFT, Shifted, {Extended, constant(*Bit)});
      emit(NdOp::INT_OR, Packed, {Kept, Shifted});
      store(offsetof(State, RFlags), Packed);
      return;
    }
    if (Destination.Offset < x86reg::RIP && !LowSlice &&
        getTargetRegInfo(Arch::X64).writeZeroExtends(Destination.Offset,
                                                     Destination.Size)) {
      const NdVar Full = temporary();
      emit(NdOp::INT_ZEXT, Full, {Value});
      store(offsetof(State, GPR) + Destination.Offset, Full);
      return;
    }
    store(*stateOffset(Destination), Value);
  }

  void leave(Exit Kind, std::optional<NdVar> PC = std::nullopt) {
    if (PC)
      store(offsetof(State, PC), *PC);
    emit(NdOp::COPY, NdVar::reg(x86reg::RAX, 8),
         {constant(static_cast<uint64_t>(Kind))});
    emit(NdOp::RETURN, {}, {NdVar::reg(x86reg::RAX, 8)});
  }

  void undefined(const LowUndefinedEffect &Effect, size_t Index) {
    const NdVar Witness =
        load(offsetof(State, Undefined) + Index * 8, Effect.Output.Size);
    const uint64_t Bits = UINT64_MAX >> (64 - Effect.BitCount);
    const uint64_t Mask = Bits << Effect.BitOffset;
    const auto K = [&](uint64_t Value) {
      return constant(Value, Effect.Output.Size);
    };
    const NdVar Limited = temporary(Effect.Output.Size);
    const NdVar Shifted = temporary(Effect.Output.Size);
    const NdVar Kept = temporary(Effect.Output.Size);
    const NdVar Updated = temporary(Effect.Output.Size);
    // A complete unconditional arbitrary production needs no previous value;
    // an instruction-local carrier may not have existed before this point.
    const bool Whole =
        Effect.BitOffset == 0 && Effect.BitCount == Effect.Output.Size * 8;
    const NdVar Old = Whole && !Effect.When ? K(0) : read(Effect.Output);
    emit(NdOp::INT_AND, Limited, {Witness, K(Bits)});
    emit(NdOp::INT_LEFT, Shifted, {Limited, K(Effect.BitOffset)});
    emit(NdOp::INT_AND, Kept, {Old, K(~Mask)});
    emit(NdOp::INT_OR, Updated, {Kept, Shifted});
    NdVar Result = Updated;
    if (Effect.When) {
      Result = temporary(Effect.Output.Size);
      emit(NdOp::SELECT, Result, {read(*Effect.When), Updated, Old});
    }
    // Architectural arbitrary bits alter this byte view, not an EAX write.
    write(Effect.Output, Result, true);
  }

  void operation(LowOp Op) {
    const NdVar NativeOutput = Op.Output;
    const bool LowSlice =
        Op.Opcode == NdOp::SUBBYTES && Op.NumInputs == 2 &&
        Op.Inputs[0].isReg() && Op.Inputs[1].isConst() &&
        isSameRegisterLowSlice(NativeOutput.Offset, NativeOutput.Size,
                               Op.Inputs[0].Offset, Op.Inputs[0].Size,
                               Op.Inputs[1].Offset);
    if (NativeOutput.isReg())
      Op.Output = temporary(NativeOutput.Size);
    for (unsigned I = 0; I < Op.NumInputs; ++I)
      Op.Inputs[I] = read(Op.Inputs[I]);
    if (Op.MemoryAddressSpace != NdMemoryAddressSpace::Default) {
      const NdVar Linear = temporary();
      const auto Base = Op.MemoryAddressSpace == NdMemoryAddressSpace::X86FS
                            ? offsetof(State, FSBase)
                            : offsetof(State, GSBase);
      const unsigned AddressInput = Op.Opcode == NdOp::INTRINSIC ? 1 : 0;
      emit(NdOp::INT_ADD, Linear, {load(Base), Op.Inputs[AddressInput]});
      Op.Inputs[AddressInput] = Linear;
      Op.MemoryAddressSpace = NdMemoryAddressSpace::Default;
    }
    if (unsignedWideDivisionIntrinsic(Op)) {
      // Reject a faulting invocation before any architectural write. For an
      // unsigned 128/64 division, high < divisor implies both nonzero divisor
      // and a representable quotient. Retain the original precondition below:
      // the native intrinsic remains the authority for division execution.
      const NdVar High = temporary(), Bad = temporary(1);
      emit(NdOp::SUBBYTES, High, {Op.Inputs[1], constant(8)});
      emit(NdOp::INT_LESSEQUAL, Bad, {Op.Inputs[2], High});
      rejectIf(Bad);
      Block->Ops.push_back(Op);
    } else if (flagIntrinsic(Op)) {
      const NdVar System = temporary();
      emit(NdOp::INT_AND, System,
           {load(offsetof(State, RFlags)), constant(~Flags::SplitMask)});
      auto Transition = detail::lowerX64MachineFlags(
          Op, System, [&](uint16_t Bytes) { return temporary(Bytes); },
          flagsProfile(Options));
      // Admission checked this exact shape before any output was published.
      append(Transition->Ops);
      const NdVar Split = temporary(), Packed = temporary();
      emit(NdOp::INT_AND, Split,
           {load(offsetof(State, RFlags)), constant(Flags::SplitMask)});
      emit(NdOp::INT_OR, Packed, {System, Split});
      store(offsetof(State, RFlags), Packed);
    } else if (faultAddressIntrinsic(Op, Options)) {
      if (Op.Inputs[0].Offset == uint64_t(Intrinsic::ReadCr2))
        emit(NdOp::COPY, Op.Output, {load(offsetof(StateV4, CR2))});
      else
        store(offsetof(StateV4, CR2), Op.Inputs[1]);
    } else if (detail::taskPriorityOperation(Op)) {
      const NdVar Priority = load(offsetof(StateV2, CR8));
      const auto Transition = detail::lowerX64TaskPriority(
          Op, Priority, [&](uint16_t Bytes) { return temporary(Bytes); });
      append(Transition->Ops);
      if (Transition->Rejected) {
        rejectIf(*Transition->Rejected);
        store(offsetof(StateV2, CR8), Priority);
      }
    } else if (x64::mxcsr::supportsScalarOperation(Op,
                                                   controlOptions(Options))) {
      const NdVar Slot = load(offsetof(StateV2, MXCSR), 4);
      const auto Transition = x64::mxcsr::lowerScalarOperation(
          Op, Slot, *Options.MXCSRMask,
          [&](uint16_t Bytes) { return temporary(Bytes); });
      append(Transition->Ops);
      if (Transition->Rejected)
        rejectIf(*Transition->Rejected);
      if (Transition->OutputState)
        store(offsetof(StateV2, MXCSR), Slot);
    } else if (x64::legacygs::supportsOperation(Op, controlOptions(Options))) {
      const NdVar Pair = temporary(16);
      emit(NdOp::CONCAT, Pair,
           {load(offsetof(StateV2, KernelGSBase)),
            load(offsetof(State, GSBase))});
      const auto Transition = x64::legacygs::lowerScalarOperation(
          Op, Pair, [&](uint16_t Bytes) { return temporary(Bytes); });
      append(Transition->Ops);
      const NdVar Active = temporary(), Inactive = temporary();
      emit(NdOp::SUBBYTES, Active, {Pair, constant(0)});
      emit(NdOp::SUBBYTES, Inactive, {Pair, constant(8)});
      store(offsetof(State, GSBase), Active);
      store(offsetof(StateV2, KernelGSBase), Inactive);
    } else {
      Block->Ops.push_back(Op);
    }
    if (NativeOutput.isReg())
      write(NativeOutput, Op.Output, LowSlice);
  }
};

void finishBlock(LowBlock &Block) {
  LowInstructionBoundary B;
  B.Address = Block.StartAddr;
  B.Size = 1;
  B.OpCount = Block.Ops.size();
  B.Control = Block.Succs.empty() ? LowInstructionControl::Return
                                  : LowInstructionControl::Branch;
  B.ControlFlags = Block.Succs.empty()
                       ? LowInstructionControlFlag::Return
                       : LowInstructionControlFlag::Branch |
                             LowInstructionControlFlag::Conditional;
  if (!Block.Succs.empty())
    B.Immediate = Block.Ops.back().Inputs[0].Offset;
  Block.InstructionBoundaries.push_back(B);
  Block.EndAddr = Block.StartAddr + 1;
  for (size_t I = 0; I < Block.Ops.size(); ++I) {
    Block.Ops[I].Addr = B.Address;
    Block.Ops[I].Seq = static_cast<int>(I);
  }
}

SourceFunctionTypeHint sourceABI() {
  SourceFunctionTypeHint ABI;
  ABI.Origin = SourceFunctionTypeHint::OriginKind::NativeAnalysis;
  ABI.Architecture = Arch::X64;
  ABI.HasExplicitABI = true;
  ABI.ReturnType = NdType::makeInt(8, false);
  ABI.ReturnLocation = {SourceABICarrierKind::IntegerRegister, x86reg::RAX, 0,
                        8};
  SourceParameterTypeHint P;
  P.Name = "machine_state";
  P.Type = NdType::makePtr(NdType::makeInt(1, false));
  P.Location = {SourceABICarrierKind::IntegerRegister, x86reg::RDI, 0, 8};
  ABI.Parameters.push_back(std::move(P));
  return ABI;
}

llvm::Expected<X64ContinuationInstructionSource>
buildInstruction(SpecializationInstruction Instruction,
                 const X64ContinuationSourceOptions &Options) {
  X64ContinuationInstructionSource Result;
  Result.Address = Instruction.Origin.Address;
  Result.Bytes = Instruction.NativeBytes;
  Result.SourceABI = sourceABI();
  auto &Function = Result.Function;
  Function.Entry = Result.Address;
  const bool Controls = hasControlState(Options);
  const bool Smap =
      Options.Profile == X64ContinuationProfile::KernelSmapNoFaultV3;
  const bool FaultAddress =
      Options.Profile == X64ContinuationProfile::KernelFaultAddressNoFaultV4;
  Result.StateVersion = FaultAddress ? 4 : Smap ? 3 : Controls ? 2 : 1;
  Result.StateBytes = FaultAddress ? sizeof(StateV4)
                      : Controls   ? sizeof(StateV2)
                                   : sizeof(State);
  Function.Name = (FaultAddress ? "neverd_step_v4_"
                   : Smap       ? "neverd_step_v3_"
                   : Controls   ? "neverd_step_v2_"
                                : "neverd_step_") +
                  llvm::utohexstr(Result.Address);
  Exit Kind = Exit::Continue;
  if (Instruction.NativeStackControl !=
      SpecializationNativeStackControl::None) {
    const bool Call = Instruction.NativeStackControl ==
                      SpecializationNativeStackControl::Call;
    auto Expanded =
        expandX64MachineExit(Instruction,
                             {1, Result.Address,
                              Call ? SpecializationX64MachineExitKind::Call
                                   : SpecializationX64MachineExitKind::Return},
                             NdVar::tmp(ScratchBase - 16, 8));
    if (!Expanded)
      return Expanded.takeError();
    Instruction.Ops = std::move(Expanded->Ops);
    Instruction.UndefinedEffects = std::move(Expanded->UndefinedEffects);
    Kind = Call ? Exit::Call : Exit::Return;
  } else if (Instruction.Origin.Control == LowInstructionControl::Branch) {
    Kind = Exit::Jump;
  }
  auto RequireNative = [&](llvm::StringRef Reason) {
    Result.RequiresNativeExecution = true;
    Result.Diagnostic = Reason.str();
  };
  if (Instruction.ProfileProjection != InterpreterProfileProjection::None ||
      Instruction.UndefinedEffects.Coverage != LowUndefinedCoverage::Complete ||
      Instruction.Origin.Control == LowInstructionControl::Terminator)
    RequireNative("instruction requires an explicit native environment");
  if (Instruction.UndefinedEffects.Effects.size() >
      std::size(State{}.Undefined))
    RequireNative("instruction exceeds the v1 arbitrary-value interface");
  for (const auto &E : Instruction.UndefinedEffects.Effects)
    if (!supportedValue(E.Output) || !E.Output.Size || E.Output.Size > 8 ||
        !E.BitCount || E.BitOffset + E.BitCount > E.Output.Size * 8 ||
        E.AfterOp > Instruction.Ops.size() ||
        (E.When && !supportedValue(*E.When)))
      RequireNative("instruction has an unsupported arbitrary-value effect");
  const bool WideDivision =
      Controls && std::any_of(Instruction.Ops.begin(), Instruction.Ops.end(),
                              unsignedWideDivisionIntrinsic);
  const auto Timestamp =
      Options.NativeTimestampReads
          ? x64::runtimeTimestampRegisters(Instruction,
                                           NdVar::tmp(ScratchBase - 16, 16))
          : std::nullopt;
  for (const LowOp &Op : Instruction.Ops) {
    if (!Timestamp && !supportedOperation(Op, Options, WideDivision)) {
      std::string Detail = "unsupported continuation operation: ";
      Detail += ndOpName(Op.Opcode);
      if (Op.Opcode == NdOp::INTRINSIC && Op.NumInputs &&
          Op.Inputs[0].isConst()) {
        Detail += " ";
        Detail += intrinsicName(static_cast<Intrinsic>(Op.Inputs[0].Offset));
      }
      RequireNative(Detail);
    }
    if (flagIntrinsic(Op)) {
      const auto Transition = detail::lowerX64MachineFlags(
          Op, NdVar::tmp(ScratchBase, 8),
          [](uint16_t N) { return NdVar::tmp(ScratchBase + 16, N); },
          flagsProfile(Options));
      if (!Transition || Transition->Rejected)
        RequireNative("instruction requires a different flags domain");
    }
  }
  // At most one control-value guard per original operation. Reserve before
  // taking block references, and keep synthetic block addresses representable.
  const size_t MaxBlocks = Instruction.Ops.size() + 3;
  if (MaxBlocks > Options.MaxOperations ||
      Result.Address >= InvalidVA - MaxBlocks)
    return invalid("continuation source block budget or address exhausted");
  Function.Blocks.reserve(MaxBlocks);
  Function.Blocks.resize(3);
  for (int I = 0; I != 3; ++I) {
    Function.Blocks[I].Id = I;
    Function.Blocks[I].StartAddr = Result.Address + I;
  }
  auto &Entry = Function.Blocks[0];
  auto &Body = Function.Blocks[1];
  auto &Rejected = Function.Blocks[2];
  Entry.Succs = {1, 2};
  Body.Preds = {0};
  Rejected.Preds = {0};
  Writer Guard{Function, &Entry, Options};
  Guard.emit(NdOp::COPY, NdVar::reg(StatePointer, 8),
             {NdVar::reg(x86reg::RDI, 8)});
  const NdVar PCBad = Guard.temporary(1), FlagBits = Guard.temporary();
  const NdVar FlagsBad = Guard.temporary(1), Fixed = Guard.temporary();
  const NdVar FixedBad = Guard.temporary(1), Bad0 = Guard.temporary(1);
  NdVar Bad = Guard.temporary(1);
  Guard.emit(NdOp::INT_NOTEQUAL, PCBad,
             {Guard.load(offsetof(State, PC)), constant(Result.Address)});
  const NdVar Packed = Guard.load(offsetof(State, RFlags));
  Guard.emit(NdOp::INT_AND, FlagBits,
             {Packed, constant(~Flags::entryMask(flagsProfile(Options)))});
  Guard.emit(NdOp::INT_NOTEQUAL, FlagsBad, {FlagBits, constant(0)});
  Guard.emit(NdOp::INT_AND, Fixed, {Packed, constant(2)});
  Guard.emit(NdOp::INT_EQUAL, FixedBad, {Fixed, constant(0)});
  Guard.emit(NdOp::BOOL_OR, Bad0, {PCBad, FlagsBad});
  Guard.emit(NdOp::BOOL_OR, Bad, {Bad0, FixedBad});
  if (Controls) {
    const NdVar PriorityBad = Guard.temporary(1);
    const NdVar Reserved = Guard.temporary(4), MXCSRBad = Guard.temporary(1);
    const NdVar ControlsBad = Guard.temporary(1), AllBad = Guard.temporary(1);
    Guard.emit(NdOp::INT_LESS, PriorityBad,
               {constant(15), Guard.load(offsetof(StateV2, CR8))});
    Guard.emit(NdOp::INT_AND, Reserved,
               {Guard.load(offsetof(StateV2, MXCSR), 4),
                constant(~*Options.MXCSRMask, 4)});
    Guard.emit(NdOp::INT_NOTEQUAL, MXCSRBad, {Reserved, constant(0, 4)});
    Guard.emit(NdOp::BOOL_OR, ControlsBad, {PriorityBad, MXCSRBad});
    Guard.emit(NdOp::BOOL_OR, AllBad, {Bad, ControlsBad});
    Bad = AllBad;
  }
  Guard.emit(NdOp::COND_BR, {}, {NdVar::cst(Rejected.StartAddr, 8), Bad});
  Writer Reject{Function, &Rejected, Options};
  Reject.leave(Exit::InvalidState);
  Writer W{Function, &Body, Options};
  if (Result.RequiresNativeExecution) {
    W.leave(Exit::NativeInstruction);
  } else {
    Result.UndefinedEffects = Instruction.UndefinedEffects.Effects;
    NdVar NextPC = constant(Instruction.Fallthrough.Address);
    auto Effects = [&](size_t After) {
      for (size_t I = 0; I != Instruction.UndefinedEffects.Effects.size(); ++I)
        if (Instruction.UndefinedEffects.Effects[I].AfterOp == After)
          W.undefined(Instruction.UndefinedEffects.Effects[I], I);
    };
    Effects(0);
    if (Timestamp) {
      // Keep the native intrinsic and its complete multi-output bundle
      // together. Ordinary operation-by-operation substitution would detach
      // its hidden result carriers, losing EDX and RDTSCP's ECX result.
      W.append(Instruction.Ops);
      for (uint64_t Register : *Timestamp)
        W.write(NdVar::reg(Register, 8), NdVar::reg(Register, 8));
    }
    for (size_t I = 0; !Timestamp && I < Instruction.Ops.size(); ++I) {
      const LowOp &Op = Instruction.Ops[I];
      if (Op.Opcode == NdOp::BRANCH || Op.Opcode == NdOp::INDIR_BR) {
        NextPC = W.read(Op.Inputs[0]);
      } else if (Op.Opcode == NdOp::COND_BR) {
        NextPC = W.temporary();
        W.emit(NdOp::SELECT, NextPC,
               {W.read(Op.Inputs[1]), W.read(Op.Inputs[0]),
                constant(Instruction.Fallthrough.Address)});
      } else {
        W.operation(Op);
      }
      Effects(I + 1);
    }
    W.leave(Kind, NextPC);
  }
  for (auto &Block : Function.Blocks)
    finishBlock(Block);
  if (auto Error = validateLowInstructionBoundaries(
          Function, LowInstructionBoundaryRequirement::Required))
    return std::move(Error);
  return Result;
}
} // namespace

llvm::Expected<std::vector<X64ContinuationInstructionSource>>
buildX64ContinuationSource(const BinaryImage &Image,
                           llvm::ArrayRef<va_t> Addresses,
                           const X64ContinuationSourceOptions &Options) {
  const bool Controls = hasControlState(Options);
  if (Options.Profile != X64ContinuationProfile::KernelNoFaultV1 && !Controls)
    return invalid("continuation source requires its explicit kernel domain");
  if (Options.NativeTimestampReads && !Controls)
    return invalid("native timestamp source requires an x64 host profile");
  if (Options.NativeWritePrefetch && !Controls)
    return invalid("native write prefetch source requires an x64 host profile");
  if (Controls != Options.MXCSRMask.has_value())
    return invalid(
        "continuation control profiles require an effective MXCSR mask; v1 has "
        "no MXCSR state");
  const auto ControlOptions = controlOptions(Options);
  if (auto Error = x64::mxcsr::validateOptions(ControlOptions))
    return std::move(Error);
  if (auto Error = x64::legacygs::validateOptions(ControlOptions))
    return std::move(Error);
  if (Addresses.empty() || Addresses.size() > Options.MaxInstructions ||
      Addresses.size() > Options.MaxOperations)
    return invalid("continuation source instruction budget exhausted");
  std::set<va_t> Unique;
  for (va_t Address : Addresses)
    if (Address >= InvalidVA - 3 || !Unique.insert(Address).second)
      return invalid("invalid or duplicate continuation instruction address");
  auto Instructions = readBinaryX64ContinuationInstructions(Image, Addresses);
  if (!Instructions)
    return Instructions.takeError();
  uint64_t Work = Addresses.size();
  std::vector<X64ContinuationInstructionSource> Result;
  for (auto &Instruction : *Instructions) {
    auto Unit = buildInstruction(std::move(Instruction), Options);
    if (!Unit)
      return Unit.takeError();
    for (const auto &Block : Unit->Function.Blocks) {
      if (Block.Ops.size() > Options.MaxOperations - Work)
        return invalid("continuation source operation budget exhausted");
      Work += Block.Ops.size();
    }
    Result.push_back(std::move(*Unit));
  }
  return Result;
}

} // namespace neverd::analysis
