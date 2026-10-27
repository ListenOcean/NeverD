//===- MedPrologueSavesTests.cpp - Callee-save prologue storage ----------===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//

#include "gtest/gtest.h"

#include "neverd/Common.h"
#include "neverd/ir/TargetRegInfo.h"
#include "neverd/ir/intrinsics/Intrinsics.h"
#include "neverd/ir/med/MedCallReturnReads.h"
#include "neverd/ir/med/MedPrologueSaves.h"
#include "neverd/lift/X86/X86Regs.h"
#include "neverd/loader/BinaryImage.h"

#include <algorithm>
#include <initializer_list>
#include <limits>
#include <utility>

namespace {

using namespace neverd;

enum : int { kSP = 1, kRBX = 2, kRCX = 3 };

MedVar reg(int Id, uint64_t RegOff, int Version) {
  MedVar V;
  V.Kind = MedVar::Reg;
  V.TheArch = Arch::X64;
  V.Id = Id;
  V.SSAVer = Version;
  V.Size = 8;
  V.RegOff = RegOff;
  return V;
}
MedVar sp(int Version) { return reg(kSP, reg::RSP, Version); }
MedVar rbx(int Version) { return reg(kRBX, reg::RBX, Version); }
MedVar rcx(int Version) {
  return reg(kRCX, getTargetRegInfo(Arch::X64).Win64ParamRegs[0], Version);
}

MedVar temp(int Id) {
  MedVar V;
  V.Kind = MedVar::Temp;
  V.TheArch = Arch::X64;
  V.Id = Id;
  V.SSAVer = 1;
  V.Size = 8;
  return V;
}

MedVar none() {
  MedVar V;
  V.Id = -1;
  return V;
}

MedOp op(NdOp Opcode, MedVar Output, std::initializer_list<MedVar> Inputs) {
  MedOp Result;
  Result.Opcode = Opcode;
  Result.Output = Output;
  for (const MedVar &Input : Inputs)
    Result.addInput(Input);
  return Result;
}

/// `push rbx; mov rbx, rcx; …; pop rbx; ret` in MedIR: the prologue saves the
/// caller's rbx below the entry stack pointer, the epilogue restores it.
MedFunc pushedRbx(CallingConv Convention = CallingConv::SysV_AMD64) {
  MedFunc Func;
  Func.Entry = 0x1000;
  Func.CC = Convention;
  Func.FrameSize = 8;
  MedBlock Block;
  Block.Id = 0;
  Block.StartAddr = Func.Entry;
  Block.Ops = {op(NdOp::COPY, sp(0), {sp(0)}),
               op(NdOp::COPY, rbx(0), {rbx(0)}),
               op(NdOp::COPY, rcx(0), {rcx(0)}),
               op(NdOp::INT_SUB, sp(1), {sp(0), MedVar::makeConst(8, 8)}),
               op(NdOp::STORE, none(), {sp(1), rbx(0)}),
               op(NdOp::COPY, rbx(1), {rcx(0)}),
               op(NdOp::LOAD, temp(10), {sp(1)}),
               op(NdOp::COPY, rbx(2), {temp(10)}),
               op(NdOp::INT_ADD, sp(2), {sp(1), MedVar::makeConst(8, 8)}),
               op(NdOp::RETURN, none(), {rbx(1)})};
  Func.Blocks.push_back(std::move(Block));
  return Func;
}

class MedPrologueSaves : public ::testing::TestWithParam<bool> {
protected:
  void markStackAccesses(MedFunc &Func, Arch Architecture, BinaryFormat Format,
                         StackEntryKind Entry = StackEntryKind::Call) {
    if (GetParam()) {
      markSourceStackAccesses(Func, Architecture, Format, Entry);
    } else {
      markCalleeSavePrologueSaves(Func, Architecture, Format, Entry);
      markReturnAddressReads(Func, Architecture, Format, Entry);
    }
  }
};

INSTANTIATE_TEST_SUITE_P(SourceStackAccesses, MedPrologueSaves,
                         ::testing::Bool(),
                         [](const ::testing::TestParamInfo<bool> &Info) {
                           return Info.param ? "Combined" : "Separate";
                         });

const MedOp &save(const MedFunc &Func) { return Func.Blocks[0].Ops[4]; }

TEST_P(MedPrologueSaves, APushedEntryValueIsAPrologueSave) {
  MedFunc Func = pushedRbx();
  markStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
  EXPECT_TRUE(save(Func).PrologueSave);
  // Marking keeps every operation where call records find it.
  EXPECT_EQ(Func.Blocks[0].Ops.size(), 10u);
}

TEST(MedSourceStackAccesses, ChangedStoresLoseTheirOldPrologueProof) {
  MedFunc Func = pushedRbx();
  markSourceStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
  ASSERT_TRUE(save(Func).PrologueSave);
  Func.Blocks[0].Ops[4].Inputs[1] =
      MedVar::makeConst(0, Func.Blocks[0].Ops[4].Inputs[1].Size);
  markSourceStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
  EXPECT_FALSE(save(Func).PrologueSave);
}

TEST_P(MedPrologueSaves, SaveAndReturnAddressAnnotationsShareTheFrame) {
  for (StackEntryKind Entry :
       {StackEntryKind::Call, StackEntryKind::ProcessEntry}) {
    SCOPED_TRACE(static_cast<int>(Entry));
    MedFunc Func = pushedRbx();
    auto &Ops = Func.Blocks[0].Ops;
    Ops.insert(Ops.end() - 1, op(NdOp::LOAD, temp(20), {sp(2)}));
    markStackAccesses(Func, Arch::X64, BinaryFormat::ELF, Entry);
    EXPECT_TRUE(save(Func).PrologueSave);
    EXPECT_EQ(Ops[9].ReturnAddressRead, Entry == StackEntryKind::Call);
    EXPECT_FALSE(Ops[6].ReturnAddressRead);
    EXPECT_EQ(Ops.size(), 11u);
  }
}

TEST_P(MedPrologueSaves, ARestoreTheBodyReadsKeepsItsSave) {
  MedFunc Func = pushedRbx();
  Func.Blocks[0].Ops.back() = op(NdOp::RETURN, none(), {rbx(2)});
  markStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
  EXPECT_FALSE(save(Func).PrologueSave);
}

TEST_P(MedPrologueSaves, OnlyObservedRestoreJoinsKeepTheirSave) {
  for (bool Observed : {false, true}) {
    SCOPED_TRACE(Observed);
    MedFunc Func = pushedRbx();
    auto &Entry = Func.Blocks.front();
    Entry.Ops.pop_back();
    Entry.Succs = {1};
    MedBlock Join;
    Join.Id = 1;
    Join.Preds = {0};
    PhiNode Phi;
    Phi.Output = rbx(3);
    Phi.Args.push_back({0, rbx(2)});
    Join.Phis.push_back(Phi);
    Join.Ops = {op(NdOp::COPY, temp(20), {rbx(3)}),
                op(NdOp::RETURN, none(), {Observed ? temp(20) : rcx(0)})};
    Func.Blocks.push_back(std::move(Join));
    markStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
    EXPECT_EQ(Func.Blocks.front().Ops[4].PrologueSave, !Observed);
  }
}

TEST_P(MedPrologueSaves, AComputedValueIsNoSave) {
  MedFunc Func = pushedRbx();
  Func.Blocks[0].Ops[4] = op(NdOp::STORE, none(), {sp(1), rbx(1)});
  markStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
  EXPECT_FALSE(save(Func).PrologueSave);
}

TEST_P(MedPrologueSaves, AnOverwritePreventsOnlyTheCalleeSaveProof) {
  MedFunc Func = pushedRbx();
  auto &Ops = Func.Blocks[0].Ops;
  Ops.insert(Ops.begin() + 6, op(NdOp::STORE, none(), {sp(1), rcx(0)}));
  markStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
  // It no longer restores rbx's entry value. The combined source pass can
  // nevertheless discard that value: its bytes are overwritten before use.
  EXPECT_EQ(save(Func).PrologueSave, GetParam());
  EXPECT_EQ(Ops.size(), 11u);
}

TEST_P(MedPrologueSaves, AReadBeforeTheOverwriteKeepsTheSave) {
  MedFunc Func = pushedRbx();
  auto &Ops = Func.Blocks[0].Ops;
  Ops.insert(Ops.begin() + 6, op(NdOp::LOAD, temp(20), {sp(1)}));
  Ops.insert(Ops.begin() + 7, op(NdOp::STORE, none(), {sp(1), rcx(0)}));
  Ops.back() = op(NdOp::RETURN, none(), {temp(20)});
  markStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
  EXPECT_FALSE(save(Func).PrologueSave);
  EXPECT_EQ(Ops.size(), 12u);
}

TEST_P(MedPrologueSaves, OverwritesKillOnlyTheirOwnEntrySpillBytes) {
  for (uint16_t Bytes : {4, 8}) {
    SCOPED_TRACE(Bytes);
    MedFunc Func = pushedRbx();
    auto &Ops = Func.Blocks[0].Ops;
    MedVar Value = rcx(0);
    Value.Size = Bytes;
    Ops.insert(Ops.begin() + 6, op(NdOp::STORE, none(), {sp(1), Value}));
    markStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
    // Reusing a save slot defeats the register-save recognizer. Combined
    // source preparation can still prove the initial bytes unobservable
    // when a complete overwrite precedes every load; a partial one cannot.
    EXPECT_EQ(save(Func).PrologueSave, GetParam() && Bytes == 8);
    EXPECT_FALSE(Ops[6].PrologueSave);
  }
}

TEST(SourceStackSpills, OverwrittenValuesNeedNotComeFromTheEntry) {
  for (Arch Architecture : {Arch::X86, Arch::X64, Arch::ARM, Arch::AArch64})
    for (BinaryFormat Format :
         {BinaryFormat::COFF, BinaryFormat::ELF, BinaryFormat::MachO})
      for (MedVar::VarKind Kind :
           {MedVar::Reg, MedVar::Temp, MedVar::Unspecified}) {
        SCOPED_TRACE(testing::Message() << unsigned(Architecture) << ':'
                                        << unsigned(Format) << ':' << Kind);
        const auto &TRI = getTargetRegInfo(Architecture);
        const auto Width = TRI.PointerSize;
        auto SP = reg(1, TRI.StackPointer, 0);
        SP.TheArch = Architecture;
        SP.Size = Width;
        auto Address = temp(10);
        Address.TheArch = Architecture;
        Address.Size = Width;
        auto Value = MedVar::makeUnspecified(Width, Architecture);
        if (Kind != MedVar::Unspecified) {
          Value = reg(2, TRI.IntReturnReg, 3);
          Value.Kind = Kind;
          Value.TheArch = Architecture;
          Value.Size = Width;
        }
        MedFunc Func;
        Func.Entry = 0x1000;
        Func.FrameSize = Width;
        MedBlock Block;
        Block.Id = 0;
        Block.StartAddr = Func.Entry;
        Block.Ops = {
            op(NdOp::COPY, SP, {SP}),
            op(NdOp::INT_SUB, Address, {SP, MedVar::makeConst(Width, Width)}),
            op(NdOp::STORE, none(), {Address, Value}),
            op(NdOp::STORE, none(), {Address, MedVar::makeConst(19, Width)}),
            op(NdOp::RETURN, none(), {MedVar::makeConst(19, Width)})};
        Func.Blocks.push_back(std::move(Block));
        markSourceStackAccesses(Func, Architecture, Format);
        EXPECT_TRUE(Func.Blocks[0].Ops[2].PrologueSave);
        EXPECT_EQ(Func.Blocks[0].Ops.size(), 5u);
      }
}

TEST(SourceStackSpills, FlagsTransfersDoNotObserveScratchButKeepTheirEffects) {
  for (Arch Architecture : {Arch::X86, Arch::X64})
    for (unsigned Mode = 0; Mode < 9; ++Mode) {
      SCOPED_TRACE(testing::Message() << unsigned(Architecture) << ':' << Mode);
      MedFunc Func = pushedRbx(CallingConv::Win64);
      auto &Ops = Func.Blocks[0].Ops;
      Ops.resize(5);
      for (auto &Op : Ops) {
        Op.Output.TheArch = Architecture;
        Op.Output.Size =
            Op.Output.Size ? getTargetRegInfo(Architecture).PointerSize : 0;
        for (unsigned I = 0; I < Op.NumInputs; ++I) {
          Op.Inputs[I].TheArch = Architecture;
          Op.Inputs[I].Size = getTargetRegInfo(Architecture).PointerSize;
        }
      }
      const auto Address = Ops[4].Inputs[0];
      const auto Width = getTargetRegInfo(Architecture).PointerSize;
      Ops[4].Inputs[1] = MedVar::makeUnspecified(Width, Architecture);
      auto Flags = temp(20);
      Flags.Size = Width;
      Flags.TheArch = Architecture;
      Ops.push_back(op(NdOp::INTRINSIC, Flags,
                       {MedVar::makeConst(unsigned(Intrinsic::Pushf), 2)}));
      Ops.push_back(
          op(NdOp::INTRINSIC, none(),
             {MedVar::makeConst(unsigned(Intrinsic::Popf), 2), Flags}));
      switch (Mode) {
      case 1: // An unrelated or unknown intrinsic remains a barrier.
        Ops[5].Inputs[0].ConstVal = 0xFFFF;
        break;
      case 2:
        Ops[5].Output.Size = 3;
        break;
      case 3:
        Ops[6].Inputs[1].Size = 3;
        break;
      case 4:
        Ops[6].NumInputs = 1;
        break;
      case 5:
        Ops[5].Inputs[0].Size = 8;
        break;
      case 6:
        Ops[5].IntrinsicOutputs.push_back(temp(30));
        break;
      case 7:
        Ops[6].MemoryOrdering = NdMemoryOrdering::SequentiallyConsistent;
        break;
      case 8:
        Func.Blocks[0].ExceptionalSuccs.emplace_back(1, 0x2000);
        break;
      }
      Ops.push_back(
          op(NdOp::STORE, none(), {Address, MedVar::makeConst(19, Width)}));
      Ops.push_back(op(NdOp::RETURN, none(), {MedVar::makeConst(19, Width)}));
      markSourceStackAccesses(Func, Architecture, BinaryFormat::COFF);
      EXPECT_EQ(Ops[4].PrologueSave, Mode == 0);
      EXPECT_EQ(Ops[5].Opcode, NdOp::INTRINSIC);
      EXPECT_EQ(Ops[6].Opcode, NdOp::INTRINSIC);
      EXPECT_FALSE(Ops[5].Dead);
      EXPECT_FALSE(Ops[6].Dead);
      EXPECT_EQ(Ops.size(), 9u);
    }
}

TEST(SourceStackSpills, OnlyUnreadScratchRestoresCanBeIgnored) {
  for (unsigned Mode = 0; Mode < 16; ++Mode) {
    SCOPED_TRACE(Mode);
    MedFunc Func = pushedRbx(CallingConv::Win64);
    auto &Ops = Func.Blocks[0].Ops;
    Ops[4].Inputs[1] = MedVar::makeUnspecified(8, Arch::X64);
    const auto Loaded = temp(10);
    auto Restored = reg(30, x86reg::R10, 1);
    // R10 is volatile and cannot be an ordinary ABI result.
    if (Mode == 1)
      Restored = rbx(2);
    if (Mode == 2)
      Restored.RegOff = getTargetRegInfo(Arch::X64).IntReturnReg;
    if (Mode == 3)
      Restored = sp(2);
    Ops[7] = op(NdOp::COPY, Restored, {Loaded});
    Ops[8] = op(NdOp::STORE, none(), {sp(1), MedVar::makeConst(19, 8)});
    Ops[9] = op(NdOp::RETURN, none(), {MedVar::makeConst(19, 8)});
    if (Mode == 4)
      Ops[9].Inputs[0] = Restored;
    if (Mode == 5) {
      PhiNode Phi;
      Phi.Output = temp(40);
      Phi.Args = {{0, Restored}};
      Func.Blocks[0].Phis.push_back(std::move(Phi));
    }
    if (Mode == 6) {
      MedCallClobber Clobber;
      Clobber.Value = temp(40);
      Clobber.PreservedInput = Restored;
      Clobber.PreservedPrefixSize = 4;
      Func.CallClobbers.push_back(Clobber);
    }
    if (Mode == 7)
      Ops.insert(Ops.begin() + 8,
                 op(NdOp::CALL, none(), {MedVar::makeConst(0x2000, 8), sp(1)}));
    if (Mode >= 8 && Mode <= 10) {
      // The slot is dead, but ABI recovery could still observe the restored
      // register at a later call. Only a complete register overwrite kills it.
      Ops.insert(Ops.end() - 1,
                 op(NdOp::CALL, none(), {MedVar::makeConst(0x2000, 8)}));
      if (Mode >= 9) {
        auto Overwritten = Restored;
        ++Overwritten.SSAVer;
        if (Mode == 10)
          Overwritten.Size = 4;
        Ops.insert(Ops.end() - 2, op(NdOp::COPY, Overwritten,
                                     {MedVar::makeConst(0, Overwritten.Size)}));
      }
    }
    if (Mode == 11) {
      Ops[7].Output.RegOff = x86reg::DF;
      Ops[7].Output.Size = 1;
    }
    if (Mode == 12)
      Func.MultiReturn.push_back({Restored.RegOff, Restored.Size, false});
    if (Mode == 13)
      Ops[9] = op(NdOp::INDIR_BR, none(), {MedVar::makeConst(0x2000, 8)});
    if (Mode == 14) {
      // A straight continuation kills the scratch register before its call.
      Ops[9] = op(NdOp::BRANCH, none(), {MedVar::makeConst(0x2000, 8)});
      Func.Blocks[0].Succs = {1};
      auto Overwritten = Restored;
      ++Overwritten.SSAVer;
      MedBlock Next;
      Next.Id = 1;
      Next.StartAddr = 0x2000;
      Next.Preds = {0};
      Next.Ops = {op(NdOp::COPY, Overwritten, {MedVar::makeConst(0, 8)}),
                  op(NdOp::CALL, none(), {MedVar::makeConst(0x3000, 8)}),
                  op(NdOp::RETURN, none(), {MedVar::makeConst(19, 8)})};
      Func.Blocks.push_back(std::move(Next));
    }
    if (Mode == 15)
      Ops[7].Output.RegOff = x86reg::RSI;
    markSourceStackAccesses(
        Func, Arch::X64, Mode == 15 ? BinaryFormat::ELF : BinaryFormat::COFF);
    EXPECT_EQ(Func.Blocks[0].Ops[4].PrologueSave,
              Mode == 0 || Mode == 9 || Mode == 14);
  }
}

TEST(SourceStackSpills, UnreadCalleeInputsRequireTheOriginalCallProof) {
  for (unsigned Mode = 0; Mode != 12; ++Mode) {
    SCOPED_TRACE(Mode);
    MedFunc Func = pushedRbx(CallingConv::Win64);
    auto &Ops = Func.Blocks[0].Ops;
    const auto Restored = reg(30, x86reg::R10, 1);
    Ops[4].Inputs[1] = MedVar::makeUnspecified(8, Arch::X64);
    Ops[7] = op(NdOp::COPY, Restored, {temp(10)});
    Ops[8] = op(NdOp::STORE, none(), {sp(1), MedVar::makeConst(19, 8)});
    Ops[9] = op(NdOp::CALL, none(), {MedVar::makeConst(0x2000, 8)});
    Ops[9].CallSiteId = 1;
    Ops[9].Addr = 0x1010;
    Ops[9].OriginSeq = 10;
    Ops[9].CallPreservedGPRs = ~uint32_t{0};
    Func.CallUnreadRegisters.emplace(
        1, MedCallUnreadRegisters{0x2000, 0x1010, 10,
                                  uint32_t{1} << (x86reg::R10 / 8)});
    Ops.push_back(op(NdOp::RETURN, none(), {MedVar::makeConst(19, 8)}));
    if (Mode == 1)
      Func.CallUnreadRegisters.clear();
    if (Mode == 2)
      Func.CallUnreadRegisters.at(1).Families = 0;
    if (Mode == 3)
      Ops[9].Inputs[0] = MedVar::makeConst(0x3000, 8);
    if (Mode == 4)
      Ops[9].addInput(Restored);
    if (Mode == 5)
      Ops[9].Opcode = NdOp::INDIR_CALL;
    if (Mode == 6)
      ++Ops[9].Addr;
    if (Mode == 7)
      ++Ops[9].OriginSeq;
    if (Mode == 8)
      ++Ops[9].CallSiteId;
    if (Mode == 9)
      Ops.back().Inputs[0] = Restored;
    if (Mode == 10)
      Ops.insert(Ops.end() - 1,
                 op(NdOp::CALL, none(), {MedVar::makeConst(0x3000, 8)}));
    if (Mode == 11)
      Ops[9].CallPreservedGPRs = 0;
    markSourceStackAccesses(Func, Arch::X64, BinaryFormat::COFF);
    EXPECT_EQ(save(Func).PrologueSave, Mode == 0 || Mode == 11);
  }
}

TEST_P(MedPrologueSaves, AnArgumentSpillIsNoSave) {
  MedFunc Func = pushedRbx();
  Func.Blocks[0].Ops[4] = op(NdOp::STORE, none(), {sp(1), rcx(0)});
  markStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
  EXPECT_FALSE(save(Func).PrologueSave);
}

TEST_P(MedPrologueSaves, OutOfFrameExtentsAreNotPrivateStorage) {
  for (BinaryFormat Format : {BinaryFormat::COFF, BinaryFormat::ELF})
    for (int64_t Offset :
         {std::numeric_limits<int64_t>::max(),
          std::numeric_limits<int64_t>::max() - 7,
          std::numeric_limits<int64_t>::max() - 8,
          std::numeric_limits<int64_t>::min(), int64_t{-9}, int64_t{0}}) {
      SCOPED_TRACE(testing::Message() << unsigned(Format) << ':' << Offset);
      MedFunc Func =
          pushedRbx(Format == BinaryFormat::COFF ? CallingConv::Win64
                                                 : CallingConv::SysV_AMD64);
      Func.Blocks[0].Ops[3] =
          op(NdOp::INT_ADD, sp(1),
             {sp(0), MedVar::makeConst(uint64_t(Offset), 8)});
      markStackAccesses(Func, Arch::X64, Format);
      EXPECT_FALSE(save(Func).PrologueSave);
    }
}

/// `mov [rsp+8], rbx; …; mov rbx, [rsp+8]; ret`: MSVC saves rbx in the home
/// slot Win64 hands the callee.
MedFunc homeSlotRbx(CallingConv Convention) {
  MedFunc Func;
  Func.Entry = 0x1000;
  Func.CC = Convention;
  MedBlock Block;
  Block.Id = 0;
  Block.StartAddr = Func.Entry;
  Block.Ops = {op(NdOp::COPY, sp(0), {sp(0)}),
               op(NdOp::COPY, rbx(0), {rbx(0)}),
               op(NdOp::COPY, rcx(0), {rcx(0)}),
               op(NdOp::INT_ADD, temp(11), {sp(0), MedVar::makeConst(8, 8)}),
               op(NdOp::STORE, none(), {temp(11), rbx(0)}),
               op(NdOp::COPY, rbx(1), {rcx(0)}),
               op(NdOp::INT_ADD, temp(12), {sp(0), MedVar::makeConst(8, 8)}),
               op(NdOp::LOAD, temp(13), {temp(12)}),
               op(NdOp::COPY, rbx(2), {temp(13)}),
               op(NdOp::RETURN, none(), {rbx(1)})};
  Func.Blocks.push_back(std::move(Block));
  return Func;
}

TEST_P(MedPrologueSaves, AWin64HomeSlotSaveIsPrologueStorage) {
  MedFunc Func = homeSlotRbx(CallingConv::Win64);
  markStackAccesses(Func, Arch::X64, BinaryFormat::COFF);
  EXPECT_TRUE(save(Func).PrologueSave);
}

TEST_P(MedPrologueSaves, OnlyWin64HandsTheCalleeHomeSlots) {
  // Above a System V callee's return address lies its caller's frame.
  MedFunc Func = homeSlotRbx(CallingConv::SysV_AMD64);
  markStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
  EXPECT_FALSE(save(Func).PrologueSave);
}

/// `mov rax, [rsp]; ret`: the function reads the return address its call
/// pushed.
MedFunc readsReturnAddress() {
  MedFunc Func;
  Func.Entry = 0x1000;
  Func.CC = CallingConv::SysV_AMD64;
  MedBlock Block;
  Block.Id = 0;
  Block.StartAddr = Func.Entry;
  Block.Ops = {op(NdOp::COPY, sp(0), {sp(0)}),
               op(NdOp::LOAD, temp(20), {sp(0)}),
               op(NdOp::RETURN, none(), {temp(20)})};
  Func.Blocks.push_back(std::move(Block));
  return Func;
}

const MedOp &read(const MedFunc &Func) { return Func.Blocks[0].Ops[1]; }

TEST_P(MedPrologueSaves, ALoadOfTheEntrySlotIsTheReturnAddress) {
  MedFunc Func = readsReturnAddress();
  markStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
  EXPECT_TRUE(read(Func).ReturnAddressRead);
}

TEST_P(MedPrologueSaves, AFunctionThatWritesTheSlotReadsItsOwnValue) {
  MedFunc Func = readsReturnAddress();
  auto &Ops = Func.Blocks[0].Ops;
  Ops.insert(Ops.begin() + 1, op(NdOp::STORE, none(), {sp(0), rcx(0)}));
  markStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
  EXPECT_FALSE(Func.Blocks[0].Ops[2].ReturnAddressRead);
}

TEST_P(MedPrologueSaves, ANarrowLoadOfTheEntrySlotIsNoReturnAddress) {
  MedFunc Func = readsReturnAddress();
  MedVar Narrow = temp(20);
  Narrow.Size = 4;
  Func.Blocks[0].Ops[1].Output = Narrow;
  markStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
  EXPECT_FALSE(read(Func).ReturnAddressRead);
}

TEST_P(MedPrologueSaves, AProcessEntryHasNoReturnAddress) {
  // The kernel starts `_start` with argc at the stack pointer.
  MedFunc Func = readsReturnAddress();
  markStackAccesses(Func, Arch::X64, BinaryFormat::ELF,
                    StackEntryKind::ProcessEntry);
  EXPECT_FALSE(read(Func).ReturnAddressRead);
}

TEST_P(MedPrologueSaves, AArch64KeepsItsReturnAddressInTheLinkRegister) {
  MedFunc Func = readsReturnAddress();
  markStackAccesses(Func, Arch::AArch64, BinaryFormat::ELF);
  EXPECT_FALSE(read(Func).ReturnAddressRead);
}

void consumeFrameRead(MedBlock &Block) {
  MedOp Call = op(NdOp::CALL, temp(20), {MedVar::makeConst(0x2000, 8)});
  auto Signature = std::make_shared<FixedIntegerCallArguments>();
  const auto Registers =
      getTargetRegInfo(Arch::X64).integerArgumentLayout(true);
  for (auto Register : Registers.Registers) {
    Signature->Parameters.push_back(
        {SourceABICarrierKind::IntegerRegister, Register, 0, 8});
    Call.addInput(MedVar::makeConst(0, 8));
  }
  Signature->Parameters.push_back({SourceABICarrierKind::Stack, 0, 40, 8});
  Call.addInput(temp(10));
  Call.IntegerCallSignature = std::move(Signature);
  Block.Ops.insert(Block.Ops.end() - 1, std::move(Call));
}

TEST(SourceFrameReads, MissingAndPartialPrivateBytesRemainUnavailable) {
  for (unsigned WrittenBytes : {0, 4, 8}) {
    SCOPED_TRACE(WrittenBytes);
    auto Func = pushedRbx();
    auto &Store = Func.Blocks[0].Ops[4];
    if (WrittenBytes)
      Store.Inputs[1].Size = WrittenBytes;
    else
      Store = op(NdOp::NOP, none(), {});
    consumeFrameRead(Func.Blocks.back());
    markSourceStackAccesses(Func, Arch::X64, BinaryFormat::COFF);
    const auto &Read = Func.Blocks[0].Ops[6];
    if (WrittenBytes == 8)
      EXPECT_EQ(Read.Opcode, NdOp::LOAD);
    else {
      ASSERT_EQ(Read.Opcode, NdOp::COPY);
      ASSERT_EQ(Read.NumInputs, 1);
      EXPECT_EQ(Read.Inputs[0].Kind, MedVar::Unspecified);
      EXPECT_EQ(Read.Inputs[0].Size, 8);
    }
  }
}

TEST(SourceFrameReads, PossibleWritersPreventAnUnavailableClaim) {
  for (auto Barrier :
       {NdOp::CALL, NdOp::INDIR_CALL, NdOp::INTRINSIC, NdOp::ATOMIC_XCHG,
        NdOp::ATOMIC_ADD, NdOp::ATOMIC_CMPXCHG, NdOp::STORE}) {
    SCOPED_TRACE(ndOpName(Barrier));
    auto Func = pushedRbx();
    Func.Blocks[0].Ops[4] =
        op(Barrier, none(), {rcx(0), MedVar::makeConst(0, 8)});
    consumeFrameRead(Func.Blocks.back());
    markSourceStackAccesses(Func, Arch::X64, BinaryFormat::COFF);
    EXPECT_EQ(Func.Blocks[0].Ops[6].Opcode, NdOp::LOAD);
  }
}

TEST(SourceFrameReads, AllPredecessorWritesAndQueryBackedgesAreConsidered) {
  for (unsigned Shape : {0, 1, 2, 3}) {
    SCOPED_TRACE(Shape);
    auto Func = pushedRbx();
    auto &Entry = Func.Blocks[0];
    MedBlock Query;
    Query.Id = 3;
    Query.Ops.assign(Entry.Ops.begin() + 6, Entry.Ops.end());
    Query.Preds = {1, 2};
    Entry.Ops.resize(4);
    Entry.Succs = {1, 2};
    MedBlock Left, Right;
    Left.Id = 1;
    Right.Id = 2;
    Left.Preds = Right.Preds = {0};
    Left.Succs = Right.Succs = {3};
    if (Shape == 1)
      Left.Ops.push_back(op(NdOp::STORE, none(), {sp(1), rbx(0)}));
    if (Shape == 2) {
      Query.Preds.push_back(3);
      Query.Succs = {3};
    }
    if (Shape == 3) // A stale/incomplete edge cannot establish an entry path.
      Query.Preds.clear();
    Func.Blocks.push_back(std::move(Left));
    Func.Blocks.push_back(std::move(Right));
    Func.Blocks.push_back(std::move(Query));
    consumeFrameRead(Func.Blocks.back());
    markSourceStackAccesses(Func, Arch::X64, BinaryFormat::COFF);
    EXPECT_EQ(Func.Blocks.back().Ops[0].Opcode,
              Shape ? NdOp::LOAD : NdOp::COPY);
  }
}

TEST(SourceFrameReads, GeneralPartialLoadsKeepTheirInitializedBits) {
  auto Func = pushedRbx();
  Func.Blocks[0].Ops[4].Inputs[1].Size = 4;
  // Only the low written word is returned. A source-only proof must not
  // replace the whole load with unavailable state merely for its upper word.
  auto LowWord =
      op(NdOp::SUBBYTES, temp(30), {temp(10), MedVar::makeConst(0, 4)});
  LowWord.Output.Size = 4;
  Func.Blocks[0].Ops.back().Inputs[0] = LowWord.Output;
  Func.Blocks[0].Ops.insert(Func.Blocks[0].Ops.end() - 1, LowWord);
  markSourceStackAccesses(Func, Arch::X64, BinaryFormat::COFF);
  EXPECT_EQ(Func.Blocks[0].Ops[6].Opcode, NdOp::LOAD);
}

TEST(SourceStackSpills, NontrappingBitCountsDoNotObserveScratchBytes) {
  for (unsigned Mode = 0; Mode < 3; ++Mode) {
    SCOPED_TRACE(Mode);
    MedFunc Func = pushedRbx();
    auto &Ops = Func.Blocks[0].Ops;
    Ops.resize(5);
    Ops[4].Inputs[1] = MedVar::makeUnspecified(8, Arch::X64);
    if (Mode == 2)
      Ops.push_back(op(NdOp::LOAD, temp(20), {sp(1)}));
    Ops.push_back(op(Mode == 1 ? NdOp::INT_DIV : NdOp::POPCOUNT, temp(21),
                     {Mode == 2 ? temp(20) : rcx(0)}));
    if (Mode == 1)
      Ops.back().addInput(MedVar::makeConst(0, 8));
    Ops.push_back(op(NdOp::STORE, none(), {sp(1), MedVar::makeConst(19, 8)}));
    Ops.push_back(op(NdOp::RETURN, none(), {temp(21)}));
    markSourceStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
    EXPECT_EQ(save(Func).PrologueSave, Mode == 0);
    EXPECT_FALSE(Ops[Ops.size() - 3].Dead);
  }
}

TEST(SourceStackSpills, ImplicitCallWritesAreNotProjectedFrameStores) {
  for (unsigned Mode = 0; Mode < 3; ++Mode) {
    SCOPED_TRACE(Mode);
    MedFunc Func = pushedRbx();
    auto &Ops = Func.Blocks[0].Ops;
    Ops.resize(5);
    Ops[4].Inputs[1] = MedVar::makeUnspecified(8, Arch::X64);
    Ops.push_back(op(NdOp::INT_ADD, sp(2), {sp(1), MedVar::makeConst(8, 8)}));
    Ops.push_back(op(NdOp::CALL, temp(20), {MedVar::makeConst(0x2000, 8)}));
    if (Mode == 2)
      Ops.back().addInput(sp(1));
    if (Mode == 0)
      Ops.push_back(op(NdOp::LOAD, temp(21), {sp(1)}));
    Ops.push_back(op(NdOp::RETURN, none(),
                     {Mode == 0   ? temp(21)
                      : Mode == 1 ? sp(1)
                                  : MedVar::makeConst(19, 8)}));
    markSourceStackAccesses(Func, Arch::X64, BinaryFormat::ELF);
    // CALL replaced the old bytes in the machine, but the C frame has no
    // corresponding store. A later load, returned frame address or callee
    // observation must not turn an unavailable value into uninitialized C.
    EXPECT_FALSE(save(Func).PrologueSave);
  }
}

BinaryImage callSlotImage(uint8_t Encoding = 0xe8) {
  BinaryImage Image;
  Image.Arch = Arch::X64;
  Image.Format = BinaryFormat::ELF;
  Segment Code;
  Code.VA = 0x1000;
  Code.Size = 64;
  Code.Data.resize(Code.Size, 0x90);
  Code.Data[8] = Encoding;
  Image.Segments.push_back(std::move(Code));
  return Image;
}

MedFunc observedCallSlot() {
  MedFunc Func;
  Func.Entry = 0x1000;
  Func.Name = "call_slot";
  Func.FrameSize = 40;
  MedBlock Block;
  Block.Id = 0;
  Block.StartAddr = Func.Entry;
  Block.Ops = {op(NdOp::COPY, sp(0), {sp(0)}),
               op(NdOp::INT_SUB, sp(1), {sp(0), MedVar::makeConst(32, 8)}),
               op(NdOp::INT_SUB, temp(20), {sp(1), MedVar::makeConst(8, 8)}),
               op(NdOp::STORE, none(), {temp(20), MedVar::makeConst(19, 8)}),
               op(NdOp::CALL, temp(21), {MedVar::makeConst(0x2000, 8)}),
               op(NdOp::LOAD, temp(22), {temp(20)}),
               op(NdOp::RETURN, none(), {temp(22)})};
  Block.Ops[4].Addr = 0x1008;
  Block.Ops[5].Addr = 0x100d;
  Func.Blocks.push_back(std::move(Block));
  return Func;
}

TEST(SourceCallReturnReads, ConstantOldContentsCannotHideTheImplicitWrite) {
  for (Arch Architecture : {Arch::X64, Arch::X86}) {
    SCOPED_TRACE(static_cast<unsigned>(Architecture));
    auto Func = observedCallSlot();
    auto Image = callSlotImage();
    Image.Arch = Architecture;
    const auto Width = getTargetRegInfo(Architecture).PointerSize;
    for (auto &Op : Func.Blocks[0].Ops) {
      Op.Output.TheArch = Architecture;
      Op.Output.Size = Width;
      for (unsigned I = 0; I < Op.NumInputs; ++I) {
        Op.Inputs[I].TheArch = Architecture;
        Op.Inputs[I].Size = Width;
      }
    }
    Func.Blocks[0].Ops[2].Inputs[1].ConstVal = Width;
    std::string Error;
    EXPECT_FALSE(validateSourceCallReturnReads(Func, Image, Error));
    EXPECT_NE(Error.find("physical CALL return slot"), std::string::npos);
    EXPECT_NE(Error.find("100D"), std::string::npos);
    EXPECT_EQ(Func.Blocks[0].Ops[3].Inputs[1].ConstVal, 19u);
    EXPECT_FALSE(Func.Blocks[0].Ops[3].PrologueSave);
  }
}

TEST(SourceCallReturnReads, OnlyLaterWritesOfEachObservedByteEndTheHazard) {
  for (unsigned Bytes : {1u, 4u, 8u}) {
    auto Func = observedCallSlot();
    auto &Ops = Func.Blocks[0].Ops;
    Ops.insert(Ops.begin() + 5, op(NdOp::STORE, none(),
                                   {temp(20), MedVar::makeConst(29, Bytes)}));
    std::string Error;
    EXPECT_EQ(validateSourceCallReturnReads(Func, callSlotImage(), Error),
              Bytes == 8)
        << Error;
    Ops[6].Output.Size = Bytes;
    EXPECT_TRUE(validateSourceCallReturnReads(Func, callSlotImage(), Error))
        << Error;
  }
  auto Func = observedCallSlot();
  auto &Ops = Func.Blocks[0].Ops;
  Ops.insert(Ops.begin() + 5,
             {op(NdOp::STORE, none(), {temp(20), MedVar::makeConst(29, 4)}),
              op(NdOp::INT_ADD, temp(23), {temp(20), MedVar::makeConst(4, 8)}),
              op(NdOp::STORE, none(), {temp(23), MedVar::makeConst(31, 4)})});
  std::string Error;
  EXPECT_TRUE(validateSourceCallReturnReads(Func, callSlotImage(), Error))
      << Error;
}

TEST(SourceCallReturnReads, EarlierReadsAndSeparatedSlotsStayValid) {
  auto Func = observedCallSlot();
  std::swap(Func.Blocks[0].Ops[4], Func.Blocks[0].Ops[5]);
  std::string Error;
  EXPECT_TRUE(validateSourceCallReturnReads(Func, callSlotImage(), Error))
      << Error;
  Func = observedCallSlot();
  Func.Blocks[0].Ops[2].Inputs[1] = MedVar::makeConst(16, 8);
  EXPECT_TRUE(validateSourceCallReturnReads(Func, callSlotImage(), Error))
      << Error;
}

TEST(SourceCallReturnReads, RepeatedReadsShareCompleteByteHistories) {
  auto Func = observedCallSlot();
  auto &Ops = Func.Blocks[0].Ops;
  const auto Call = Ops[4];
  auto Return = Ops[6];
  Return.Inputs[0] = temp(227);
  Ops.resize(4);
  for (int I = 0; I != 128; ++I) {
    Ops.push_back(op(NdOp::NOP, none(), {}));
    Ops.push_back(op(NdOp::LOAD, temp(100 + I), {temp(20)}));
  }
  Ops.insert(Ops.end(), {Call, Return});
  std::string Error;
  EXPECT_TRUE(validateSourceCallReturnReads(Func, callSlotImage(), Error, 8192))
      << Error;
  // A later observation still reaches the CALL, even when earlier reads of
  // the same bytes have populated the completed-history cache.
  Ops.insert(Ops.end() - 1, op(NdOp::LOAD, temp(300), {temp(20)}));
  EXPECT_FALSE(
      validateSourceCallReturnReads(Func, callSlotImage(), Error, 8192));
  EXPECT_NE(Error.find("physical CALL return slot"), std::string::npos)
      << Error;
}

TEST(SourceCallReturnReads, NonMemoryOperationsDoNotMultiplyByteHistories) {
  for (unsigned Written : {4u, 8u}) {
    auto Func = observedCallSlot();
    auto &Ops = Func.Blocks.front().Ops;
    Ops.insert(Ops.begin() + 5, op(NdOp::STORE, none(),
                                   {temp(20), MedVar::makeConst(29, Written)}));
    Ops.insert(Ops.begin() + 6, 2048, op(NdOp::NOP, none(), {}));
    std::string Error;
    EXPECT_EQ(validateSourceCallReturnReads(Func, callSlotImage(), Error, 8192),
              Written == 8)
        << Error;
    if (Written != 8)
      EXPECT_NE(Error.find("physical CALL return slot"), std::string::npos)
          << Error;
  }
}

TEST(SourceCallReturnReads, BoundedAllocationsSeparateTheFixedFrame) {
  for (bool Bounded : {false, true})
    for (bool Overlap : {false, true}) {
      auto Func = observedCallSlot();
      auto &Ops = Func.Blocks.front().Ops;
      if (!Overlap)
        Ops[2].Opcode = NdOp::INT_ADD;
      Ops.insert(Ops.begin() + 4,
                 {op(Bounded ? NdOp::INT_ZEXT : NdOp::COPY, temp(30),
                     {MedVar::makeUnspecified(Bounded ? 4 : 8, Arch::X64)}),
                  op(NdOp::INT_SUB, sp(2), {sp(1), temp(30)})});
      std::string Error;
      EXPECT_EQ(validateSourceCallReturnReads(Func, callSlotImage(), Error),
                Bounded && !Overlap)
          << Error;
    }
}

TEST(SourceCallReturnReads, BoundedCallResultsKeepPhysicalSlotChecks) {
  auto Image = callSlotImage();
  Image.Segments.front().Data[16] = 0xe8;
  for (bool HasRange : {false, true})
    for (bool Negative : {false, true}) {
      auto Func = observedCallSlot();
      auto &Ops = Func.Blocks.front().Ops;
      // The saved word is above both call slots when the allocation only
      // lowers SP. A signed negative count can instead raise it into that word.
      Ops[2].Opcode = NdOp::INT_ADD;
      auto Result = temp(40);
      Result.Kind = MedVar::Reg;
      Result.RegOff = getTargetRegInfo(Image.Arch).IntReturnReg;
      auto Query = op(NdOp::CALL, Result, {MedVar::makeConst(0x2000, 8)});
      Query.Addr = 0x1008;
      auto Narrow = temp(41);
      Narrow.Size = 4;
      Ops[4].Addr = 0x1010;
      Ops[4].Inputs[0] = MedVar::makeConst(0x3000, 8);
      Ops[5].Addr = 0x1015;
      Ops.insert(Ops.begin() + 4,
                 {Query,
                  op(NdOp::SUBBYTES, Narrow, {Result, MedVar::makeConst(0, 4)}),
                  op(NdOp::INT_SEXT, temp(42), {Narrow}),
                  op(NdOp::INT_SUB, sp(2), {sp(1), temp(42)})});
      MedCallReturnRanges Ranges;
      if (HasRange)
        Ranges.try_emplace(
            0x2000, MedIntegerReturnRange{Image.Arch, 8, 0,
                                          Negative ? UINT32_MAX : UINT16_MAX});
      std::string Error;
      EXPECT_EQ(validateSourceCallReturnReads(
                    Func, Image, Error, limits::ir::kSourceCallReturnReadWork,
                    nullptr, &Ranges),
                HasRange && !Negative)
          << Error;
      if (!HasRange || Negative)
        EXPECT_NE(Error.find("physical CALL return slot"), std::string::npos);
    }
}

TEST(SourceCallReturnReads, SparseStackWritesNeedOnlyOneOperationScan) {
  auto Func = observedCallSlot();
  auto &Ops = Func.Blocks.front().Ops;
  Ops[2].Inputs[1] = MedVar::makeConst(16, 8);
  Ops.insert(Ops.begin() + 4, 2048, op(NdOp::NOP, none(), {}));
  std::string Error;
  EXPECT_TRUE(validateSourceCallReturnReads(Func, callSlotImage(), Error, 4352))
      << Error;
  Ops[2].Inputs[1] = MedVar::makeConst(8, 8);
  EXPECT_FALSE(
      validateSourceCallReturnReads(Func, callSlotImage(), Error, 4352));
  EXPECT_NE(Error.find("physical CALL return slot"), std::string::npos)
      << Error;
}

TEST(SourceCallReturnReads, ManyCallsShareTheConvergedStackBasis) {
  for (bool Cycle : {false, true})
    for (bool Reversed : {false, true}) {
      SCOPED_TRACE(testing::Message() << Cycle << ":" << Reversed);
      auto Func = observedCallSlot();
      auto &Entry = Func.Blocks.front();
      const auto Call = Entry.Ops[4];
      const auto Load = Entry.Ops[5];
      Entry.Ops.resize(3);
      Entry.Ops[2].Opcode = NdOp::INT_ADD;
      Entry.Ops[2].Inputs[1] = MedVar::makeConst(16, 8);
      Entry.Succs = {1};
      constexpr int Blocks = 128;
      for (int I = 1; I <= Blocks; ++I) {
        MedBlock Block;
        Block.Id = I;
        Block.StartAddr = 0x2000 + I * 32;
        Block.Preds = {I - 1};
        if (I < Blocks)
          Block.Succs = {I + 1};
        Block.Ops.assign(24, op(NdOp::NOP, none(), {}));
        Block.Ops.push_back(Call);
        Block.Ops.push_back(Load);
        Func.Blocks.push_back(std::move(Block));
      }
      if (Cycle) {
        Func.Blocks.back().Succs = {1};
        Func.Blocks[1].Preds.push_back(Blocks);
      }
      if (Reversed)
        std::reverse(Func.Blocks.begin() + 1, Func.Blocks.end());
      std::string Error;
      EXPECT_TRUE(
          validateSourceCallReturnReads(Func, callSlotImage(), Error, 16384))
          << Error;
      // Sharing the stack analysis must retain the physical return-slot
      // hazard when the same graph actually reads that slot.
      Func.Blocks[0].Ops[2].Opcode = NdOp::INT_SUB;
      Func.Blocks[0].Ops[2].Inputs[1] = MedVar::makeConst(8, 8);
      EXPECT_FALSE(
          validateSourceCallReturnReads(Func, callSlotImage(), Error, 16384));
      EXPECT_NE(Error.find("physical CALL return slot"), std::string::npos)
          << Error;
    }
}

TEST(SourceCallReturnReads, BackedgeConflictsCannotPublishAProvisionalBasis) {
  for (bool Reversed : {false, true}) {
    auto Func = observedCallSlot();
    auto &Entry = Func.Blocks.front();
    const auto Call = Entry.Ops[4];
    const auto Load = Entry.Ops[5];
    Entry.Ops.resize(3);
    Entry.Ops[2].Opcode = NdOp::INT_ADD;
    Entry.Ops[2].Inputs[1] = MedVar::makeConst(16, 8);
    Entry.Succs = {1};
    MedBlock Loop;
    Loop.Id = 1;
    Loop.StartAddr = 0x2000;
    Loop.Preds = {0, 2};
    Loop.Succs = {2};
    Loop.Ops = {Call, Load};
    Func.Blocks.push_back(Loop);
    MedBlock Backedge;
    Backedge.Id = 2;
    Backedge.StartAddr = 0x3000;
    Backedge.Preds = {1};
    Backedge.Succs = {1};
    Backedge.Ops = {
        op(NdOp::INT_ADD, sp(2), {sp(1), MedVar::makeConst(24, 8)})};
    Func.Blocks.push_back(Backedge);
    if (Reversed)
      std::swap(Func.Blocks[1], Func.Blocks[2]);
    std::string Error;
    EXPECT_FALSE(validateSourceCallReturnReads(Func, callSlotImage(), Error));
    EXPECT_NE(Error.find("physical CALL return slot"), std::string::npos)
        << Error;
  }
}

TEST(SourceCallReturnReads, TailJumpsDoNotAcquireAPush) {
  std::string Error;
  EXPECT_TRUE(validateSourceCallReturnReads(observedCallSlot(),
                                            callSlotImage(0xe9), Error))
      << Error;
  EXPECT_FALSE(validateSourceCallReturnReads(observedCallSlot(),
                                             callSlotImage(0x90), Error));
}

TEST(SourceCallReturnReads, LocalByteWritesBoundExceptionalEntryObservations) {
  for (bool Incoming : {false, true})
    for (unsigned Bytes : {0u, 1u, 8u}) {
      SCOPED_TRACE(testing::Message() << Incoming << ":" << Bytes);
      auto Func = observedCallSlot();
      auto &Block = Func.Blocks.front();
      if (Incoming)
        Block.ExceptionalPreds.emplace_back(-1, Block.StartAddr);
      else
        Block.ExceptionalSuccs.emplace_back(-1, 0x3000);
      if (Bytes)
        Block.Ops.insert(
            Block.Ops.begin() + 5,
            op(NdOp::STORE, none(), {temp(20), MedVar::makeConst(29, Bytes)}));
      std::string Error;
      EXPECT_EQ(validateSourceCallReturnReads(Func, callSlotImage(), Error),
                Bytes == 8)
          << Error;
      // Reading before CALL is protected by the initial complete store,
      // including when dispatch can enter this block exceptionally.
      Func = observedCallSlot();
      if (Incoming)
        Func.Blocks[0].ExceptionalPreds.emplace_back(-1, Func.Entry);
      else
        Func.Blocks[0].ExceptionalSuccs.emplace_back(-1, 0x3000);
      std::swap(Func.Blocks[0].Ops[4], Func.Blocks[0].Ops[5]);
      EXPECT_TRUE(validateSourceCallReturnReads(Func, callSlotImage(), Error))
          << Error;
      // Without that local definition, an exceptional entry cannot inherit
      // the ordinary caller's frame history merely from its normal CFG.
      if (Incoming) {
        Func.Blocks[0].Ops.erase(Func.Blocks[0].Ops.begin() + 3);
        EXPECT_FALSE(
            validateSourceCallReturnReads(Func, callSlotImage(), Error));
        EXPECT_NE(Error.find("exceptional entry"), std::string::npos);
      }
    }
}

MedFunc exceptionalCallSlot(va_t Source) {
  auto Func = observedCallSlot();
  MedBlock Handler;
  Handler.Id = 1;
  Handler.StartAddr = 0x1020;
  Handler.Ops = {Func.Blocks[0].Ops[5], Func.Blocks[0].Ops[6]};
  Handler.Ops[0].Addr = Handler.StartAddr;
  auto &Entry = Func.Blocks[0];
  Entry.Ops.resize(5);
  Entry.Ops[3].Addr = 0x1006;
  Entry.Ops.push_back(
      op(NdOp::STORE, none(), {temp(20), MedVar::makeConst(29, 8)}));
  Entry.Ops.back().Addr = 0x100d;
  Entry.Ops.push_back(op(NdOp::COPY, temp(23), {MedVar::makeConst(31, 8)}));
  Entry.Ops.back().Addr = 0x1010;
  Entry.ExceptionalSuccs.emplace_back(Handler.Id, Handler.StartAddr,
                                      ExceptionalEdgeKind::SEHFilter, 0, -1,
                                      Source);
  Handler.ExceptionalPreds = Entry.ExceptionalSuccs;
  Handler.ExceptionalPreds[0].BlockId = Entry.Id;
  Func.Blocks.push_back(std::move(Handler));
  return Func;
}

TEST(SourceCallReturnReads, ExceptionalSourcesRetainEveryPossibleCallWrite) {
  for (va_t Source :
       {va_t{0x1006}, va_t{0x1008}, va_t{0x100d}, va_t{0x1010}, InvalidVA})
    for (unsigned Bytes : {0u, 4u, 8u}) {
      SCOPED_TRACE(testing::Message() << Source << ":" << Bytes);
      auto Func = exceptionalCallSlot(Source);
      if (Bytes)
        Func.Blocks[1].Ops.insert(
            Func.Blocks[1].Ops.begin(),
            op(NdOp::STORE, none(), {temp(20), MedVar::makeConst(37, Bytes)}));
      std::string Error;
      // The filter can observe a CALL push even if the throwing CALL never
      // returns. A later parent store helps only when it definitely completed
      // before the exception; a handler store kills just its own bytes.
      EXPECT_EQ(validateSourceCallReturnReads(Func, callSlotImage(), Error),
                Bytes == 8 || Source == 0x1006 || Source == 0x1010)
          << Error;
    }
}

TEST(SourceCallReturnReads, ExceptionalHistoryRequiresTheCurrentSourceEdge) {
  for (unsigned Change = 0; Change != 5; ++Change) {
    SCOPED_TRACE(Change);
    auto Func = exceptionalCallSlot(0x1010);
    auto &Entry = Func.Blocks[0];
    auto &Handler = Func.Blocks[1];
    switch (Change) {
    case 0:
      Entry.ExceptionalSuccs.clear();
      break;
    case 1:
      Handler.ExceptionalPreds.clear();
      break;
    case 2:
      Handler.ExceptionalPreds[0].SourceVA = 0x1006;
      break;
    case 3:
      Entry.ExceptionalSuccs[0].SourceVA = 0x1030;
      Handler.ExceptionalPreds[0].SourceVA = 0x1030;
      break;
    case 4:
      Entry.ExceptionalSuccs[0].TargetVA = 0x1030;
      Handler.ExceptionalPreds[0].TargetVA = 0x1030;
      break;
    }
    std::string Error;
    EXPECT_FALSE(validateSourceCallReturnReads(Func, callSlotImage(), Error));
    EXPECT_NE(Error.find("exceptional entry"), std::string::npos) << Error;
  }
}

TEST(SourceCallReturnReads, RestoredRegistrationStacksNeedFreshSourceFacts) {
  for (unsigned Change = 0; Change != 12; ++Change) {
    SCOPED_TRACE(Change);
    auto Func = observedCallSlot();
    auto &Ops = Func.Blocks[0].Ops;
    Ops[2].Inputs[1].ConstVal = 4;
    const auto Call = Ops[4], Load = Ops[5], Return = Ops[6];
    Ops.resize(4);
    Ops.push_back(op(NdOp::INT_SUB, temp(23),
                     {sp(1), MedVar::makeConst(Change == 11 ? 0 : 16, 8)}));
    Ops.push_back(
        op(NdOp::INT_ADD, temp(24), {sp(1), MedVar::makeConst(8, 8)}));
    Ops.push_back(op(NdOp::STORE, none(), {temp(24), temp(23)}));
    Ops.push_back(op(NdOp::LOAD, temp(25), {temp(24)}));
    Ops.push_back(op(NdOp::COPY, sp(2), {temp(25)}));
    Ops.insert(Ops.end(), {Call, Load, Return});
    for (size_t I = 0; I < Ops.size(); ++I) {
      auto &Op = Ops[I];
      Op.Addr = I == 9 ? 0x1008 : 0x1100 + I;
      Op.OriginSeq = 0;
      Op.Output.TheArch = Arch::X86;
      if (Op.Output.Size)
        Op.Output.Size = 4;
      for (unsigned K = 0; K < Op.NumInputs; ++K) {
        Op.Inputs[K].TheArch = Arch::X86;
        Op.Inputs[K].Size = 4;
      }
    }
    LowFunc Source;
    Source.Entry = Func.Entry;
    Source.ExceptionMetadata.emplace();
    auto &EH = *Source.ExceptionMetadata;
    EH.CodeRange = {Func.Entry, 0x1200};
    EH.ParseStatus = ExceptionParseStatus::Complete;
    EH.Encoding = ExceptionEncoding::X86ScopeTableEH3;
    EH.Registration.emplace();
    Source.RegistrationStates.emplace();
    auto &States = *Source.RegistrationStates;
    States.Complete = States.CallbackStatesComplete =
        States.RegistrationLifetimeComplete = true;
    States.FrameValues = {{Ops[1].Addr, 0, -28},
                          {Ops[8].Addr, 0, Change == 11 ? -28 : -44}};
    Source.Blocks.emplace_back();
    auto ToLow = [](const MedVar &V) {
      return V.isConst()             ? NdVar::cst(V.ConstVal, V.Size)
             : V.Kind == MedVar::Reg ? NdVar::reg(V.RegOff, V.Size)
                                     : NdVar::tmp(V.Id, V.Size);
    };
    for (const auto &Op : Ops) {
      LowOp Original;
      Original.Addr = Op.Addr;
      Original.Seq = Op.OriginSeq;
      Original.Opcode = Op.Opcode;
      Original.Output = ToLow(Op.Output);
      for (unsigned K = 0; K < Op.NumInputs; ++K)
        Original.addInput(ToLow(Op.Inputs[K]));
      Source.Blocks[0].Ops.push_back(Original);
    }
    auto Image = callSlotImage();
    Image.Arch = Arch::X86;
    Image.Format = BinaryFormat::COFF;
    switch (Change) {
    case 2:
      States.Complete = false;
      break;
    case 3:
      States.CallbackStatesComplete = false;
      break;
    case 4:
      States.RegistrationLifetimeComplete = false;
      break;
    case 5:
      Ops[8].OriginSeq = 1;
      break;
    case 6:
      Source.Blocks[0].Ops[8].Opcode = NdOp::INT_ZEXT;
      break;
    case 7:
      Source.Blocks[0].Ops[9].Inputs[0].Offset += 4;
      break;
    case 8:
      EH.Registration->RealignedFrame.emplace();
      break;
    case 9:
      Image.Format = BinaryFormat::ELF;
      break;
    case 10:
      States.FrameValues[1].EstablishedFrameOffset.reset();
      break;
    }
    std::string Error;
    EXPECT_EQ(validateSourceCallReturnReads(
                  Func, Image, Error, limits::ir::kSourceCallReturnReadWork,
                  Change == 1 ? nullptr : &Source),
              Change == 0)
        << Error;
  }
}

TEST(SourceCallReturnReads, AStoreOnAnotherPathDoesNotHideACall) {
  auto Func = observedCallSlot();
  auto &Entry = Func.Blocks[0];
  const auto Call = Entry.Ops[4];
  const auto Load = Entry.Ops[5];
  const auto Return = Entry.Ops[6];
  const auto Store = Entry.Ops[3];
  Entry.Ops.resize(4);
  Entry.Succs = {1, 2};
  MedBlock Left, Right, Join;
  Left.Id = 1;
  Left.Preds = {0};
  Left.Succs = {3};
  Left.Ops = {Call};
  Right.Id = 2;
  Right.Preds = {0};
  Right.Succs = {3};
  Right.Ops = {Store};
  Join.Id = 3;
  Join.Preds = {1, 2};
  Join.Ops = {Load, Return};
  Func.Blocks.insert(Func.Blocks.end(), {Left, Right, Join});
  std::string Error;
  EXPECT_FALSE(validateSourceCallReturnReads(Func, callSlotImage(), Error));
  Func.Blocks[1].Ops.push_back(Store);
  EXPECT_TRUE(validateSourceCallReturnReads(Func, callSlotImage(), Error))
      << Error;
}

TEST(SourceCallReturnReads, ALaterCallCanReachTheNextLoopIteration) {
  auto Func = observedCallSlot();
  auto &Entry = Func.Blocks[0];
  const auto Call = Entry.Ops[4];
  const auto Load = Entry.Ops[5];
  Entry.Ops.resize(4);
  Entry.Succs = {1};
  MedBlock Loop;
  Loop.Id = 1;
  Loop.Preds = {0, 1};
  Loop.Succs = {1};
  Loop.Ops = {Load, Call};
  Func.Blocks.push_back(Loop);
  std::string Error;
  EXPECT_FALSE(validateSourceCallReturnReads(Func, callSlotImage(), Error));
}

TEST(SourceCallReturnReads, BalancedLoopCallsSeparateOnlyProvenLocalBytes) {
  for (BinaryFormat Format :
       {BinaryFormat::COFF, BinaryFormat::ELF, BinaryFormat::MachO})
    for (bool Drifts : {false, true})
      for (int Slot : {8, -8, -24}) {
        SCOPED_TRACE(testing::Message() << static_cast<int>(Format) << ":"
                                        << Drifts << ":" << Slot);
        auto Func = observedCallSlot();
        auto Image = callSlotImage();
        Image.Format = Format;
        Image.Segments[0].Data[16] = 0xe8;
        Image.Segments[0].Data[24] = 0xe8;
        auto &Entry = Func.Blocks[0];
        auto Load = Entry.Ops[5];
        Load.Addr = 0x1008;
        auto Call = Entry.Ops[4];
        Call.Addr = 0x1010;
        auto RestoredCall = Call;
        RestoredCall.Addr = 0x1018;
        RestoredCall.Output = temp(23);
        Entry.Ops.resize(4);
        Entry.Ops[2] =
            op(NdOp::INT_ADD, temp(20), {sp(1), MedVar::makeConst(Slot, 8)});
        Entry.Succs = {1};
        MedBlock Loop;
        Loop.Id = 1;
        Loop.StartAddr = 0x1008;
        Loop.Preds = {0, 1};
        Loop.Succs = {1};
        PhiNode Stack;
        Stack.Output = sp(2);
        Stack.Args = {{0, sp(1)}, {1, sp(4)}};
        Loop.Phis.push_back(std::move(Stack));
        Loop.Ops = {Load,
                    op(NdOp::INT_SUB, sp(3), {sp(2), MedVar::makeConst(16, 8)}),
                    Call,
                    op(NdOp::INT_ADD, sp(4),
                       {sp(3), MedVar::makeConst(Drifts ? 24 : 16, 8)}),
                    RestoredCall};
        Func.Blocks.push_back(std::move(Loop));
        std::string Error;
        EXPECT_EQ(validateSourceCallReturnReads(Func, Image, Error),
                  !Drifts && Slot == 8)
            << Error;
      }
}

TEST(SourceCallReturnReads,
     MissingStackAndMalformedGraphsDoNotGrantSeparation) {
  auto Func = observedCallSlot();
  Func.Blocks[0].Ops.insert(
      Func.Blocks[0].Ops.begin() + 4,
      op(NdOp::COPY, sp(2), {MedVar::makeUnspecified(8, Arch::X64)}));
  std::string Error;
  EXPECT_FALSE(validateSourceCallReturnReads(Func, callSlotImage(), Error));
  Func = observedCallSlot();
  Func.Blocks[0].Preds = {99};
  EXPECT_FALSE(validateSourceCallReturnReads(Func, callSlotImage(), Error));
  EXPECT_NE(Error.find("complete normal"), std::string::npos);
}

TEST(SourceCallReturnReads, LinkRegisterCallsDoNotWriteAStackSlot) {
  for (Arch Architecture : {Arch::ARM, Arch::AArch64}) {
    auto Image = callSlotImage();
    Image.Arch = Architecture;
    std::string Error;
    EXPECT_TRUE(validateSourceCallReturnReads(observedCallSlot(), Image, Error))
        << Error;
  }
}

TEST(SourceCallReturnReads,
     BudgetExhaustionNeverPublishesAnUncheckedProjection) {
  std::string Error;
  EXPECT_FALSE(validateSourceCallReturnReads(observedCallSlot(),
                                             callSlotImage(), Error, 0));
  EXPECT_NE(Error.find("work budget"), std::string::npos);
  EXPECT_TRUE(validateSourceCallReturnReads(observedCallSlot(),
                                            callSlotImage(0xe9), Error));
  EXPECT_TRUE(Error.empty());
}

TEST(SourceFrameBorrows, ReadExtentsAndEscapesBoundPrivateStoreRemoval) {
  for (unsigned Case = 0; Case != 22; ++Case) {
    SCOPED_TRACE(Case);
    MedFunc Caller;
    Caller.Entry = 0x1000;
    Caller.CC = CallingConv::Win64;
    Caller.FrameSize = 0x38;
    MedBlock Block;
    Block.Id = 0;
    Block.StartAddr = Caller.Entry;
    auto Word = temp(20);
    Word.Size = 4;
    Block.Ops = {
        op(NdOp::COPY, sp(0), {sp(0)}),
        op(NdOp::INT_SUB, sp(1), {sp(0), MedVar::makeConst(0x38, 8)}),
        op(NdOp::INT_ADD, temp(10), {sp(1), MedVar::makeConst(0x20, 8)}),
        op(NdOp::INT_ADD, temp(11), {sp(1), MedVar::makeConst(0x24, 8)}),
        op(NdOp::STORE, none(),
           {temp(10), MedVar::makeUnspecified(4, Arch::X64)}),
        op(NdOp::STORE, none(), {temp(11), MedVar::makeConst(37, 4)}),
        op(NdOp::CALL, Word, {MedVar::makeConst(0x2000, 8), temp(11)}),
        op(NdOp::INT_ADD, sp(2), {sp(1), MedVar::makeConst(0x38, 8)}),
        op(NdOp::RETURN, none(), {Word})};
    Block.Ops[6].CalleeRegisterArgs = 1;
    Block.Ops[6].CalleeStackArgs = 0;
    Block.Ops[6].CalleeVectorArgs = 0;
    Caller.Blocks.push_back(std::move(Block));
    MedCallInfo Call;
    Call.BlockId = 0;
    Call.OpIdx = 6;
    Call.TargetAddr = 0x2000;
    Call.Args = {temp(11)};
    Caller.CallInfos.push_back(Call);

    MedFunc Callee;
    Callee.Entry = Call.TargetAddr;
    Callee.CC = CallingConv::Win64;
    Callee.Params = {rcx(0)};
    MedBlock Body;
    Body.Id = 0;
    Body.StartAddr = Callee.Entry;
    Body.Ops = {op(NdOp::COPY, rcx(0), {rcx(0)}),
                op(NdOp::LOAD, Word, {rcx(0)}),
                op(NdOp::RETURN, none(), {Word})};
    if (Case == 1 || Case == 2) {
      Body.Ops.insert(
          Body.Ops.begin() + 1,
          op(NdOp::INT_SUB, temp(30), {rcx(0), MedVar::makeConst(4, 8)}));
      Body.Ops[2].Inputs[0] = temp(30);
      if (Case == 2)
        Body.Ops[2].Output.Size = 8;
    } else if (Case == 3) {
      Body.Ops.back().Inputs[0] = rcx(0);
    } else if (Case == 4) {
      Body.Ops.insert(
          Body.Ops.begin() + 1,
          op(NdOp::STORE, none(), {MedVar::makeConst(0x3000, 8), rcx(0)}));
    } else if (Case == 5) {
      auto Narrow = temp(30);
      Narrow.Size = 4;
      Body.Ops.insert(
          Body.Ops.begin() + 1,
          op(NdOp::SUBBYTES, Narrow, {rcx(0), MedVar::makeConst(0, 4)}));
      Body.Ops.insert(
          Body.Ops.begin() + 2,
          op(NdOp::STORE, none(), {MedVar::makeConst(0x3000, 8), Narrow}));
    } else if (Case == 6) {
      Body.ExceptionalSuccs.emplace_back();
    } else if (Case == 7) {
      Callee.SkippedSSA = true;
    } else if (Case == 8) {
      Caller.CallInfos[0].IsIndirect = true;
    } else if (Case == 10) {
      Body.Ops[1].Inputs[0] = reg(8, x86reg::RDX, 0);
    } else if (Case == 9) {
      Body.Ops.insert(Body.Ops.begin() + 1,
                      op(NdOp::INDIR_CALL, temp(30), {rcx(0)}));
    }
    if (Case == 13) {
      Body.Ops[1].Output = reg(9, x86reg::RAX, 0);
      Body.Ops[1].Output.Size = 4;
      Body.Ops.back().Inputs[0] = Body.Ops[1].Output;
    }
    if (Case == 14 || Case == 15) {
      // A narrow non-argument carrier can still disclose pointer bits.
      // AH is not the low slice of its family; a scalar XMM lane is not a GPR.
      auto Input = reg(40, Case == 14 ? x86reg::RAX + 1 : x86reg::XMM0, 0);
      Input.Size = Case == 14 ? 1 : 4;
      Body.Ops.insert(
          Body.Ops.begin() + 1,
          op(NdOp::STORE, none(), {MedVar::makeConst(0x3000, 8), Input}));
    }
    if (Case == 16)
      Callee.EntryKind = StackEntryKind::ProcessEntry;
    if (Case == 17)
      Body.Ops.back().Inputs[0] = sp(0);
    if (Case == 18)
      Body.Ops.insert(
          Body.Ops.begin() + 1,
          op(NdOp::STORE, none(), {MedVar::makeConst(0x3000, 8), sp(0)}));
    if (Case == 19) {
      Body.Ops.insert(
          Body.Ops.begin() + 1,
          op(NdOp::INT_ADD, temp(30), {sp(0), MedVar::makeConst(0x28, 8)}));
      Body.Ops[2].Inputs[0] = temp(30);
    }
    if (Case == 20 || Case == 21) {
      Caller.CallInfos[0].IsIndirect = true;
      Caller.CallInfos[0].Args.clear();
      auto &Invoke = Caller.Blocks[0].Ops[6];
      Invoke.Opcode = NdOp::INDIR_CALL;
      Invoke.CalleeRegisterArgs = 0;
      Invoke.NumInputs = 1;
      if (Case == 21) {
        Invoke.Output = none();
        Caller.Blocks[0].Ops.back().Inputs[0] = MedVar::makeConst(37, 4);
      }
    }
    if (Case == 11)
      Caller.Blocks[0].Ops[2].Inputs[1] = MedVar::makeConst(0x18, 8);
    if (Case == 12)
      Callee.SourceParametersBound = true;
    Callee.Blocks.push_back(std::move(Body));
    const std::map<va_t, const MedFunc *> Callees{{Callee.Entry, &Callee}};
    markUnobservedBorrowedFrameStores(Caller, Arch::X64, BinaryFormat::COFF,
                                      Callees);
    EXPECT_EQ(Caller.Blocks[0].Ops[4].PrologueSave, Case == 0 || Case == 13);
    EXPECT_FALSE(Caller.Blocks[0].Ops[5].PrologueSave);
    EXPECT_EQ(Caller.Blocks[0].Ops[6].Opcode,
              Case >= 20 ? NdOp::INDIR_CALL : NdOp::CALL);
  }
}

} // namespace
