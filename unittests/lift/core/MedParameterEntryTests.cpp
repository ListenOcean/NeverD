//===- MedParameterEntryTests.cpp - Pointer entry-value identity ---------===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Local and forwarded pointer roles require an actual incoming value.
///
//===----------------------------------------------------------------------===//

#include "gtest/gtest.h"

#include "neverd/ir/TargetRegInfo.h"
#include "neverd/ir/med/MedIR.h"
#include "neverd/ir/med/MedTypePass.h"

#include <algorithm>
#include <vector>

using namespace neverd;

namespace {
void checkEntryIdentity(bool Forwarded) {
  for (auto Architecture : {Arch::X86, Arch::X64, Arch::ARM, Arch::AArch64})
    for (unsigned Mutation = 0; Mutation != 16; ++Mutation)
      for (bool Reverse : {false, true}) {
        SCOPED_TRACE(unsigned(Architecture));
        SCOPED_TRACE(Mutation);
        SCOPED_TRACE(Reverse);
        const auto &Registers = getTargetRegInfo(Architecture);
        const auto Bytes = Registers.PointerSize;
        MedVar Parameter;
        Parameter.Kind = MedVar::Param;
        Parameter.Id = 1;
        Parameter.TheArch = Architecture;
        Parameter.RegOff = Registers.IntParamRegs[0];
        Parameter.Size = Bytes;
        auto Incoming = Parameter;
        Incoming.Kind = MedVar::Reg;
        Incoming.Id = 100;
        auto Value = Incoming;
        MedFunc Function;
        Function.Entry = 0x1000;
        Function.Params = {Parameter};
        Function.Blocks.resize(1);
        auto &Block = Function.Blocks.front();
        Block.Id = 0;
        if (Mutation == 1 || Mutation == 10) {
          MedCallClobber Clobber;
          Clobber.Value = Incoming;
          if (Mutation == 10)
            ++Clobber.Value.Id;
          Function.CallClobbers.push_back(Clobber);
        } else if (Mutation == 2 || Mutation == 7 || Mutation == 8 ||
                   Mutation == 9) {
          MedOp Copy;
          Copy.Opcode = NdOp::COPY;
          Copy.Output = Incoming;
          if (Mutation == 7) {
            ++Copy.Output.Id;
            Copy.Output.Size = Bytes / 2;
          } else if (Mutation == 9) {
            Copy.Output.Kind = MedVar::Temp;
          }
          Copy.addInput(Mutation == 8 ? Incoming
                                      : MedVar::makeConst(7, Copy.Output.Size));
          Block.Ops.push_back(Copy);
        } else if (Mutation == 3) {
          PhiNode Phi;
          Phi.Output = Incoming;
          Phi.Args = {{1, MedVar::makeConst(7, Bytes)},
                      {2, MedVar::makeConst(11, Bytes)}};
          Block.Phis.push_back(Phi);
        } else if (Mutation == 4) {
          ++Value.SSAVer;
        } else if (Mutation == 5) {
          Value.Size /= 2;
        } else if (Mutation == 6 || Mutation == 11 || Mutation >= 14) {
          Value = Parameter;
          if (Mutation == 6)
            ++Value.Id;
          else if (Mutation == 11)
            Value.RegOff = Registers.IntParamRegs[1];
          else if (Mutation == 15)
            Value.Size /= 2;
        } else if (Mutation == 12) {
          auto Duplicate = Parameter;
          ++Duplicate.Id;
          Function.Params.push_back(Duplicate);
        } else if (Mutation == 13) {
          Value.Kind = MedVar::Temp;
        }

        MedOp Load;
        Load.Opcode = NdOp::LOAD;
        Load.addInput(Value);
        if (!Forwarded)
          Block.Ops.push_back(Load);
        MedFunc Leaf;
        Leaf.Entry = 0x2000;
        Leaf.Params = {Parameter};
        Leaf.Blocks.resize(1);
        Load.Inputs[0] = Incoming;
        Leaf.Blocks[0].Ops.push_back(Load);
        if (Forwarded) {
          MedCallInfo Call;
          Call.TargetAddr = Leaf.Entry;
          Call.Args = {Value};
          Function.CallInfos.push_back(Call);
        }
        MedFunc Outer;
        Outer.Entry = 0x3000;
        Outer.Params = Function.Params;
        MedCallInfo Call;
        Call.TargetAddr = Function.Entry;
        Call.Args = {Incoming};
        Outer.CallInfos.push_back(Call);
        std::vector<MedFunc> Functions{Outer, Function, Leaf};
        if (Reverse)
          std::reverse(Functions.begin(), Functions.end());
        propagateForwardedPointerParams(Functions, Architecture);
        const bool Pointer = Mutation == 0 || Mutation == 7 || Mutation == 8 ||
                             Mutation == 9 || Mutation == 10 || Mutation == 14;
        for (const auto &F : Functions) {
          ASSERT_FALSE(F.TypedParams.empty());
          EXPECT_EQ(F.TypedParams[0].Type->Kind,
                    Pointer || F.Entry == Leaf.Entry ? NdTypeKind::Ptr
                                                     : NdTypeKind::Int);
        }
      }
}
} // namespace

TEST(MedParameterEntry, AddressUsesNeedTheIncomingValue) {
  checkEntryIdentity(false);
}

TEST(MedParameterEntry, ForwardedUsesNeedTheIncomingValue) {
  checkEntryIdentity(true);
}
