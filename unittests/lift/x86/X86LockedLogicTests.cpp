//===- X86LockedLogicTests.cpp - Native locked logical transactions ------===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
/// \file
/// Compare original memory and flags with both C routes at unaligned addresses.
//===----------------------------------------------------------------------===//

#include "../x86_64/X86FPStateAccuracyFixture.h"

#include "neverd/ir/med/IntrinsicShapes.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace {
class X86LockedLogicSource : public X86FPStateFixture {};

TEST_F(X86LockedLogicSource, EveryWidthRetainsMemoryAndCompletedFlags) {
  if (!nativeX64() || hostFormat() != BinaryFormat::ELF)
    GTEST_SKIP() << "native locked logical comparison requires Linux x64";
  BinaryImage Image;
  Image.Arch = Arch::X64;
  Image.Bits = Bitness::Bits64;
  Image.Format = BinaryFormat::ELF;
  Image.Base = Image.Entry = Entry;
  Segment Text;
  Text.VA = Entry;
  Text.Flags = SegmentFlags::Readable | SegmentFlags::Executable;
  std::vector<va_t> Entries;
  std::string Oracles, Checks;
  for (unsigned Kind = 0; Kind != 3; ++Kind)
    for (unsigned Width : {1u, 2u, 4u, 8u})
      for (bool Immediate : {false, true})
        for (bool Segmented : {false, true})
          for (bool Dead : {false, true}) {
            const unsigned Index = Entries.size();
            const va_t Address = Entry + Index * 64;
            Entries.push_back(Address);
            std::vector<uint8_t> Bytes;
            if (Segmented)
              Bytes.push_back(0x65);
            Bytes.push_back(0xf0);
            if (Width == 2)
              Bytes.push_back(0x66);
            if ((!Immediate && Width == 1) || Width == 8)
              Bytes.push_back(Width == 1 ? 0x40 : 0x48);
            const unsigned Opcode = Kind == 0 ? 0x20 : Kind == 1 ? 0x08 : 0x30;
            // LOCK AND/OR/XOR [RDI], SIL/SI/ESI/RSI.
            if (Immediate) {
              const unsigned Extension = Kind == 0 ? 4 : Kind == 1 ? 1 : 6;
              Bytes.insert(Bytes.end(), {uint8_t(Width == 1 ? 0x80 : 0x81),
                                         uint8_t((Extension << 3) | 7)});
              const uint32_t Value = Width == 2 ? 0x8081 : 0x80000081;
              for (unsigned I = 0; I != std::min(Width, 4u); ++I)
                Bytes.push_back(Value >> (I * 8));
            } else {
              Bytes.insert(Bytes.end(), {uint8_t(Opcode + (Width != 1)), 0x37});
            }
            if (Dead)
              Bytes.insert(Bytes.end(), {0x31, 0xc0});
            else
              // Only architecturally defined logical flags are observed.
              Bytes.insert(Bytes.end(), {0x9c, 0x58, 0x25, 0xc5, 0x08, 0, 0});
            Bytes.push_back(0xc3);
            Text.Data.resize(Index * 64, 0x90);
            Text.Data.insert(Text.Data.end(), Bytes.begin(), Bytes.end());
            const std::string Name = "logic_" + std::to_string(Index);
            auto Symbol = neverd::Symbol::makeFunc(Address, Bytes.size());
            Symbol.Name = Name;
            Image.Symbols.push_back(std::move(Symbol));
            const auto Native = "original_" + std::to_string(Index);
            Oracles += "extern uint64_t " + Native + "(void *, uint64_t);\n";
            Oracles += "__asm__(\".text\\n.globl " + Native + "\\n" + Native +
                       ":\\n.byte ";
            for (size_t I = 0; I < Bytes.size(); ++I) {
              if (I)
                Oracles += ',';
              Oracles += std::to_string(Bytes[I]);
            }
            Oracles += "\\n\");\n";
            Checks +=
                "for(unsigned off=1;off<8;off+=3) for(unsigned a=0;a<8;++a) "
                "for(unsigned b=0;b<" +
                std::string(Immediate ? "1" : "8") + ";++b) {\n";
            Checks += "unsigned char x[32],y[32];memset(x,0xa5,sizeof(x));\n";
            Checks += "memcpy(x+off,&values[a]," + std::to_string(Width) +
                      ");memcpy(y,x,sizeof(x));\n";
            if (Segmented)
              Checks +=
                  "if(syscall(SYS_arch_prctl,ARCH_SET_GS,x))return 201;\n";
            Checks += "uint64_t expected=" + Native +
                      (Segmented ? "((void*)(uintptr_t)off,values[b]);\n"
                                 : "(x+off,values[b]);\n");
            if (Segmented)
              Checks +=
                  "if(syscall(SYS_arch_prctl,ARCH_SET_GS,y))return 202;\n";
            Checks += "uint64_t actual=" + Name + "(ADDRESS_" +
                      std::to_string(Index) +
                      (Segmented ? "(off)" : "(y+off)") +
                      (Immediate ? ");\n" : ",values[b]);\n");
            if (Segmented)
              Checks += "if(syscall(SYS_arch_prctl,ARCH_SET_GS,saved_gs))"
                        "return 203;\n";
            Checks += "if(actual!=expected || memcmp(x,y,sizeof(x)))return " +
                      std::to_string(Index + 1) + ";}\n";
          }
  Text.Size = Text.FileSz = Text.Data.size();
  Image.Segments.push_back(std::move(Text));
  for (bool High : {true, false})
    for (bool NoOpt : {false, true}) {
      llvm::LLVMContext Context;
      PipelineOptions Options;
      Options.LiftMode = !High;
      Options.SourceProjection = !High;
      Options.NoOpt = NoOpt;
      Options.EmitDumpOutput = false;
      Options.OnlyFunctionEntries.insert(Entries.begin(), Entries.end());
      auto Result = Pipeline().run(Image, Context, Options);
      ASSERT_TRUE(Result.Success) << Result.Error;
      CEmitterOptions Emit;
      Emit.TheArch = Arch::X64;
      Emit.Format = BinaryFormat::ELF;
      Emit.Image = &Image;
      Emit.UseUnalignedPointers = false;
      std::string Source;
      llvm::raw_string_ostream OS(Source);
      ASSERT_TRUE(High ? HighCEmitter().emit(Result.HighFuncs, OS, Emit)
                       : LLVMCEmitter().emit(*Result.LlvmModule, OS, Emit,
                                             nullptr, &Image));
      ASSERT_EQ(Source.find("unknown value"), std::string::npos) << Source;
      // Adapt only the test caller's address spelling to the recovered
      // source signature. The machine pointer/offset bits stay unchanged.
      for (unsigned I = 0; I < Entries.size(); ++I) {
        bool Pointer = false;
        if (High) {
          const auto F = std::find_if(
              Result.HighFuncs.begin(), Result.HighFuncs.end(),
              [&](const HighFunc &F) { return F.Entry == Entries[I]; });
          ASSERT_NE(F, Result.HighFuncs.end());
          ASSERT_FALSE(F->Params.empty());
          Pointer =
              F->Params[0].Type && F->Params[0].Type->Kind == NdTypeKind::Ptr;
        } else {
          const auto *F =
              Result.LlvmModule->getFunction("logic_" + std::to_string(I));
          ASSERT_NE(F, nullptr);
          ASSERT_FALSE(F->arg_empty());
          Pointer = F->getArg(0)->getType()->isPointerTy();
        }
        Source += "#define ADDRESS_" + std::to_string(I) + "(x) (" +
                  (Pointer ? "(void *)" : "") + "(uintptr_t)(x))\n";
      }
      Source += Oracles + R"C(
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/prctl.h>
int main(void) {
  uintptr_t saved_gs;
  if(syscall(SYS_arch_prctl,ARCH_GET_GS,&saved_gs))return 200;
  const uint64_t values[]={0,1,0x80,0x8000,0x80000000ULL,
                          0x8000000000000000ULL,0x123456789abcdef0ULL,UINT64_MAX};
)C" + Checks + "return 0;}\n";
      const auto Input = file("locked-logic.c");
      write(Input, Source);
      retain(High ? "locked-high.c" : "locked-llvm.c", Source);
      for (const auto *Opt : {"-O0", "-O2"}) {
        const auto Executable = file(std::string("locked-logic") + Opt);
        const auto Built =
            command(Compiler, {"-std=gnu23", "-fno-strict-aliasing", "-fno-pie",
                               "-no-pie", "-fsanitize=address,undefined", Opt,
                               Input, "-o", Executable});
        ASSERT_EQ(Built.Status, 0) << Built.Error << Source;
        const auto Actual = command(Executable, {});
        ASSERT_EQ(Actual.Status, 0) << Actual.Error << Source;
      }
      ++ProbeNumber;
    }
}

TEST(X86LockedLogic, ContractRequiresOneSequentialTransaction) {
  for (auto Id : {Intrinsic::X86LockedAnd, Intrinsic::X86LockedOr,
                  Intrinsic::X86LockedXor})
    for (uint16_t Width : {1, 2, 4, 8}) {
      X86SystemStateShape S;
      S.TargetArch = Arch::X64;
      S.ValidId = S.WritableOutput = true;
      S.OutputSize = 4;
      S.Arguments = 2;
      S.InputSizes = {8, Width};
      S.ScalarInputs = {true, true};
      S.MemoryOrdering = NdMemoryOrdering::SequentiallyConsistent;
      EXPECT_TRUE(x86SystemStateShapeIsValid(Id, S));
      S.MemoryOrdering = NdMemoryOrdering::None;
      EXPECT_FALSE(x86SystemStateShapeIsValid(Id, S));
      S.MemoryOrdering = NdMemoryOrdering::Relaxed;
      EXPECT_FALSE(x86SystemStateShapeIsValid(Id, S));
      S.MemoryOrdering = NdMemoryOrdering::SequentiallyConsistent;
      S.OutputSize = 8;
      EXPECT_FALSE(x86SystemStateShapeIsValid(Id, S));
    }
}
} // namespace
