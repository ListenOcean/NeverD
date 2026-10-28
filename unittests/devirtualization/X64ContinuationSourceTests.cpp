//===- X64ContinuationSourceTests.cpp - Physical state and reentry --------===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
/// \file
/// Execute continuation source against independent state and memory oracles.
//===----------------------------------------------------------------------===//

#include "../lift/NeverDLiftFixture.h"

#include "neverd/analysis/arch/x86_64/X64ContinuationSource.h"
#include "neverd/backend/c/HighC/HighCEmitter.h"
#include "neverd/backend/c/LLVMC/LLVMCEmitter.h"
#include "neverd/backend/llvm/MedLLVMEmitter.h"
#include "neverd/ir/high/MedToHigh.h"
#include "neverd/ir/med/LowToMed.h"
#include "neverd/ir/med/MedIR.h"
#include "neverd/ir/med/MedTypePass.h"
#include "neverd/loader/BinaryImage.h"

#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace neverd;
using namespace neverd::analysis;

BinaryImage image(std::vector<uint8_t> Bytes) {
  BinaryImage Image;
  Image.Arch = Arch::X64;
  Image.Bits = Bitness::Bits64;
  Image.Format = BinaryFormat::ELF;
  Image.Base = Image.Entry = 0x1000;
  Segment S;
  S.Name = ".text";
  S.VA = Image.Entry;
  S.Size = S.FileSz = Bytes.size();
  S.Flags = SegmentFlags::Readable | SegmentFlags::Executable;
  S.Data = std::move(Bytes);
  Image.Segments.push_back(std::move(S));
  return Image;
}

X64ContinuationSourceOptions options() {
  X64ContinuationSourceOptions O;
  O.Profile = X64ContinuationProfile::KernelNoFaultV1;
  return O;
}

constexpr char StateDeclaration[] = R"C(
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
typedef struct __attribute__((aligned(16))) {
  uint64_t gpr[16], flags, pc, fs, gs;
  unsigned char zmm[32][64];
  uint64_t arbitrary[8];
} state_t;
_Static_assert(sizeof(state_t) == 2272, "continuation v1 layout");
#define ARG(s) ((uint8_t *)(s))
#define CHECK(c) do { if (!(c)) abort(); } while (0)
static state_t seed(uint64_t pc) {
  state_t s = {0};
  for (unsigned i=0; i<16; ++i) s.gpr[i] = 0x1234567800000000ULL+i*71;
  for (unsigned i=0; i<sizeof(s.zmm); ++i) ((unsigned char *)s.zmm)[i] = i*13+7;
  s.flags=0x246; s.pc=pc;
  return s;
}
typedef struct __attribute__((aligned(16))) {
  state_t core;
  uint64_t cr8, kernel_gs;
  uint32_t mxcsr, reserved;
  uint64_t reserved_tail;
} state_v2_t;
_Static_assert(sizeof(state_v2_t) == 2304, "continuation v2 layout");
static state_v2_t seed_v2(uint64_t pc) {
  state_v2_t s={0}; s.core=seed(pc); s.cr8=3; s.mxcsr=0x1f80;
  return s;
}
typedef struct __attribute__((aligned(16))) {
  state_v2_t core;
  uint64_t cr2, reserved;
} state_v4_t;
_Static_assert(sizeof(state_v4_t) == 2320, "continuation v4 layout");
)C";

class X64ContinuationSourceTest : public NeverDLiftTest {
protected:
  void run(std::vector<uint8_t> Bytes, std::vector<va_t> Entries,
           llvm::StringRef Harness, bool NativeBoundary = false,
           X64ContinuationSourceOptions Options = options(),
           llvm::StringRef RequiredSpelling = {}) {
    auto Image = image(std::move(Bytes));
    auto Units = buildX64ContinuationSource(Image, Entries, Options);
    ASSERT_TRUE(bool(Units)) << llvm::toString(Units.takeError());
    ASSERT_EQ(Units->size(), Entries.size());
    for (const auto &Unit : *Units) {
      EXPECT_EQ(Unit.RequiresNativeExecution, NativeBoundary)
          << Unit.Address << " " << Unit.Diagnostic;
      const bool V2 =
          Options.Profile == X64ContinuationProfile::KernelControlsNoFaultV2 ||
          Options.Profile == X64ContinuationProfile::KernelSmapNoFaultV3 ||
          Options.Profile ==
              X64ContinuationProfile::KernelFaultAddressNoFaultV4;
      const bool V3 =
          Options.Profile == X64ContinuationProfile::KernelSmapNoFaultV3;
      const bool V4 = Options.Profile ==
                      X64ContinuationProfile::KernelFaultAddressNoFaultV4;
      EXPECT_EQ(Unit.StateVersion, V4 ? 4u : V3 ? 3u : V2 ? 2u : 1u);
      EXPECT_EQ(Unit.StateBytes, V4   ? sizeof(X64ContinuationStateV4)
                                 : V2 ? sizeof(X64ContinuationStateV2)
                                      : sizeof(X64ContinuationStateV1));
    }
    for (bool LLVM : {false, true}) {
      SCOPED_TRACE(LLVM ? "LLVMC" : "HighC");
      std::vector<MedFunc> Meds;
      for (const auto &Unit : *Units) {
        LowToMedConverter Convert;
        const std::map<va_t, SourceFunctionTypeHint> Hints{
            {Unit.Function.Entry, Unit.SourceABI}};
        Convert.setSourceCallHintsEnabled(true);
        Convert.setSourceEntryTypeHints(&Hints);
        auto Med = Convert.convert(Unit.Function, Arch::X64);
        Med.SourceTypeHint = Unit.SourceABI;
        inferMedTypes(Med, Arch::X64);
        ASSERT_TRUE(verifyMedFunc(Med, "continuation-test"));
        EXPECT_EQ(Med.Params.size(), 1u);
        EXPECT_EQ(Med.FrameSize, 0);
        Meds.push_back(std::move(Med));
      }
      std::string Source;
      llvm::raw_string_ostream OS(Source);
      CEmitterOptions O;
      O.TheArch = Arch::X64;
      O.Format = BinaryFormat::ELF;
      O.UseUnalignedPointers = false;
      if (LLVM) {
        llvm::LLVMContext Context;
        auto Module = MedLLVMEmitter().emit(Meds, Context);
        ASSERT_NE(Module, nullptr);
        ASSERT_FALSE(llvm::verifyModule(*Module, &llvm::errs()));
        ASSERT_TRUE(LLVMCEmitter().emit(*Module, OS, O));
      } else {
        std::vector<HighFunc> High;
        for (const auto &Med : Meds)
          High.push_back(MedToHighConverter().convert(Med, Arch::X64));
        ASSERT_TRUE(HighCEmitter().emit(High, OS, O));
      }
      OS.flush();
      if (!RequiredSpelling.empty())
        EXPECT_NE(Source.find(RequiredSpelling.str()), std::string::npos);
      ASSERT_EQ(Source.find("unknown register"), std::string::npos) << Source;
      const auto File =
          tmpFile(LLVM ? "continuation-llvm.c" : "continuation-high.c");
      std::ofstream(File) << StateDeclaration << Source << Harness.str();
      for (const char *Optimization : {"-O0", "-O2"}) {
        SCOPED_TRACE(Optimization);
        const auto Program =
            tmpFile(std::string("continuation") + Optimization +
                    neverd::test::executableSuffix());
        const auto Built =
            exec(NEVERD_TEST_CLANG,
                 {"-std=c11", Optimization, "-Werror=uninitialized",
                  "-Werror=return-type", "-fsanitize=undefined,address",
                  File.string(), "-o", Program.string()});
        ASSERT_TRUE(Built.ok()) << Built.err << '\n' << Source;
        const auto Ran = exec(Program.string(), {});
        ASSERT_TRUE(Ran.ok()) << Ran.err << " exit " << Ran.exitCode << '\n'
                              << Source;
      }
    }
  }
};

X64ContinuationSourceOptions controlsOptions(uint32_t Mask = 0xffbf) {
  auto O = options();
  O.Profile = X64ContinuationProfile::KernelControlsNoFaultV2;
  O.MXCSRMask = Mask;
  return O;
}

X64ContinuationSourceOptions smapOptions() {
  auto O = controlsOptions();
  O.Profile = X64ContinuationProfile::KernelSmapNoFaultV3;
  return O;
}

TEST_F(X64ContinuationSourceTest, FaultAddressReadWriteKeepsEveryOtherBank) {
  auto O = smapOptions();
  O.Profile = X64ContinuationProfile::KernelFaultAddressNoFaultV4;
  std::vector<uint8_t> Bytes;
  std::vector<va_t> Entries;
  std::string Calls, PCs;
  for (unsigned Register = 0; Register != 16; ++Register)
    for (bool Write : {false, true}) {
      const va_t PC = 0x1000 + Bytes.size();
      Entries.push_back(PC);
      if (!Calls.empty()) {
        Calls += ",";
        PCs += ",";
      }
      Calls += "neverd_step_v4_" + llvm::utohexstr(PC);
      PCs += "0x" + llvm::utohexstr(PC);
      if (Register >= 8)
        Bytes.push_back(0x41);
      Bytes.insert(Bytes.end(), {0x0f, uint8_t(Write ? 0x22 : 0x20),
                                 uint8_t(0xd0 | (Register & 7))});
    }
  run(Bytes, Entries,
      "static __typeof__(&neverd_step_v4_1000) steps[]={" + Calls +
          "};\nstatic const uint64_t pcs[]={" + PCs + "};\n" + R"C(
int main(void) {
  const uint64_t values[]={0,1,UINT64_MAX,0xffff800012345678ULL,
                          0x0123456789abcdefULL};
  const unsigned bits[]={11,7,6,4,2,0};
  for(unsigned n=0;n<32;++n) for(unsigned v=0;v<5;++v)
  for(unsigned flags=0;flags<64;++flags) {
    state_v4_t s={0}; s.core=seed_v2(pcs[n]);
    s.cr2=values[v]; s.reserved=0x1234567812345678ULL;
    s.core.core.flags=0x40202;
    s.core.core.gpr[n/2]=values[4-v];
    for(unsigned i=0;i<6;++i) s.core.core.arbitrary[i]=(flags>>i)&1;
    state_v4_t expected=s;
    if(n&1) expected.cr2=s.core.core.gpr[n/2];
    else expected.core.core.gpr[n/2]=s.cr2;
    expected.core.core.pc+=n>=16?4:3;
    for(unsigned i=0;i<6;++i)
      expected.core.core.flags|=((uint64_t)((flags>>i)&1))<<bits[i];
    CHECK(steps[n](ARG(&s))==0 && memcmp(&s,&expected,sizeof(s))==0);
    /* Wrong-PC invocations are atomic refusals, even for writes. */
    s.core.core.pc=0; expected=s;
    CHECK(steps[n](ARG(&s))==5 && memcmp(&s,&expected,sizeof(s))==0);
  }
  return 0;
})C",
      false, O);
}

TEST_F(X64ContinuationSourceTest,
       EarlierProfilesNeverAcquireFaultAddressState) {
  for (auto O : {options(), controlsOptions(), smapOptions()}) {
    auto Units = buildX64ContinuationSource(
        image({0x0f, 0x20, 0xd0, 0x0f, 0x22, 0xd0}), {0x1000, 0x1003}, O);
    ASSERT_TRUE(bool(Units)) << llvm::toString(Units.takeError());
    for (const auto &Unit : *Units)
      EXPECT_TRUE(Unit.RequiresNativeExecution);
  }
}

TEST_F(X64ContinuationSourceTest, NativeTimestampsKeepAllResultsAndOtherState) {
#if !defined(__x86_64__) && !defined(_M_X64)
  GTEST_SKIP() << "native timestamp execution requires an x64 host";
#else
  auto O = smapOptions();
  O.NativeTimestampReads = true;
  run({0x0f, 0x31, 0x0f, 0x01, 0xf9}, {0x1000, 0x1002}, R"C(
#include <cpuid.h>
#if defined(__linux__)
#include <sched.h>
#endif
static uint64_t clock_sample(unsigned *aux) {
  unsigned lo,hi;
  __asm__ volatile("rdtscp; lfence" : "=a"(lo), "=d"(hi), "=c"(*aux) : : "memory");
  return ((uint64_t)hi<<32)|lo;
}
int main(void) {
  unsigned a,b,c,d;
  CHECK(__get_cpuid(0x80000001,&a,&b,&c,&d) && (d&(1u<<27)));
#if defined(__linux__)
  cpu_set_t available, selected;
  CHECK(sched_getaffinity(0,sizeof(available),&available)==0);
  CPU_ZERO(&selected);
  for(unsigned cpu=0;cpu<CPU_SETSIZE;++cpu)
    if(CPU_ISSET(cpu,&available)) {CPU_SET(cpu,&selected); break;}
  CHECK(sched_setaffinity(0,sizeof(selected),&selected)==0);
#endif
  for(unsigned kind=0;kind<2;++kind) for(unsigned n=0;n<128;++n) {
    state_v2_t s=seed_v2(kind?0x1002:0x1000), expected=s;
    unsigned before_aux,after_aux;
    uint64_t before=clock_sample(&before_aux);
    CHECK((kind?neverd_step_v3_1002(ARG(&s)):neverd_step_v3_1000(ARG(&s)))==0);
    uint64_t after=clock_sample(&after_aux);
    CHECK(!(s.core.gpr[0]>>32) && !(s.core.gpr[2]>>32));
    uint64_t value=(s.core.gpr[2]<<32)|s.core.gpr[0];
    CHECK(value>=before && value<=after);
    expected.core.gpr[0]=s.core.gpr[0]; expected.core.gpr[2]=s.core.gpr[2];
    expected.core.pc=kind?0x1005:0x1002;
    if(kind) {
      CHECK(!(s.core.gpr[1]>>32));
      CHECK(before_aux==after_aux && s.core.gpr[1]==before_aux);
      expected.core.gpr[1]=before_aux;
    }
    CHECK(memcmp(&s,&expected,sizeof(s))==0);
  }
  return 0;
})C",
      false, O);
#endif
}

TEST_F(X64ContinuationSourceTest, TimestampEnvironmentRequiresExplicitOptIn) {
  for (auto O : {options(), controlsOptions(), smapOptions()}) {
    auto Units = buildX64ContinuationSource(
        image({0x0f, 0x31, 0x0f, 0x01, 0xf9}), {0x1000, 0x1002}, O);
    ASSERT_TRUE(bool(Units)) << llvm::toString(Units.takeError());
    for (const auto &Unit : *Units)
      EXPECT_TRUE(Unit.RequiresNativeExecution);
  }
  auto O = options();
  O.NativeTimestampReads = true;
  auto Units = buildX64ContinuationSource(image({0x0f, 0x31}), {0x1000}, O);
  ASSERT_FALSE(bool(Units));
  llvm::consumeError(Units.takeError());
}

TEST_F(X64ContinuationSourceTest, WritePrefetchKeepsNativeHintAndLiveSegments) {
  auto O = smapOptions();
  O.NativeWritePrefetch = true;
  run({0x0f, 0x0d, 0x8f, 0x90, 0,    0,    0,    0x64, 0x0f, 0x0d, 0x8f,
       0x90, 0,    0,    0,    0x65, 0x0f, 0x0d, 0x8f, 0x90, 0,    0,
       0,    0x65, 0x67, 0x0f, 0x0d, 0x8f, 0x90, 0,    0,    0},
      {0x1000, 0x1007, 0x100f, 0x1017}, R"C(
int main(void) {
  unsigned char memory[512], expected_memory[512];
  memset(memory,0x5a,sizeof(memory)); memcpy(expected_memory,memory,sizeof(memory));
  const uint64_t pcs[]={0x1000,0x1007,0x100f,0x1017};
  __typeof__(&neverd_step_v3_1000) steps[]={neverd_step_v3_1000,
      neverd_step_v3_1007,neverd_step_v3_100F,neverd_step_v3_1017};
  for(unsigned n=0;n<4;++n) {
    state_v2_t s=seed_v2(pcs[n]);
    s.core.gpr[7]=n?0x100:(uintptr_t)memory;
    s.core.fs=s.core.gs=(uintptr_t)memory-0x100;
    if(n==3) s.core.gpr[7]|=0x1234567800000000ULL;
    state_v2_t expected=s; expected.core.pc+=n==0?7:n==3?9:8;
    CHECK(steps[n](ARG(&s))==0 && memcmp(&s,&expected,sizeof(s))==0);
    CHECK(memcmp(memory,expected_memory,sizeof(memory))==0);
  }
  return 0;
})C",
      false, O, "__asm__ volatile(\"prefetchw");
  auto Refused = buildX64ContinuationSource(image({0x0f, 0x0d, 0x0f}), {0x1000},
                                            smapOptions());
  ASSERT_TRUE(bool(Refused)) << llvm::toString(Refused.takeError());
  EXPECT_TRUE(Refused->front().RequiresNativeExecution);
}

TEST_F(X64ContinuationSourceTest, LockedUnaryPreservesCarryAndUnalignedMemory) {
  std::vector<uint8_t> Bytes;
  std::vector<va_t> Entries;
  std::string Calls, PCs;
  for (unsigned Width : {1u, 2u, 4u, 8u})
    for (bool Decrement : {false, true}) {
      const va_t PC = 0x1000 + Bytes.size();
      Entries.push_back(PC);
      if (!Calls.empty()) {
        Calls += ",";
        PCs += ",";
      }
      Calls += "neverd_step_v3_" + llvm::utohexstr(PC);
      PCs += "0x" + llvm::utohexstr(PC);
      Bytes.push_back(0xf0);
      if (Width == 2)
        Bytes.push_back(0x66);
      if (Width == 8)
        Bytes.push_back(0x48);
      Bytes.push_back(Width == 1 ? 0xfe : 0xff);
      Bytes.push_back(Decrement ? 0x0f : 0x07); // [rdi]
    }
  const auto Harness = "static __typeof__(&neverd_step_v3_1000) steps[]={" +
                       Calls + "};\n" + "static const uint64_t pcs[]={" + PCs +
                       "};\n" +
                       R"C(
int main(void) {
  const unsigned widths[]={1,1,2,2,4,4,8,8};
  const uint64_t samples[]={0,1,15,16,127,128,255,256,
                           0x7fffffff,0x80000000,UINT64_MAX,
                           0x7fffffffffffffffULL,0x8000000000000000ULL};
  for (unsigned n=0;n<8;++n) for(unsigned carry=0;carry<2;++carry)
  for(unsigned i=0;i<sizeof(samples)/sizeof(samples[0]);++i)
  for(unsigned offset=8;offset<16;++offset) {
    _Alignas(64) unsigned char memory[64], wanted[64];
    memset(memory,0x5a,sizeof(memory));
    unsigned width=widths[n], bits=width*8;
    uint64_t mask=UINT64_MAX>>(64-bits), old=samples[i]&mask;
    memcpy(memory+offset,&old,width);
    memcpy(wanted,memory,sizeof(memory));
    uint64_t value=(n&1 ? old-1 : old+1)&mask;
    memcpy(wanted+offset,&value,width);
    state_v2_t s=seed_v2(pcs[n]), expected;
    s.core.flags=0x40202|carry;
    s.core.gpr[7]=(uintptr_t)(memory+offset);
    expected=s;
    unsigned parity=0;
    for(unsigned b=0;b<8;++b) parity^=(value>>b)&1;
    uint64_t overflow=(n&1) ? old==(UINT64_C(1)<<(bits-1))
                           : old==((UINT64_C(1)<<(bits-1))-1);
    expected.core.flags=(s.core.flags&~UINT64_C(0x8d4)) |
        ((uint64_t)!parity<<2) | (((old^1^value)&16)!=0 ? 16 : 0) |
        ((uint64_t)(value==0)<<6) | (((value>>(bits-1))&1)<<7) |
        (overflow<<11);
    expected.core.pc+=width==2||width==8 ? 4 : 3;
    CHECK(steps[n](ARG(&s))==0);
    CHECK(memcmp(&s,&expected,sizeof(s))==0);
    CHECK(memcmp(memory,wanted,sizeof(memory))==0);
  }
  return 0;
}
)C";
  run(Bytes, Entries, Harness, false, smapOptions(), "lock xadd");
}

TEST_F(X64ContinuationSourceTest, AccessCheckIsGuestStateAcrossFlagSnapshots) {
  run({0x0f, 0x01, 0xcb, 0x9c, 0x58, 0xfa, 0xfb, 0x0f, 0x01, 0xca, 0x90},
      {0x1000, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007, 0x100a}, R"C(
int main(void) {
  const unsigned bits[]={0,2,4,6,7,9,10,11,14,18,21};
  for(unsigned pattern=0;pattern<2048;++pattern) {
    uint64_t stack[2]={0x1234,0x5678};
    state_v2_t s=seed_v2(0x1000);
    s.core.flags=2;
    for(unsigned i=0;i<11;++i)s.core.flags|=((pattern>>i)&1ULL)<<bits[i];
    s.core.gpr[4]=(uintptr_t)&stack[1];
    state_v2_t expected=s;
    CHECK(neverd_step_v3_1000(ARG(&s))==0);
    expected.core.flags|=1ULL<<18; expected.core.pc=0x1003;
    CHECK(memcmp(&s,&expected,sizeof(s))==0);
    CHECK(neverd_step_v3_1003(ARG(&s))==0);
    expected.core.gpr[4]-=8; expected.core.pc=0x1004;
    CHECK(stack[0]==expected.core.flags && stack[1]==0x5678);
    CHECK(memcmp(&s,&expected,sizeof(s))==0);
    CHECK(neverd_step_v3_1004(ARG(&s))==0);
    expected.core.gpr[0]=expected.core.flags;
    expected.core.gpr[4]+=8; expected.core.pc=0x1005;
    CHECK(memcmp(&s,&expected,sizeof(s))==0);
    CHECK(neverd_step_v3_1005(ARG(&s))==0);
    expected.core.flags&=~(1ULL<<9); expected.core.pc=0x1006;
    CHECK(memcmp(&s,&expected,sizeof(s))==0);
    CHECK(neverd_step_v3_1006(ARG(&s))==0);
    expected.core.flags|=1ULL<<9; expected.core.pc=0x1007;
    CHECK(memcmp(&s,&expected,sizeof(s))==0);
    CHECK(neverd_step_v3_1007(ARG(&s))==0);
    expected.core.flags&=~(1ULL<<18); expected.core.pc=0x100a;
    CHECK(memcmp(&s,&expected,sizeof(s))==0);
    CHECK(neverd_step_v3_100A(ARG(&s))==0);
    expected.core.pc=0x100b;
    CHECK(memcmp(&s,&expected,sizeof(s))==0);
  }
  return 0;
})C",
      false, smapOptions());
}

TEST_F(X64ContinuationSourceTest, AccessCheckDoesNotExtendPreviousDomains) {
  for (bool V2 : {false, true}) {
    std::string Harness = R"C(
int main(void) {
  state_v2_t s=seed_v2(0x1000), before=s;
  CHECK(STEP1000(ARG(&s))==4 && memcmp(&s,&before,sizeof(s))==0);
  s.core.pc=0x1003; before=s;
  CHECK(STEP1003(ARG(&s))==4 && memcmp(&s,&before,sizeof(s))==0);
  s.core.pc=0x1000; s.core.flags|=1ULL<<18; before=s;
  CHECK(STEP1000(ARG(&s))==5 && memcmp(&s,&before,sizeof(s))==0);
  return 0;
})C";
    const std::string Prefix = V2 ? "neverd_step_v2_" : "neverd_step_";
    for (const char *PC : {"1000", "1003"}) {
      const std::string From = std::string("STEP") + PC;
      for (size_t At = Harness.find(From); At != std::string::npos;
           At = Harness.find(From))
        Harness.replace(At, From.size(), Prefix + PC);
    }
    run({0x0f, 0x01, 0xcb, 0x0f, 0x01, 0xca}, {0x1000, 0x1003}, Harness, true,
        V2 ? controlsOptions() : options());
  }
}

TEST_F(X64ContinuationSourceTest, SmapEntryStillRejectsEveryOtherExcludedFlag) {
  run({0x90}, {0x1000}, R"C(
int main(void) {
  const uint64_t allowed=0xcd5ULL|(1ULL<<9)|(1ULL<<14)|(1ULL<<18)|(1ULL<<21)|2;
  for(unsigned bit=0;bit<64;++bit) {
    if(allowed&(1ULL<<bit))continue;
    state_v2_t s=seed_v2(0x1000); s.core.flags|=(1ULL<<18)|(1ULL<<bit);
    state_v2_t before=s;
    CHECK(neverd_step_v3_1000(ARG(&s))==5 && memcmp(&s,&before,sizeof(s))==0);
  }
  state_v2_t s=seed_v2(0x1000); s.core.flags&=~2ULL;
  state_v2_t before=s;
  CHECK(neverd_step_v3_1000(ARG(&s))==5 && memcmp(&s,&before,sizeof(s))==0);
  s=seed_v2(0x1000); s.core.flags|=1ULL<<18; s.cr8=16; before=s;
  CHECK(neverd_step_v3_1000(ARG(&s))==5 && memcmp(&s,&before,sizeof(s))==0);
  s=seed_v2(0x1000); s.core.flags|=1ULL<<18; s.mxcsr=0x10000; before=s;
  CHECK(neverd_step_v3_1000(ARG(&s))==5 && memcmp(&s,&before,sizeof(s))==0);
  return 0;
})C",
      false, smapOptions());
}

TEST_F(X64ContinuationSourceTest, SmapNativeBoundaryRetainsAccessCheckState) {
  run({0x0f, 0x32}, {0x1000}, R"C(
int main(void) {
  state_v2_t s=seed_v2(0x1000);
  s.core.flags|=1ULL<<18;
  s.kernel_gs=0x1122334455667788ULL;
  s.reserved=0x89abcdef; s.reserved_tail=0xfedcba9876543210ULL;
  state_v2_t before=s;
  CHECK(neverd_step_v3_1000(ARG(&s))==4);
  CHECK(memcmp(&s,&before,sizeof(s))==0);
  return 0;
})C",
      true, smapOptions());
}

TEST_F(X64ContinuationSourceTest, SmapStateRetainsLegacyGSAndMemoryControls) {
  run({0x0f, 0x01, 0xf8, 0x65, 0x0f, 0xae, 0x17, 0x0f, 0xae, 0xe8},
      {0x1000, 0x1003, 0x1007}, R"C(
int main(void) {
  uint32_t mxcsr=0x3f80;
  state_v2_t s=seed_v2(0x1000);
  s.core.flags|=1ULL<<18;
  s.core.gs=0x123456; s.kernel_gs=(uintptr_t)&mxcsr; s.core.gpr[7]=0;
  state_v2_t expected=s;
  CHECK(neverd_step_v3_1000(ARG(&s))==0);
  expected.core.gs=(uintptr_t)&mxcsr; expected.kernel_gs=0x123456;
  expected.core.pc=0x1003;
  CHECK(memcmp(&s,&expected,sizeof(s))==0);
  CHECK(neverd_step_v3_1003(ARG(&s))==0);
  expected.mxcsr=mxcsr; expected.core.pc=0x1007;
  CHECK(memcmp(&s,&expected,sizeof(s))==0);
  CHECK(neverd_step_v3_1007(ARG(&s))==0);
  expected.core.pc=0x100a;
  CHECK(memcmp(&s,&expected,sizeof(s))==0);
  return 0;
})C",
      false, smapOptions());
}

TEST_F(X64ContinuationSourceTest,
       UnsignedWideDivisionKeepsAliasedInputsFlagsAndRefusalState) {
  std::vector<uint8_t> Bytes;
  std::vector<va_t> Entries;
  // LLVM opaque pointers print as void*, while HighC retains uint8_t*.
  // Direct calls accept either spelling without incompatible function casts.
  std::string Harness = "static uint64_t step(unsigned reg,uint8_t *s) {\n"
                        "switch(reg) {\n";
  for (unsigned Register = 0; Register != 16; ++Register) {
    Entries.push_back(0x1000 + Bytes.size());
    Harness += "case " + std::to_string(Register) + ": return neverd_step_v2_" +
               llvm::utohexstr(Entries.back()) + "(s);\n";
    Bytes.insert(Bytes.end(), {uint8_t(Register < 8 ? 0x48 : 0x49), 0xf7,
                               uint8_t(0xf0 | (Register & 7))});
  }
  Harness += R"C(default: abort();
}}
/* Bit-at-a-time restoring division, independent of host C division or the
   lifted quotient/remainder expressions. Inputs below satisfy high<divisor. */
static uint64_t quotient(uint64_t low,uint64_t high,uint64_t divisor,uint64_t *rem) {
  uint64_t q=0;
  for(unsigned bit=64;bit--;) {
    const unsigned carry=high>>63;
    high=(high<<1)|((low>>bit)&1);
    if(carry || high>=divisor) { high-=divisor; q|=1ULL<<bit; }
  }
  *rem=high; return q;
}
int main(void) {
  const unsigned flagbits[]={11,7,6,4,2,0};
  const uint64_t divisors[]={0,1,2,3,0x8000000000000000ULL,UINT64_MAX};
  const uint64_t lows[]={0,1,0xfedcba9876543210ULL,UINT64_MAX};
  for(unsigned reg=0;reg<16;++reg)
    for(unsigned d=0;d<sizeof(divisors)/sizeof(*divisors);++d)
      for(unsigned l=0;l<sizeof(lows)/sizeof(*lows);++l)
        for(unsigned edge=0;edge<3;++edge)
          for(unsigned pattern=0;pattern<64;++pattern) {
            state_v2_t s=seed_v2(0x1000+3*reg);
            s.core.gpr[0]=lows[l];
            s.core.gpr[2]=edge==0 ? 0 : divisors[d]-(edge==1);
            s.core.gpr[reg]=divisors[d];
            for(unsigned i=0;i<6;++i)s.core.arbitrary[i]=(pattern>>i)&1;
            state_v2_t expected=s;
            const uint64_t low=s.core.gpr[0],high=s.core.gpr[2],divisor=s.core.gpr[reg];
            const int bad=divisor==0 || high>=divisor;
            const uint64_t status=step(reg,ARG(&s));
            CHECK(status==(bad ? 5 : 0));
            if(!bad) {
              expected.core.gpr[0]=quotient(low,high,divisor,&expected.core.gpr[2]);
              expected.core.pc+=3;
              expected.core.flags&=~0x8d5ULL;
              for(unsigned i=0;i<6;++i)expected.core.flags|=expected.core.arbitrary[i]<<flagbits[i];
            }
            CHECK(memcmp(&s,&expected,sizeof(s))==0);
          }
  return 0;
})C";
  run(std::move(Bytes), std::move(Entries), Harness, false, controlsOptions());
}

TEST_F(X64ContinuationSourceTest, WideDivisionDoesNotExtendTheV1Profile) {
  run({0x48, 0xf7, 0xf1}, {0x1000}, R"C(
int main(void) {
  state_t s=seed(0x1000), before=s;
  CHECK(neverd_step_1000(ARG(&s))==4 && memcmp(&s,&before,sizeof(s))==0);
  return 0;
})C",
      true);
}

TEST_F(X64ContinuationSourceTest, TaskPriorityRetainsInvalidWrites) {
  run({0x44, 0x0f, 0x20, 0xc0, 0x44, 0x0f, 0x22, 0xc1}, {0x1000, 0x1004}, R"C(
int main(void) {
  state_v2_t s=seed_v2(0x1000), before=s;
  CHECK(neverd_step_v2_1000(ARG(&s))==0 && s.core.gpr[0]==3);
  CHECK(s.core.flags==(before.core.flags & ~0x8d5ULL));
  /* Each successful MOV CR8 consumes six independent fresh flag bits. */
  const unsigned bits[]={11,7,6,4,2,0};
  for(unsigned pattern=0;pattern<64;++pattern) {
    s.core.pc=0x1000; s.cr8=pattern%16;
    uint64_t flags=s.core.flags & ~0x8d5ULL;
    for(unsigned i=0;i<6;++i) {
      s.core.arbitrary[i]=(pattern>>i)&1;
      flags|=s.core.arbitrary[i]<<bits[i];
    }
    CHECK(neverd_step_v2_1000(ARG(&s))==0);
    CHECK(s.core.gpr[0]==s.cr8 && s.core.flags==flags);
  }
  s.core.gpr[1]=11;
  CHECK(neverd_step_v2_1004(ARG(&s))==0 && s.cr8==11);
  s.core.pc=0x1004; s.core.gpr[1]=16; before=s;
  CHECK(neverd_step_v2_1004(ARG(&s))==5 && memcmp(&s,&before,sizeof(s))==0);
  s.core.pc=0x1000; s.cr8=16; before=s;
  CHECK(neverd_step_v2_1000(ARG(&s))==5 && memcmp(&s,&before,sizeof(s))==0);
  return 0;
})C",
      false, controlsOptions());
}

TEST_F(X64ContinuationSourceTest, MXCSRUsesGuestBytesAndRejectsReservedBits) {
  run({0x0f, 0xae, 0x17, 0x0f, 0xae, 0x1e, 0x65, 0x0f, 0xae, 0x14, 0x25, 0x80,
       1, 0, 0},
      {0x1000, 0x1003, 0x1006}, R"C(
int main(void) {
  uint32_t input=0x3f80, output=0xdeadbeef;
  state_v2_t s=seed_v2(0x1000);
  s.core.gpr[7]=(uintptr_t)&input; s.core.gpr[6]=(uintptr_t)&output;
  CHECK(neverd_step_v2_1000(ARG(&s))==0 && s.mxcsr==input);
  CHECK(neverd_step_v2_1003(ARG(&s))==0 && output==input);
  input=0x1f80; s.core.gs=(uintptr_t)&input-0x180;
  CHECK(neverd_step_v2_1006(ARG(&s))==0 && s.mxcsr==input);
  for(unsigned i=0;i<2;++i) {
    input=i ? 0x10000 : 0x40;
    s.core.pc=0x1000; state_v2_t before=s;
    CHECK(neverd_step_v2_1000(ARG(&s))==5 && memcmp(&s,&before,sizeof(s))==0);
    CHECK(output==0x3f80);
  }
  s.mxcsr=0x10000; s.core.pc=0x1003; state_v2_t before=s;
  CHECK(neverd_step_v2_1003(ARG(&s))==5 && memcmp(&s,&before,sizeof(s))==0);
  CHECK(output==0x3f80);
  return 0;
})C",
      false, controlsOptions());
}

TEST_F(X64ContinuationSourceTest, MXCSRDAZRequiresItsDeclaredWritableMask) {
  run({0x0f, 0xae, 0x17}, {0x1000}, R"C(
int main(void) {
  uint32_t input=0x1fc0;
  state_v2_t s=seed_v2(0x1000), before=s;
  s.core.gpr[7]=(uintptr_t)&input; before=s;
  CHECK(neverd_step_v2_1000(ARG(&s))==0 && s.mxcsr==input);
  before.mxcsr=input; before.core.pc=0x1003;
  CHECK(memcmp(&s,&before,sizeof(s))==0);
  return 0;
})C",
      false, controlsOptions(0xffff));
}

TEST_F(X64ContinuationSourceTest, LoadFenceRetainsTheHostHardwareBarrier) {
  run({0x0f, 0xae, 0xe8}, {0x1000}, R"C(
int main(void) {
  state_v2_t s=seed_v2(0x1000), before=s;
  CHECK(neverd_step_v2_1000(ARG(&s))==0);
  before.core.pc=0x1003;
  CHECK(memcmp(&s,&before,sizeof(s))==0);
  return 0;
})C",
      false, controlsOptions(), "lfence");
}

TEST_F(X64ContinuationSourceTest, LegacyGSExchangeChangesTheActualMemoryBase) {
  run({0x0f, 0x01, 0xf8, 0x65, 0x48, 0x8b, 0x07}, {0x1000, 0x1003}, R"C(
int main(void) {
  uint64_t old[2]={3,7}, replacement[2]={11,19};
  state_v2_t s=seed_v2(0x1000);
  s.core.gs=(uintptr_t)old; s.kernel_gs=(uintptr_t)replacement;
  s.core.gpr[7]=8; state_v2_t before=s;
  CHECK(neverd_step_v2_1000(ARG(&s))==0);
  CHECK(s.core.gs==(uintptr_t)replacement && s.kernel_gs==(uintptr_t)old);
  CHECK(neverd_step_v2_1003(ARG(&s))==0 && s.core.gpr[0]==19);
  s.core.pc=0x1000;
  CHECK(neverd_step_v2_1000(ARG(&s))==0);
  CHECK(s.core.gs==before.core.gs && s.kernel_gs==before.kernel_gs);
  CHECK(neverd_step_v2_1003(ARG(&s))==0 && s.core.gpr[0]==7);
  before.core.pc=s.core.pc; before.core.gpr[0]=7;
  CHECK(memcmp(&s,&before,sizeof(s))==0);
  return 0;
})C",
      false, controlsOptions());
}

TEST_F(X64ContinuationSourceTest, WholeVectorXorPreservesUpperLanes) {
  run({0x66, 0x0f, 0xef, 0xc1}, {0x1000}, R"C(
int main(void) {
  state_t s=seed(0x1000), before=s;
  CHECK(neverd_step_1000(ARG(&s))==0);
  for(unsigned i=0;i<16;++i) before.zmm[0][i]^=before.zmm[1][i];
  before.pc=0x1004;
  CHECK(memcmp(&s,&before,sizeof(s))==0);
  return 0;
})C");
}

TEST_F(X64ContinuationSourceTest,
       MemoryBitStringsRetainSegmentsAndArbitraryFlags) {
  run({0x66, 0x65, 0x0f, 0xba, 0x34, 0x25, 0x60, 8,    0,    0,
       0x12, 0x0f, 0xba, 0x6b, 0x74, 8,    0x48, 0x0f, 0xa3, 0x0f},
      {0x1000, 0x100b, 0x1010}, R"C(
int main(void) {
  const unsigned bits[]={11,7,4,2};
  for(unsigned pattern=0;pattern<16;++pattern) {
    uint16_t word=0xa55f;
    state_t s=seed(0x1000); s.gs=(uintptr_t)&word-0x860;
    uint64_t flags=(s.flags & ~0x895ULL)|1;
    for(unsigned i=0;i<4;++i) {
      s.arbitrary[i]=(pattern>>i)&1; flags|=s.arbitrary[i]<<bits[i];
    }
    state_t before=s;
    CHECK(neverd_step_1000(ARG(&s))==0 && word==0xa55b);
    before.pc=0x100b; before.flags=flags;
    CHECK(memcmp(&s,&before,sizeof(s))==0);
  }
  uint32_t dword=0;
  state_t s=seed(0x100b); s.gpr[3]=(uintptr_t)&dword-0x74;
  CHECK(neverd_step_100B(ARG(&s))==0 && dword==0x100 && !(s.flags&1));
  uint64_t words[]={0x8000000000000000ULL,1,0x1234};
  const int64_t offsets[]={-1,0,64};
  for(unsigned i=0;i<3;++i) {
    s=seed(0x1010); s.gpr[7]=(uintptr_t)&words[1]; s.gpr[1]=offsets[i];
    CHECK(neverd_step_1010(ARG(&s))==0 && (s.flags&1)==(i<2));
    CHECK(words[0]==0x8000000000000000ULL && words[1]==1 && words[2]==0x1234);
  }
  return 0;
})C");
}

TEST_F(X64ContinuationSourceTest, SelectorAndTailJumpRetainCompleteState) {
  run({0xb8, 0x78, 0, 0, 0, 0x41, 0xff, 0xe3}, {0x1000, 0x1005}, R"C(
int main(void) {
  state_t s=seed(0x1000), before=s;
  CHECK(neverd_step_1000(ARG(&s)) == 0);
  CHECK(s.gpr[0] == 0x78 && s.pc == 0x1005);
  CHECK(neverd_step_1005(ARG(&s)) == 2);
  CHECK(s.pc == before.gpr[11]);
  before.pc=s.pc; before.gpr[0]=0x78;
  CHECK(memcmp(&s,&before,sizeof(s)) == 0);
  return 0;
})C");
}

TEST_F(X64ContinuationSourceTest, MemoryCallLoadsTargetBeforeItsAliasingPush) {
  run({0xff, 0x54, 0x24, 0xf8, 0xc2, 0x10, 0}, {0x1000, 0x1004}, R"C(
int main(void) {
  uint64_t stack[8]={0};
  state_t s=seed(0x1000);
  s.gpr[4]=(uintptr_t)&stack[4]; stack[3]=0x99887766;
  CHECK(neverd_step_1000(ARG(&s)) == 1);
  CHECK(s.pc==0x99887766 && stack[3]==0x1004);
  CHECK(s.gpr[4]==(uintptr_t)&stack[3]);
  /* External code changes both the physical PC cell and a live register. */
  stack[3]=0x55443322; s.gpr[9]=0xdeadbeef; s.pc=0x1004;
  CHECK(neverd_step_1004(ARG(&s)) == 3);
  CHECK(s.pc==0x55443322 && s.gpr[4]==(uintptr_t)&stack[6]);
  CHECK(s.gpr[9]==0xdeadbeef);
  return 0;
})C");
}

TEST_F(X64ContinuationSourceTest, ChangedSavedStackCellControlsReentry) {
  run({0x48, 0x89, 0x54, 0x24, 0x10, 0xe8, 0x76, 0, 0, 0, 0x48, 0x8b, 0x64,
       0x24, 0x10, 0xc3},
      {0x1000, 0x1005, 0x100a, 0x100f}, R"C(
int main(void) {
  uint64_t old[8]={0}, alt[8]={0}, callback[8]={0};
  state_t s=seed(0x1000);
  s.gpr[4]=(uintptr_t)&alt[3]; s.gpr[2]=(uintptr_t)&old[3];
  CHECK(neverd_step_1000(ARG(&s))==0 && alt[5]==(uintptr_t)&old[3]);
  CHECK(neverd_step_1005(ARG(&s))==1 && alt[2]==0x100a);
  /* A callback may alias and overwrite the saved stack cell in the home area. */
  alt[5]=(uintptr_t)&callback[3]; callback[3]=0x778899;
  s.pc=alt[2]; s.gpr[4]+=8;
  CHECK(neverd_step_100A(ARG(&s))==0);
  CHECK(s.gpr[4]==(uintptr_t)&callback[3]);
  CHECK(neverd_step_100F(ARG(&s))==3);
  CHECK(s.pc==0x778899 && s.gpr[4]==(uintptr_t)&callback[4]);
  return 0;
})C");
}

TEST_F(X64ContinuationSourceTest,
       WideCopyUsesPhysicalBytesAndPreservesUpperLanes) {
  run({0x66, 0x0f, 0x6f, 0x04, 0x24, 0x66, 0x0f, 0x7f, 0x01}, {0x1000, 0x1005},
      R"C(
int main(void) {
  unsigned char input[32] __attribute__((aligned(16)));
  unsigned char output[32] __attribute__((aligned(16)));
  for (unsigned i=0;i<32;++i) { input[i]=i*17+5; output[i]=0x9d; }
  state_t s=seed(0x1000), before=s;
  s.gpr[4]=(uintptr_t)input; s.gpr[1]=(uintptr_t)output;
  CHECK(neverd_step_1000(ARG(&s))==0);
  CHECK(memcmp(s.zmm[0],input,16)==0);
  CHECK(memcmp(s.zmm[0]+16,before.zmm[0]+16,48)==0);
  CHECK(neverd_step_1005(ARG(&s))==0);
  CHECK(memcmp(output,input,16)==0);
  for (unsigned i=16;i<32;++i) CHECK(output[i]==0x9d);
  return 0;
})C");
}

TEST_F(X64ContinuationSourceTest, SegmentBaseMayAliasThePhysicalStack) {
  run({0x65, 0x48, 0x8b, 0x07, 0x65, 0x48, 0x89, 0x07}, {0x1000, 0x1004}, R"C(
int main(void) {
  uint64_t stack[4]={7,0x1122334455667788ULL,9,10};
  state_t s=seed(0x1000);
  s.gs=(uintptr_t)stack; s.gpr[7]=8; s.gpr[4]=(uintptr_t)&stack[1];
  CHECK(neverd_step_1000(ARG(&s))==0 && s.gpr[0]==stack[1]);
  s.gpr[0]=0x99aabbccddeeff00ULL;
  CHECK(neverd_step_1004(ARG(&s))==0 && stack[1]==s.gpr[0]);
  CHECK(s.gpr[4]==(uintptr_t)&stack[1] && stack[0]==7 && stack[2]==9);
  return 0;
})C");
}

TEST_F(X64ContinuationSourceTest, FlagsUseGuestStateAndFreshArbitraryBits) {
  run({0x9c, 0xfa, 0xfb, 0x48, 0x85, 0xc0}, {0x1000, 0x1001, 0x1002, 0x1003},
      R"C(
int main(void) {
  uint64_t stack[4]={0};
  state_t s=seed(0x1000);
  s.gpr[4]=(uintptr_t)&stack[3];
  CHECK(neverd_step_1000(ARG(&s))==0 && stack[2]==0x246);
  CHECK(neverd_step_1001(ARG(&s))==0 && s.flags==0x46);
  CHECK(neverd_step_1002(ARG(&s))==0 && s.flags==0x246);
  s.gpr[0]=0; s.arbitrary[0]=1;
  CHECK(neverd_step_1003(ARG(&s))==0);
  CHECK((s.flags & 0xcd5)==0x54); /* ZF/PF defined; AF is caller's witness. */
  s.pc=0x1003; s.arbitrary[0]=0;
  CHECK(neverd_step_1003(ARG(&s))==0 && (s.flags&0x10)==0);
  return 0;
})C");
}

TEST_F(X64ContinuationSourceTest, ConditionalShiftWitnessesKeepZeroCountFlags) {
  run({0x48, 0xd3, 0xe0}, {0x1000}, R"C(
int main(void) {
  const unsigned counts[]={0,1,2,64};
  for(unsigned i=0;i<4;++i) {
    state_t s=seed(0x1000);
    s.gpr[0]=0x8000000000000001ULL; s.gpr[1]=counts[i];
    for(unsigned j=0;j<8;++j) s.arbitrary[j]=1;
    CHECK(neverd_step_1000(ARG(&s))==0 && s.pc==0x1003);
    if(counts[i]==0 || counts[i]==64) {
      CHECK(s.gpr[0]==0x8000000000000001ULL && s.flags==0x246);
    } else if(counts[i]==1) {
      CHECK(s.gpr[0]==2 && s.flags==0xa13);
    } else {
      CHECK(s.gpr[0]==4 && s.flags==0xa12);
    }
  }
  return 0;
})C");
}

TEST_F(X64ContinuationSourceTest, PartialRegistersAndInvalidInput) {
  run({0xb4, 0xaa, 0x66, 0xb8, 0x55, 0x66, 0xb8, 0x78, 0x56, 0x34, 0x12},
      {0x1000, 0x1002, 0x1006}, R"C(
int main(void) {
  state_t s=seed(0x1000);
  CHECK(neverd_step_1000(ARG(&s))==0 && s.gpr[0]==0x123456780000aa00ULL);
  CHECK(neverd_step_1002(ARG(&s))==0 && s.gpr[0]==0x1234567800006655ULL);
  CHECK(neverd_step_1006(ARG(&s))==0 && s.gpr[0]==0x12345678);
  state_t before=s;
  CHECK(neverd_step_1000(ARG(&s))==5 && memcmp(&before,&s,sizeof(s))==0);
  s.pc=0x1000; s.flags|=0x100; before=s;
  CHECK(neverd_step_1000(ARG(&s))==5 && memcmp(&before,&s,sizeof(s))==0);
  return 0;
})C");
}

TEST_F(X64ContinuationSourceTest, NativeRequestDoesNotExecuteOrAdvance) {
  run({0x0f, 0x32}, {0x1000}, R"C(
int main(void) {
  state_t s=seed(0x1000), before=s;
  CHECK(neverd_step_1000(ARG(&s))==4);
  CHECK(memcmp(&s,&before,sizeof(s))==0);
  return 0;
})C",
      true);
}

TEST_F(X64ContinuationSourceTest, PrivilegeReturnDoesNotBecomePhysicalNearRet) {
  run({0x48, 0xcf}, {0x1000}, R"C(
int main(void) {
  state_t s=seed(0x1000), before=s;
  /* RSP intentionally points nowhere: IRETQ must not pop a near-RET cell. */
  CHECK(neverd_step_1000(ARG(&s))==4);
  CHECK(memcmp(&s,&before,sizeof(s))==0);
  return 0;
})C",
      true);
}

TEST_F(X64ContinuationSourceTest,
       NativeServiceStubKeepsItsFrameAndServiceNumber) {
  // Exact instruction sequence of the investigated ZwAlpcCancelMessage stub;
  // only its code coordinate is changed to this fixture's immutable mapping.
  run({0x48, 0x8b, 0xc4, 0xfa, 0x48, 0x83, 0xec, 0x10, 0x50, 0x9c,
       0x6a, 0x10, 0x48, 0x8d, 0x05, 0x2d, 0x7a, 0,    0,    0x50,
       0xb8, 0x78, 0,    0,    0,    0xe9, 0xf2, 0x65, 1,    0},
      {0x1000, 0x1003, 0x1004, 0x1008, 0x1009, 0x100a, 0x100c, 0x1013, 0x1014,
       0x1019},
      R"C(
int main(void) {
  uint64_t stack[16]={0};
  state_t s=seed(0x1000); s.gpr[4]=(uintptr_t)&stack[12];
  state_t before=s;
  CHECK(neverd_step_1000(ARG(&s))==0);
  CHECK(neverd_step_1003(ARG(&s))==0);
  CHECK(neverd_step_1004(ARG(&s))==0);
  CHECK(neverd_step_1008(ARG(&s))==0);
  CHECK(neverd_step_1009(ARG(&s))==0);
  CHECK(neverd_step_100A(ARG(&s))==0);
  CHECK(neverd_step_100C(ARG(&s))==0);
  CHECK(neverd_step_1013(ARG(&s))==0);
  CHECK(neverd_step_1014(ARG(&s))==0);
  CHECK(neverd_step_1019(ARG(&s))==2);
  CHECK(s.gpr[0]==0x78 && s.gpr[4]==(uintptr_t)&stack[6]);
  CHECK(s.pc==0x17610 && stack[6]==0x8a40 && stack[7]==0x10);
  CHECK(stack[9]==before.gpr[4]);
  uint64_t sub=before.gpr[4]-16;
  unsigned parity=0; for(unsigned i=0;i<8;++i) parity^=(sub>>i)&1;
  CHECK(stack[8]==(2|((uint64_t)!parity<<2)));
  before.gpr[0]=s.gpr[0]; before.gpr[4]=s.gpr[4];
  before.flags=s.flags; before.pc=s.pc;
  CHECK(memcmp(&s,&before,sizeof(s))==0);
  return 0;
})C");
}

TEST_F(X64ContinuationSourceTest, ConditionalWideReadRetainsEarlierCallBytes) {
  run({0xe8, 0x7b, 0,    0,    0,    0x48, 0x83, 0xec, 0x10, 0xe8, 0x72,
       0,    0,    0,    0xf7, 0x04, 0x24, 1,    0,    0,    0,    0x74,
       9,    0x66, 0x0f, 0x6f, 0x04, 0x24, 0x66, 0x0f, 0x7f, 0x01, 0xc3},
      {0x1000, 0x1005, 0x1009, 0x100e, 0x1015, 0x1017, 0x101c}, R"C(
int main(void) {
  for (unsigned flag=0;flag<2;++flag) for(unsigned full=0;full<2;++full) {
    unsigned char stack[64] __attribute__((aligned(16)));
    unsigned char out[16] __attribute__((aligned(16)));
    memset(stack,0xa5,sizeof(stack)); memset(out,0x7d,sizeof(out));
    state_t s=seed(0x1000); s.gpr[4]=(uintptr_t)(stack+32);
    CHECK(neverd_step_1000(ARG(&s))==1);
    uint64_t return_pc; memcpy(&return_pc,stack+24,8);
    CHECK(return_pc==0x1005);
    s.pc=return_pc; s.gpr[4]+=8;
    CHECK(neverd_step_1005(ARG(&s))==0 && s.gpr[4]==(uintptr_t)(stack+16));
    CHECK(neverd_step_1009(ARG(&s))==1);
    if(full) for(unsigned i=0;i<16;++i) stack[16+i]=i*9+17;
    uint32_t bits=flag; memcpy(stack+16,&bits,4);
    unsigned char expected[16]; memcpy(expected,stack+16,16);
    memcpy(&s.pc,stack+8,8); s.gpr[4]+=8; s.gpr[1]=(uintptr_t)out;
    CHECK(s.pc==0x100e && neverd_step_100E(ARG(&s))==0);
    CHECK(neverd_step_1015(ARG(&s))==2);
    if(flag) {
      CHECK(s.pc==0x1017 && neverd_step_1017(ARG(&s))==0);
      CHECK(neverd_step_101C(ARG(&s))==0 && memcmp(out,expected,16)==0);
      if(!full) { memcpy(&return_pc,out+8,8); CHECK(return_pc==0x1005); }
    } else {
      CHECK(s.pc==0x1020);
      for(unsigned i=0;i<16;++i) CHECK(out[i]==0x7d);
    }
  }
  return 0;
})C");
}

TEST(X64ContinuationSource, RequiresExplicitDomainAndBoundedDistinctAddresses) {
  auto Image = image({0x90, 0xc3});
  auto CheckError = [&](std::vector<va_t> Addresses,
                        X64ContinuationSourceOptions O) {
    auto R = buildX64ContinuationSource(Image, Addresses, O);
    ASSERT_FALSE(bool(R));
    llvm::consumeError(R.takeError());
  };
  CheckError({0x1000}, {});
  CheckError({0x1000, 0x1000}, options());
  CheckError({0x1002}, options());
  auto V2 = controlsOptions();
  V2.MXCSRMask.reset();
  CheckError({0x1000}, V2);
  CheckError({0x1000}, controlsOptions(0x10000));
  auto V1 = options();
  V1.MXCSRMask = 0xffbf;
  CheckError({0x1000}, V1);
  auto O = options();
  O.MaxOperations = 1;
  CheckError({0x1000}, O);
  O = options();
  O.MaxInstructions = 1;
  CheckError({0x1000, 0x1001}, O);
}

} // namespace
