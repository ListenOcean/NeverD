//===- X64ContinuationSource.h - Explicit native continuation C -*- C++ -*-===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
/// \file
/// Versioned instruction-step source interface for physical x64 continuations.
//===----------------------------------------------------------------------===//

#ifndef NEVERD_ANALYSIS_ARCH_X86_64_X64CONTINUATIONSOURCE_H
#define NEVERD_ANALYSIS_ARCH_X86_64_X64CONTINUATIONSOURCE_H

#include "neverd/analysis/Limits.h"
#include "neverd/ir/SourceTypeHint.h"
#include "neverd/ir/low/LowIR.h"
#include "neverd/ir/low/LowUndefinedEffects.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/Error.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace neverd {
struct BinaryImage;
namespace analysis {

/// Instruction-step source interface, separate from ordinary function C and
/// the interpreter recovery ABI. GPRs use the x86 encoding order. Vector
/// containers retain all bytes, including upper lanes untouched by legacy SSE.
/// The environment owns other architectural banks (MSRs, descriptor tables,
/// etc.); a NativeInstruction request must be handled with that environment.
struct alignas(16) X64ContinuationStateV1 {
  uint64_t GPR[16] = {};
  uint64_t RFlags = 2;
  uint64_t PC = 0;
  uint64_t FSBase = 0;
  uint64_t GSBase = 0;
  uint8_t ZMM[32][64] = {};
  /// Fresh, caller-selected architectural arbitrary values for this dynamic
  /// instruction. Each sidecar effect consumes one slot, including conditional
  /// effects. All copies of its produced value share that value. Reusing these
  /// slots selects a subset of permitted executions, not all undefined choices.
  uint64_t Undefined[8] = {};
};

/// A separate layout; V1 callers never provide or acquire these extra banks.
struct alignas(16) X64ContinuationStateV2 {
  X64ContinuationStateV1 Core;
  uint64_t CR8 = 0;
  uint64_t KernelGSBase = 0;
  uint32_t MXCSR = 0;
  uint32_t Reserved = 0;
  uint64_t ReservedTail = 0;
};

/// V3 retains the V2 storage layout. Its separate profile and symbol prefix
/// permit AC in Core.RFlags; invoking a V2 step still rejects that state.
using X64ContinuationStateV3 = X64ContinuationStateV2;

/// V4 owns a separate CR2 cell. Earlier layouts and profiles never read it.
struct alignas(16) X64ContinuationStateV4 {
  X64ContinuationStateV2 Core;
  uint64_t CR2 = 0;
  uint64_t Reserved = 0;
};

enum class X64ContinuationExitV1 : uint64_t {
  Continue = 0,
  Call = 1,
  Jump = 2,
  Return = 3,
  /// Nothing in this instruction has executed. PC still identifies its exact
  /// bytes in the manifest. This is an explicit unsupported execution boundary,
  /// not successful emulation, an ordinary return, or permission to skip it.
  NativeInstruction = 4,
  /// State, a control write, or a division precondition violates the invocation
  /// contract; no state is changed. This rejects an invocation, not an emulated
  /// CPU fault.
  InvalidState = 5,
};

enum class X64ContinuationProfile : uint8_t {
  Unspecified,
  /// CPL=0, IOPL=0, CET disabled, no asynchronous events/privilege transitions,
  /// canonical KernelX64NoFaultV1 flags and successful ordinary RAM accesses.
  /// Execution is sequential, with no concurrent memory writers or MMIO.
  /// Code retains the exact fixed image mapping and is immutable for execution.
  /// In particular, every executed byte must match the returned instruction
  /// manifest. This is an explicit snapshot binding, not a theorem about PE
  /// loader writes or initialized Windows state. Data reads are never folded.
  /// State storage is accessible and disjoint from all guest accesses. FS/GS
  /// bases are arbitrary and may alias each other or the physical guest stack.
  /// The host is little-endian with 64-bit pointers. Faulting executions and
  /// NativeInstruction requests are outside this source execution contract.
  KernelNoFaultV1,
  /// V1's domain plus an x64 host, legacy GS (CR4.FRED=0), explicit CR8/MXCSR
  /// state and no APIC/TPR memory aliases or external changes to these banks.
  /// MXCSRMask declares the effective writable bits. V2 uses StateV2 and a
  /// distinct generated symbol prefix; it is not an extension of V1 storage.
  KernelControlsNoFaultV2,
  /// V2's controls plus CPUID SMAP support and a live AC flag. Accesses must
  /// remain nonfaulting under the actual page permissions and AC value.
  /// STAC/CLAC update guest flags, never host flags. No page-table, SMAP-fault
  /// or privilege-transition model is implied. V1/V2 admission is unchanged.
  KernelSmapNoFaultV3,
  /// V3 plus the explicit fault-address register. Under the nonfaulting,
  /// no-asynchronous-event domain only MOV CR2 changes it. No page-fault,
  /// paging, TLB or CR3 model is implied. Uses StateV4 and a distinct prefix.
  KernelFaultAddressNoFaultV4,
};

struct X64ContinuationSourceOptions {
  X64ContinuationProfile Profile = X64ContinuationProfile::Unspecified;
  std::optional<uint32_t> MXCSRMask;
  /// Opt in to the executing x64 host's TSC and IA32_TSC_AUX, including its
  /// actual timestamp access/ordering behavior. The caller must bind this
  /// native environment to the source run and ensure RDTSC/RDTSCP support and
  /// nonfaulting access. No clock or processor-identity translation is made.
  bool NativeTimestampReads = false;
  /// Retain PREFETCHW on the executing x64 host. The invocation supplies its
  /// feature support and the same cacheable memory environment; the hint is
  /// emitted at the original address, including live FS/GS base addition.
  bool NativeWritePrefetch = false;
  uint64_t MaxInstructions = limits::analysis::kX64ContinuationMaxInstructions;
  uint64_t MaxOperations = limits::analysis::kX64ContinuationMaxOperations;
};

struct X64ContinuationInstructionSource {
  va_t Address = 0;
  std::vector<uint8_t> Bytes;
  unsigned StateVersion = 1;
  uint64_t StateBytes = sizeof(X64ContinuationStateV1);
  /// One complete native instruction, with an explicit state pointer and exit
  /// status. CALL/RET use the original stack and actual next PC. No argument
  /// count, callee preservation, private frame or return-slot proof is assumed.
  LowFunc Function;
  SourceFunctionTypeHint SourceABI;
  /// The arbitrary-value slot order and original instruction-local timing.
  /// Empty for a native request, where no source instruction has executed.
  std::vector<LowUndefinedEffect> UndefinedEffects;
  bool RequiresNativeExecution = false;
  std::string Diagnostic;
};

/// Strictly relift every requested original instruction through the binary
/// provider. Addresses select a region, not proof of whole-function coverage.
/// The caller dispatches on State.PC after each step and may reenter any listed
/// address with fully changed state. Missing addresses remain outside the
/// region. Unsupported decoding/lifting fails; supported instructions outside
/// this version's state lowering remain explicit NativeInstruction requests.
/// Never publish these units as ordinary function C or count requests as
/// reconstructed native semantics. Both C backends consume the same LowIR and
/// explicit SourceABI; emission uses no BinaryImage address rebasing.
/// Emit ordinary memory as byte copies (UseUnalignedPointers=false) or through
/// the C backends' aligned(1), may_alias types, including state accesses.
llvm::Expected<std::vector<X64ContinuationInstructionSource>>
buildX64ContinuationSource(const BinaryImage &Image,
                           llvm::ArrayRef<va_t> Addresses,
                           const X64ContinuationSourceOptions &Options);

} // namespace analysis
} // namespace neverd

#endif // NEVERD_ANALYSIS_ARCH_X86_64_X64CONTINUATIONSOURCE_H
