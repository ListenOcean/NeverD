//===- X86RegistrationCall.h - Checked source call ABI ----------*- C++ -*-===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//

#ifndef NEVERD_IR_MED_X86_X86REGISTRATIONCALL_H
#define NEVERD_IR_MED_X86_X86REGISTRATIONCALL_H

#include "neverd/ir/med/MedIR.h"

namespace neverd {
struct LowFunc;
struct LowBlock;
struct LowOp;

/// Consume a checked source call's cleanup before forming stack SSA: the one
/// a complete registration proof binds to this call, or else a direct
/// callee's proven return cleanup (RegistrationStateAnalysis::CalleeStacks).
std::optional<uint32_t> registrationCallStackPop(const LowFunc &Func,
                                                 const LowBlock &Block,
                                                 const LowOp &Call);

/// The physical arguments of a checked original PE32 callee. A leaf may
/// borrow ECX; an initializer also consumes checked scalar stack words. A
/// direct rethrow takes two null stack arguments. This describes the callee,
/// not the current values supplied by the caller.
struct RegistrationCallABI {
  bool BorrowsECX = false;
  bool RuntimeThrow = false;
  bool Initializer = false;
  uint32_t ScalarStackWords = 0;
  llvm::ArrayRef<uint64_t> integerArgumentRegisters() const;
};

/// Bind the retained LowIR callee contract to this exact surviving CALL.
/// An incomplete, moved, duplicated or retargeted occurrence has no binding.
std::optional<RegistrationCallABI> registrationCallABI(const MedFunc &Func,
                                                       const MedBlock &Block,
                                                       const MedOp &Call);

} // namespace neverd

#endif // NEVERD_IR_MED_X86_X86REGISTRATIONCALL_H
