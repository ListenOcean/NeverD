//===- LLVMX87NativeState.h - Native x87 state contracts ------*- C++ -*-===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
/// \file
/// Own the fixed interfaces for native x87 control, status and reset calls.
//===----------------------------------------------------------------------===//

#ifndef NEVERD_BACKEND_LLVM_X86_LLVMX87NATIVESTATE_H
#define NEVERD_BACKEND_LLVM_X86_LLVMX87NATIVESTATE_H

#include "neverd/ArchSupport.h"
#include "neverd/ir/intrinsics/Intrinsics.h"

#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

#include <stdexcept>

namespace neverd {

enum class X87NativeStateKind {
  ReadControl,
  WriteControl,
  ReadStatus,
  StoreStatus,
  ClearExceptions,
  Initialize,
  Wait
};

struct X87NativeStateSpec {
  X87NativeStateKind Kind;
  const char *LLVMName;
  const char *Builtin;
  const char *Mnemonic;
  bool ReturnsStatus;
  bool HasPointer;
};

inline constexpr X87NativeStateSpec X87NativeStateSpecs[] = {
    {X87NativeStateKind::ReadControl, "llvm.x86.fnstcw",
     "__builtin_ia32_fnstcw", "fnstcw", false, true},
    {X87NativeStateKind::WriteControl, "llvm.x86.fldcw", "__builtin_ia32_fldcw",
     "fldcw", false, true},
    {X87NativeStateKind::ReadStatus, "llvm.x86.fnstsw", "__builtin_ia32_fnstsw",
     "fnstsw", true, false},
    {X87NativeStateKind::StoreStatus, "llvm.x86.fnstsw.mem",
     "__builtin_ia32_fnstsw_mem", "fnstsw", false, true},
    {X87NativeStateKind::ClearExceptions, "llvm.x86.fnclex",
     "__builtin_ia32_fnclex", "fnclex", false, false},
    {X87NativeStateKind::Initialize, "llvm.x86.fninit", "__builtin_ia32_fninit",
     "fninit", false, false},
    {X87NativeStateKind::Wait, "llvm.x86.fwait", "__builtin_ia32_fwait",
     "fwait", false, false}};

inline const X87NativeStateSpec &x87NativeStateSpec(X87NativeStateKind Kind) {
  for (const auto &Spec : X87NativeStateSpecs)
    if (Spec.Kind == Kind)
      return Spec;
  throw std::invalid_argument("invalid native x87 state operation");
}

/// Only these typed operations act on ambient state. X87ReadStatus instead
/// reads the sampled SSA status of an owned operation and must not use FNSTSW.
inline const X87NativeStateSpec *x87NativeStateOfIntrinsic(Intrinsic Id) {
  switch (Id) {
  case Intrinsic::X87Fninit:
    return &x87NativeStateSpec(X87NativeStateKind::Initialize);
  case Intrinsic::X87Fnclex:
    return &x87NativeStateSpec(X87NativeStateKind::ClearExceptions);
  case Intrinsic::X87Wait:
    return &x87NativeStateSpec(X87NativeStateKind::Wait);
  default:
    return nullptr;
  }
}

inline const X87NativeStateSpec *
classifyX87NativeState(const llvm::CallBase &Call, Arch TheArch) {
  // getCalledFunction() hides a named function when the call-site prototype
  // differs. Such a call must still reach this contract's rejection.
  const auto *Callee = llvm::dyn_cast<llvm::Function>(
      Call.getCalledOperand()->stripPointerCastsAndAliases());
  if (!Callee)
    return nullptr;
  const X87NativeStateSpec *Spec = nullptr;
  for (const auto &Candidate : X87NativeStateSpecs)
    if (Callee->getName() == Candidate.LLVMName)
      Spec = &Candidate;
  if (!Spec)
    return nullptr;
  if ((TheArch != Arch::X86 && TheArch != Arch::X64) ||
      !llvm::isa<llvm::CallInst>(Call) || !Callee->isDeclaration() ||
      Call.getCalledOperand() != Callee ||
      Call.getFunctionType() != Callee->getFunctionType() ||
      Call.getCallingConv() != llvm::CallingConv::C ||
      Callee->getCallingConv() != llvm::CallingConv::C ||
      (Spec->ReturnsStatus ? !Call.getType()->isIntegerTy(16)
                           : !Call.getType()->isVoidTy()) ||
      Call.getFunctionType()->isVarArg() ||
      Call.arg_size() != unsigned(Spec->HasPointer) ||
      (Spec->HasPointer &&
       (!Call.getArgOperand(0)->getType()->isPointerTy() ||
        Call.getArgOperand(0)->getType()->getPointerAddressSpace() != 0)))
    throw std::invalid_argument("invalid native x87 state call");
  return Spec;
}

} // namespace neverd

#endif // NEVERD_BACKEND_LLVM_X86_LLVMX87NATIVESTATE_H
