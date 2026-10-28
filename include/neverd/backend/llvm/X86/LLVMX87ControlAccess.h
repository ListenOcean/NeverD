//===- LLVMX87ControlAccess.h - Native x87 memory calls -------*- C++ -*-===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
/// \file
/// Validate the fixed pointer interfaces for native x87 control-word access.
//===----------------------------------------------------------------------===//

#ifndef NEVERD_BACKEND_LLVM_X86_LLVMX87CONTROLACCESS_H
#define NEVERD_BACKEND_LLVM_X86_LLVMX87CONTROLACCESS_H

#include "neverd/ArchSupport.h"

#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

#include <optional>
#include <stdexcept>

namespace neverd {

enum class X87ControlAccessKind { Read, Write };

inline std::optional<X87ControlAccessKind>
classifyX87ControlAccess(const llvm::CallBase &Call, Arch TheArch) {
  const auto *Callee = Call.getCalledFunction();
  if (!Callee || (Callee->getName() != "llvm.x86.fnstcw" &&
                  Callee->getName() != "llvm.x86.fldcw"))
    return std::nullopt;
  if ((TheArch != Arch::X86 && TheArch != Arch::X64) ||
      !llvm::isa<llvm::CallInst>(Call) || !Callee->isDeclaration() ||
      Call.getFunctionType() != Callee->getFunctionType() ||
      Call.getCallingConv() != llvm::CallingConv::C ||
      Callee->getCallingConv() != llvm::CallingConv::C ||
      !Call.getType()->isVoidTy() || Call.getFunctionType()->isVarArg() ||
      Call.arg_size() != 1 ||
      !Call.getArgOperand(0)->getType()->isPointerTy() ||
      Call.getArgOperand(0)->getType()->getPointerAddressSpace() != 0)
    throw std::invalid_argument("invalid native x87 control-word call");
  return Callee->getName() == "llvm.x86.fldcw" ? X87ControlAccessKind::Write
                                               : X87ControlAccessKind::Read;
}

} // namespace neverd

#endif // NEVERD_BACKEND_LLVM_X86_LLVMX87CONTROLACCESS_H
