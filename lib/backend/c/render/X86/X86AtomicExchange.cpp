//===- X86AtomicExchange.cpp - Memory XCHG C projection -----------------===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
/// \file
/// Both C routes retain the exchange, including unaligned native accesses.
//===----------------------------------------------------------------------===//

#include "X86AtomicExchange.h"

#include "neverd/backend/llvm/X86/LLVMX86AddressSpaces.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/ModRef.h"

#include <stdexcept>

namespace neverd {

std::string renderX86AtomicRMW(const X86AtomicRMWPlan &Plan,
                               const std::string &Address,
                               const std::string &Value) {
  std::string Temporary = Plan.Kind == X86AtomicRMWKind::Exchange
                              ? "neverd_xchg_value"
                              : "neverd_xadd_value";
  while (Address.find(Temporary) != std::string::npos ||
         Value.find(Temporary) != std::string::npos)
    Temporary += "_";
  const auto Word = "uint" + std::to_string(Plan.Bytes * 8) + "_t";
  const auto Pointer = "uint" + std::to_string(Plan.addressBytes() * 8) + "_t";
  const auto Prefix = Plan.segment().empty() ? "" : "%%" + Plan.segment() + ":";
  return "({ " + Word + " " + Temporary + " = (" + Word + ")(uintptr_t)(" +
         Value + "); __asm__ __volatile__(\"" + Plan.mnemonic() + " %0, " +
         Prefix + "(%1)\" : \"+" + (Plan.Bytes == 1 ? "q" : "r") + "\"(" +
         Temporary + ") : \"r\"((" + Pointer + ")(uintptr_t)(" + Address +
         ")) : \"memory\"" +
         (Plan.Kind == X86AtomicRMWKind::FetchAdd ? ", \"cc\"" : "") + "); " +
         Temporary + "; })";
}

std::optional<X86AtomicRMWPlan>
x86AtomicRMWCallPlan(Arch Architecture, const llvm::CallInst &Call) {
  const auto *Assembly =
      llvm::dyn_cast<llvm::InlineAsm>(Call.getCalledOperand());
  if (!Assembly)
    return std::nullopt;
  const llvm::StringRef Text = Assembly->getAsmString();
  const bool Add = Text.starts_with(kX86AtomicFetchAddAsmMarker);
  if (!Add && !Text.starts_with(kX86AtomicExchangeAsmMarker))
    return std::nullopt;
  const auto Invalid = []() {
    throw std::invalid_argument("invalid owned x86 atomic memory transaction");
  };
  if (!Call.getType()->isIntegerTy() || Call.arg_size() != 2 ||
      !Call.getArgOperand(0)->getType()->isPointerTy() ||
      Call.getArgOperand(1)->getType() != Call.getType())
    Invalid();
  const auto Space = Call.getArgOperand(0)->getType()->getPointerAddressSpace();
  NdMemoryAddressSpace AddressSpace = NdMemoryAddressSpace::Default;
  if (isLLVMX86FSAddressSpace(Space))
    AddressSpace = NdMemoryAddressSpace::X86FS;
  else if (isLLVMX86GSAddressSpace(Space))
    AddressSpace = NdMemoryAddressSpace::X86GS;
  else if (Space)
    Invalid();
  const unsigned Bits = Call.getType()->getIntegerBitWidth();
  const auto Plan = x86AtomicRMWPlan(Architecture, Bits / 8, AddressSpace,
                                     Add ? X86AtomicRMWKind::FetchAdd
                                         : X86AtomicRMWKind::Exchange);
  if (!Plan || Bits != Plan->Bytes * 8 ||
      Assembly->getAsmString() != Plan->assembly() ||
      Assembly->getConstraintString() != Plan->constraints() ||
      !Assembly->hasSideEffects() || Assembly->isAlignStack() ||
      Assembly->canThrow() ||
      Assembly->getDialect() != llvm::InlineAsm::AD_ATT ||
      Call.getFunctionType() != Assembly->getFunctionType() ||
      Call.getFunctionType()->isVarArg() || Call.getNumOperandBundles() ||
      Call.doesNotReturn() || Call.hasFnAttr(llvm::Attribute::NoSync) ||
      Call.getMemoryEffects() != llvm::MemoryEffects::unknown() ||
      Call.getCallingConv() != llvm::CallingConv::C)
    Invalid();
  return Plan;
}

} // namespace neverd
