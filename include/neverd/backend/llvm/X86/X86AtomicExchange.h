//===- X86AtomicExchange.h - Native memory XCHG contract ------*- C++ -*-===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
/// \file
/// Native exchange and fetch-add transactions accept unaligned addresses.
//===----------------------------------------------------------------------===//

#ifndef NEVERD_BACKEND_LLVM_X86_X86ATOMICEXCHANGE_H
#define NEVERD_BACKEND_LLVM_X86_X86ATOMICEXCHANGE_H

#include "neverd/Common.h"
#include "neverd/ir/NdOps.h"

#include <optional>
#include <string>
#include <string_view>

namespace neverd {

inline constexpr std::string_view kX86AtomicExchangeAsmMarker =
    "# neverd.x86.exchange ";
inline constexpr std::string_view kX86AtomicFetchAddAsmMarker =
    "# neverd.x86.fetch-add ";

enum class X86AtomicRMWKind { Exchange, FetchAdd };

struct X86AtomicRMWPlan {
  Arch Architecture;
  unsigned Bytes;
  NdMemoryAddressSpace AddressSpace;
  X86AtomicRMWKind Kind = X86AtomicRMWKind::Exchange;

  unsigned addressBytes() const { return Architecture == Arch::X86 ? 4 : 8; }
  std::string mnemonic() const {
    const std::string Base =
        Kind == X86AtomicRMWKind::FetchAdd ? "lock xadd" : "xchg";
    return Base + (Bytes == 1   ? "b"
                   : Bytes == 2 ? "w"
                   : Bytes == 4 ? "l"
                                : "q");
  }
  std::string segment() const {
    return AddressSpace == NdMemoryAddressSpace::X86FS   ? "fs"
           : AddressSpace == NdMemoryAddressSpace::X86GS ? "gs"
                                                         : "";
  }
  std::string constraints() const {
    // The byte output must be an encodable low-byte register. The address
    // and value are both inputs until the exchange completes.
    return std::string(Bytes == 1 ? "=q,r,0,~{memory}" : "=r,r,0,~{memory}") +
           (Kind == X86AtomicRMWKind::FetchAdd ? ",~{cc}" : "");
  }
  std::string assembly() const {
    const auto Prefix = segment().empty() ? "" : "%" + segment() + ":";
    const auto Marker = Kind == X86AtomicRMWKind::FetchAdd
                            ? kX86AtomicFetchAddAsmMarker
                            : kX86AtomicExchangeAsmMarker;
    return std::string(Marker) + std::to_string(Bytes) + " " +
           std::to_string(static_cast<unsigned>(AddressSpace)) + "\n" +
           mnemonic() + " $0, " + Prefix + "($1)";
  }
};

inline std::optional<X86AtomicRMWPlan>
x86AtomicRMWPlan(Arch Architecture, unsigned Bytes,
                 NdMemoryAddressSpace AddressSpace, X86AtomicRMWKind Kind) {
  if ((Architecture != Arch::X86 && Architecture != Arch::X64) ||
      (Bytes != 1 && Bytes != 2 && Bytes != 4 && Bytes != 8) ||
      (Architecture == Arch::X86 && Bytes == 8))
    return std::nullopt;
  switch (AddressSpace) {
  case NdMemoryAddressSpace::Default:
  case NdMemoryAddressSpace::X86FS:
  case NdMemoryAddressSpace::X86GS:
    return X86AtomicRMWPlan{Architecture, Bytes, AddressSpace, Kind};
  }
  return std::nullopt;
}

using X86AtomicExchangePlan = X86AtomicRMWPlan;
inline std::optional<X86AtomicExchangePlan>
x86AtomicExchangePlan(Arch Architecture, unsigned Bytes,
                      NdMemoryAddressSpace AddressSpace) {
  return x86AtomicRMWPlan(Architecture, Bytes, AddressSpace,
                          X86AtomicRMWKind::Exchange);
}

} // namespace neverd

#endif // NEVERD_BACKEND_LLVM_X86_X86ATOMICEXCHANGE_H
