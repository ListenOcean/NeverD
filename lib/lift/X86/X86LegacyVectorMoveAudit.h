//===- X86LegacyVectorMoveAudit.h - Legacy vector move audit ---*- C++ -*-===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
/// \file
/// Undefined-output admission for legacy vector moves and register XOR.
//===----------------------------------------------------------------------===//

#ifndef NEVERD_LIB_LIFT_X86_X86LEGACYVECTORMOVEAUDIT_H
#define NEVERD_LIB_LIFT_X86_X86LEGACYVECTORMOVEAUDIT_H

#include "X86LegacyMemoryAudit.h"

namespace neverd::vectormoveaudit {

// Intel SDM Vol. 2B: packed moves copy all 128 bits. MOVSS/MOVSD copy the low
// scalar, merging register destinations or clearing the remaining XMM bits
// for memory loads. Legacy writes preserve higher vector bits and flags.
// This is only undefined-output coverage, not a preserved-opaque-bank audit.
// Aligned forms retain the lifter-owned guard in the bound operation span.
inline bool form(const cs_insn *Insn, Arch Target) {
  const auto &X = Insn->detail->x86;
  if (X.op_count != 2 || Insn->size > 15)
    return false;
  uint8_t RequiredPrefix = 0, LoadOpcode = 0, StoreOpcode = 0;
  unsigned MemoryBytes = 16;
  switch (Insn->id) {
  case X86_INS_PXOR:
    // Legacy register XOR changes all XMM bits and preserves flags and the
    // upper vector lanes. Memory forms need their own alignment audit.
    if (X.operands[1].type != X86_OP_REG)
      return false;
    RequiredPrefix = 0x66;
    LoadOpcode = StoreOpcode = 0xef;
    break;
  case X86_INS_MOVDQU:
    RequiredPrefix = 0xf3;
    LoadOpcode = 0x6f;
    StoreOpcode = 0x7f;
    break;
  case X86_INS_MOVDQA:
    RequiredPrefix = 0x66;
    LoadOpcode = 0x6f;
    StoreOpcode = 0x7f;
    break;
  case X86_INS_MOVUPS:
    LoadOpcode = 0x10;
    StoreOpcode = 0x11;
    break;
  case X86_INS_MOVUPD:
    RequiredPrefix = 0x66;
    LoadOpcode = 0x10;
    StoreOpcode = 0x11;
    break;
  case X86_INS_MOVAPS:
    LoadOpcode = 0x28;
    StoreOpcode = 0x29;
    break;
  case X86_INS_MOVAPD:
    RequiredPrefix = 0x66;
    LoadOpcode = 0x28;
    StoreOpcode = 0x29;
    break;
  case X86_INS_MOVSS:
    RequiredPrefix = 0xf3;
    MemoryBytes = 4;
    LoadOpcode = 0x10;
    StoreOpcode = 0x11;
    break;
  case X86_INS_MOVSD:
    RequiredPrefix = 0xf2;
    MemoryBytes = 8;
    LoadOpcode = 0x10;
    StoreOpcode = 0x11;
    break;
  default:
    return false;
  }
  const bool Long = Target == Arch::X64;
  size_t Pos = 0;
  uint8_t MandatoryPrefix = 0, AddressPrefix = 0, Rex = 0;
  for (; Pos < Insn->size; ++Pos) {
    const uint8_t B = Insn->bytes[Pos];
    if (RequiredPrefix && B == RequiredPrefix) {
      if (MandatoryPrefix || Rex)
        return false;
      MandatoryPrefix = B;
    } else if (B == 0x67) {
      if (AddressPrefix || Rex)
        return false;
      AddressPrefix = B;
    } else if (Long && B >= 0x40 && B <= 0x4f) {
      if (Rex)
        return false;
      Rex = B;
    } else {
      break;
    }
  }
  if (MandatoryPrefix != RequiredPrefix || Pos + 3 > Insn->size ||
      Insn->bytes[Pos] != 0x0f)
    return false;
  const uint8_t Opcode = Insn->bytes[Pos + 1];
  const uint8_t ModRM = Insn->bytes[Pos + 2];
  const unsigned AddressSize =
      Long ? (AddressPrefix ? 4 : 8) : (AddressPrefix ? 2 : 4);
  // Capstone removes mandatory F2/F3 from its normalized repeat-prefix field;
  // the raw prefix above remains authoritative for the instruction identity.
  if ((Opcode != LoadOpcode && Opcode != StoreOpcode) || X.modrm != ModRM ||
      X.encoding.modrm_offset != Pos + 2 || X.opcode[0] != 0x0f ||
      X.opcode[1] != Opcode || X.opcode[2] || X.opcode[3] || X.rex != Rex ||
      X.prefix[0] || X.prefix[1] ||
      X.prefix[2] != (RequiredPrefix == 0x66 ? 0x66 : 0) ||
      X.prefix[3] != AddressPrefix || X.addr_size != AddressSize ||
      X.encoding.imm_size || X.encoding.imm_offset || X.avx_sae ||
      X.avx_rm != X86_AVX_RM_INVALID || X.avx_cc != X86_AVX_CC_INVALID)
    return false;
  for (unsigned I = 0; I != 2; ++I)
    if (X.operands[I].size !=
            (X.operands[I].type == X86_OP_MEM ? MemoryBytes : 16) ||
        X.operands[I].avx_bcast != X86_AVX_BCAST_INVALID ||
        X.operands[I].avx_zero_opmask)
      return false;
  const auto Register = [&](const cs_x86_op &Operand, unsigned Number) {
    if (Operand.type != X86_OP_REG)
      return false;
    const auto R = mapCapstoneReg(static_cast<x86_reg>(Operand.reg));
    return R.Offset == x86reg::vectorReg(Number) && R.Size == 16;
  };
  const auto &Reg = X.operands[Opcode == LoadOpcode ? 0 : 1];
  const auto &RMOperand = X.operands[Opcode == LoadOpcode ? 1 : 0];
  if (!Register(Reg, ((ModRM >> 3) & 7) + ((Rex & 4) ? 8 : 0)))
    return false;
  if ((ModRM >> 6) == 3)
    return !AddressPrefix && !(Rex & 2) && Pos + 3 == Insn->size &&
           !X.encoding.disp_size && !X.encoding.disp_offset && !X.disp &&
           !X.sib && Register(RMOperand, (ModRM & 7) + ((Rex & 1) ? 8 : 0));
  return legacyaudit::memoryOperand(Insn, RMOperand, MemoryBytes, AddressSize,
                                    Long, Rex, Pos + 3);
}

} // namespace neverd::vectormoveaudit

#endif
