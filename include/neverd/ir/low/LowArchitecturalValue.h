//===- LowArchitecturalValue.h - Fresh architectural bits -------*- C++ -*-===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
/// \file Raw-region productions, distinct from LLVM undef and C undefinedness.

#ifndef NEVERD_IR_LOW_LOWARCHITECTURALVALUE_H
#define NEVERD_IR_LOW_LOWARCHITECTURALVALUE_H

#include "neverd/ir/low/LowUndefinedEffects.h"

#include <optional>

namespace neverd {

/// Conservative refusal recognition, including malformed ID aliases.
inline bool isLowArchitecturalValue(const LowOp &Op) {
  return Op.Opcode == NdOp::INTRINSIC &&
         isArchitecturalValueId(Op.Inputs[0].Offset);
}

/// One fresh BitCount-bit production per dynamic occurrence, independent of
/// earlier occurrences. Preserve Old outside the selected bit range; a false
/// Boolean guard preserves Old entirely. Copies share the produced value.
/// The listed production occurs even when its guard is false. This operation
/// has no implicit register write extension, native fault or runtime provider.
/// Its publisher owns the exact architectural sidecar and raw-domain receipt.
inline std::optional<LowOp>
makeLowArchitecturalValue(const LowUndefinedEffect &Effect, va_t Address,
                          int Seq = 0) {
  const auto Scalar = [](const NdVar &V) {
    return (V.isReg() || V.isTemp() || V.isConst()) &&
           (V.Size == 1 || V.Size == 2 || V.Size == 4 || V.Size == 8) &&
           (V.isConst() || V.Offset <= InvalidVA - (V.Size - 1));
  };
  if (!Scalar(Effect.Output) || Effect.Output.isConst() || !Effect.BitCount ||
      Effect.BitOffset >= Effect.Output.Size * 8 ||
      Effect.BitCount > Effect.Output.Size * 8 - Effect.BitOffset ||
      (Effect.When && (!Scalar(*Effect.When) || Effect.When->Size != 1 ||
                       Effect.When->isReg() ||
                       (Effect.When->isConst() && Effect.When->Offset > 1))))
    return std::nullopt;
  const bool Whole =
      Effect.BitOffset == 0 && Effect.BitCount == Effect.Output.Size * 8;
  LowOp Op;
  Op.Opcode = NdOp::INTRINSIC;
  Op.Output = Effect.Output;
  Op.Addr = Address;
  Op.Seq = Seq;
  Op.addInput(NdVar::scalar(uint64_t(Intrinsic::ArchitecturalValueV1), 8));
  Op.addInput(Whole && !Effect.When ? NdVar::scalar(0, Effect.Output.Size)
                                    : Effect.Output);
  Op.addInput(Effect.When.value_or(NdVar::scalar(1, 1)));
  Op.addInput(NdVar::scalar(Effect.BitOffset, 8));
  Op.addInput(NdVar::scalar(Effect.BitCount, 8));
  return Op;
}

} // namespace neverd

#endif // NEVERD_IR_LOW_LOWARCHITECTURALVALUE_H
