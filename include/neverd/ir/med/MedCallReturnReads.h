//===- MedCallReturnReads.h - Source call-stack observations ----*- C++ -*-===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Reject observations of physical call writes absent from a source frame.
///
//===----------------------------------------------------------------------===//

#ifndef NEVERD_IR_MED_MEDCALLRETURNREADS_H
#define NEVERD_IR_MED_MEDCALLRETURNREADS_H

#include "neverd/ir/Limits.h"

#include <cstddef>
#include <string>

namespace neverd {
struct BinaryImage;
struct LowFunc;
struct MedFunc;

/// Check exact entry-relative loads against reaching physical x86 CALL
/// return slots before source cleanup. An ordinary C call does not write the
/// reconstructed frame. A later explicit store kills only its own bytes;
/// reading any remaining call-written byte requires a machine-state source
/// contract. This check does not certify unresolved addresses or callee
/// effects. FreshSource, when supplied, must be the exact LowIR input of this
/// fresh conversion, before source cleanup. Its checked registration-state
/// flow can locate restored x86 SEH stacks; this is not a reusable MedIR fact.
bool validateSourceCallReturnReads(
    const MedFunc &Func, const BinaryImage &Image, std::string &Diagnostic,
    size_t WorkLimit = limits::ir::kSourceCallReturnReadWork,
    const LowFunc *FreshSource = nullptr);

/// Retain observed near-CALL return-address writes in the reconstructed frame.
/// Only exact entry-relative slots below entry SP are admitted. Planning is
/// transactional: ambiguous stacks, incomplete graphs and unavailable original
/// encodings leave Func unchanged. This does not prove callee memory effects or
/// authorize a physical stack switch. Invoke before source stack cleanup.
bool preserveSourceCallReturnWrites(
    MedFunc &Func, const BinaryImage &Image, std::string &Diagnostic,
    size_t WorkLimit = limits::ir::kSourceCallReturnReadWork,
    const LowFunc *FreshSource = nullptr);
} // namespace neverd

#endif // NEVERD_IR_MED_MEDCALLRETURNREADS_H
