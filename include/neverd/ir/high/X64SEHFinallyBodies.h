//===- X64SEHFinallyBodies.h - __finally termination bodies -----*- C++ -*-===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Windows x64 calls a `__finally` termination handler out of line, with the
/// parent's EstablisherFrame as the second argument and an abnormal-termination
/// flag as the first.  A C `__finally` body runs on both the normal exit and an
/// unwind, so the compiler emits the body twice: the funclet (unwind) and an
/// inline copy on the normal path with the flag folded false.  This projects
/// the funclet's logic into the parent's empty `__finally` clause, keyed by the
/// certified EstablisherFrame, without running it twice.
///
//===----------------------------------------------------------------------===//

#ifndef NEVERD_IR_HIGH_X64SEHFINALLYBODIES_H
#define NEVERD_IR_HIGH_X64SEHFINALLYBODIES_H

#include "neverd/ir/high/HighIR.h"

#include <set>
#include <vector>

namespace neverd {

/// Fill the empty `__finally` clauses of every x64 SEH function in \p Funcs
/// with its termination handler's logic.  The handler reads the parent's
/// locals through `EstablisherFrame + k`; the certified frame bytes
/// (`HighFunc::SEHTerminationFrameBytes`) rebase that onto the parent's entry
/// stack pointer, as a catch funclet's `RDX` is rebased.  The abnormal-
/// termination argument becomes `AbnormalTermination()`.
///
/// A C `__finally` runs on the normal exit too, so the compiler's inline
/// normal-path copy must not run a second time.  When the parent's statements
/// after the `__try` are that copy, they are left in place and the clause
/// holds only the abnormal work under `if (AbnormalTermination())`; when the
/// clause can instead be proved equal to that copy with the flag false, the
/// copy is removed and the clause holds the whole body.  A handler whose frame
/// is not certified, whose body is unavailable, or whose shape is unsupported
/// keeps its address comment.  \p Funcs is the whole translation unit so the
/// termination funclets can be read; only non-funclet parents are filled.
/// Each funclet whose body is attached into a parent is added to \p Merged
/// when given, so a single-function view need not also print it standalone.
void attachSEHFinallyBodies(std::vector<HighFunc> &Funcs, Arch TargetArch,
                            std::set<va_t> *Merged = nullptr);

} // namespace neverd

#endif // NEVERD_IR_HIGH_X64SEHFINALLYBODIES_H
