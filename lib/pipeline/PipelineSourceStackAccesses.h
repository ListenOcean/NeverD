//===- PipelineSourceStackAccesses.h - Stack projection --------*- C++ -*-===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Post-conversion stack semantics shared by the initial MedIR conversion and
/// caller reconversion after register-pair return recovery.
///
//===----------------------------------------------------------------------===//

#ifndef NEVERD_LIB_PIPELINE_PIPELINESOURCESTACKACCESSES_H
#define NEVERD_LIB_PIPELINE_PIPELINESOURCESTACKACCESSES_H

#include "neverd/ir/med/MedIntegerReturnRange.h"

namespace neverd {

struct BinaryImage;
struct LowFunc;
struct MedFunc;
struct PipelineOptions;
struct PipelineResult;

enum class MedStackProjection { Machine, Source };

/// Source projections omit proved caller-state saves. Machine analysis and
/// rewriting retain those operations even when source output was also asked
/// for.
MedStackProjection medStackProjection(const PipelineOptions &Options);

/// Recompute entry kind, alignment and source stack annotations on this fresh
/// conversion. Never copy annotation flags from another operation sequence.
void prepareMedStackAccesses(MedFunc &Func, const LowFunc &Source,
                             const BinaryImage &Image,
                             MedStackProjection Projection,
                             const MedCallReturnRanges *CallReturns = nullptr);

/// Read complete local leaf results in parallel after conversion has joined.
/// The returned facts are immutable during the following source checks.
MedCallReturnRanges sourceCallReturnRanges(const BinaryImage &Image,
                                           const PipelineResult &Result);

/// Shared source-only frame observation proof after call ABI recovery.
void prepareRecoveredSourceStackAccesses(const BinaryImage &Image,
                                         PipelineResult &Result);

} // namespace neverd

#endif // NEVERD_LIB_PIPELINE_PIPELINESOURCESTACKACCESSES_H
