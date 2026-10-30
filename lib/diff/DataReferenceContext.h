//===- DataReferenceContext.h - Paired uses of unnamed data -----*- C++ -*-===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Candidate function pairs supported by data-reference occurrences in a
/// previously settled correspondence. This does not establish data identity.
///
//===----------------------------------------------------------------------===//

#ifndef NEVERD_LIB_DIFF_DATAREFERENCECONTEXT_H
#define NEVERD_LIB_DIFF_DATAREFERENCECONTEXT_H

#include "neverd/diff/Control.h"

#include "llvm/ADT/ArrayRef.h"

#include <cstdint>
#include <utility>
#include <vector>

namespace neverd::diff {

struct Program;
struct ProgramFeatures;

/// Returns only unique candidates with complete, consistently mapped address
/// roles and equal address-independent layouts. The supplied function maps are
/// frozen for this pass; proposed candidates never support their own evidence.
std::vector<std::pair<uint32_t, uint32_t>>
dataReferenceCandidates(const Program &P, const ProgramFeatures &PF,
                        llvm::ArrayRef<uint32_t> PMatch, const Program &S,
                        const ProgramFeatures &SF,
                        llvm::ArrayRef<uint32_t> SMatch,
                        const ComparisonControl &Control);

} // namespace neverd::diff

#endif // NEVERD_LIB_DIFF_DATAREFERENCECONTEXT_H
