//===- MedPrologueSaves.h - Callee-save prologue storage -----*- C++ -*-===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
///
/// \file
/// A prologue saves the callee-saved registers its body uses and the
/// epilogue restores them: storage that keeps the caller's registers, which
/// no source statement reads.  A source view leaves those saves out, as every
/// C function leaves its caller's state alone.
///
//===----------------------------------------------------------------------===//

#ifndef NEVERD_IR_MED_MEDPROLOGUESAVES_H
#define NEVERD_IR_MED_MEDPROLOGUESAVES_H

#include "neverd/ir/med/MedIR.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>

namespace neverd {
struct BinaryImage;

/// Whether \p V is the value register \p RegOff holds at \p Func's entry:
/// its version zero, or the entry seed that copies it (`COPY RSI.1 = RSI`).
bool isEntryLiveInValue(const MedFunc &Func, const MedVar &V, uint64_t RegOff);

/// A bounded extent in the function's private frame or incoming ABI home
/// storage. This classifies storage, not its initialization or capture state.
bool isSourcePrivateFrameAccess(const MedFunc &Func, Arch Architecture,
                                BinaryFormat Format, int64_t Offset,
                                uint16_t Bytes);

/// Mark source-mode prologue saves, unobserved scratch spills and
/// return-address reads using one frame access analysis. Complete fixed integer
/// call operands reading private frame bytes proved never written on any
/// incoming path become explicit unavailable values in source only. General
/// partial-byte observations are separate. The analysis is discarded before
/// returning; operation positions stay stable. An optional current image
/// identifies complete data-object reads disjoint from the private source
/// frame; unknown addresses and external stores still stop the spill proof.
void markSourceStackAccesses(MedFunc &Func, Arch Architecture,
                             BinaryFormat Format,
                             StackEntryKind Entry = StackEntryKind::Call,
                             const BinaryImage *Image = nullptr);

/// Positional Win64 register inputs whose only uses are source-proved dead
/// spills and dead identity transports. Every implicit call observation must
/// follow a full overwrite or have a bound unread-register proof. The caller
/// must supply a complete current body with freshly prepared source stores.
/// This does not remove parameter slots or authorize a native ABI rewrite.
std::set<unsigned> unobservedSourceSpillParameters(const MedFunc &Func);

/// Source-only low-prefix demand, by positional Win64 integer parameter.
/// Missing entries retain the whole carrier; zero requires a proved discarded
/// spill or forwarding to another proved unobserved input. Facts are local to
/// one preparation of complete bodies and must never enter native summaries.
using SourceRegisterParameterReads = std::map<unsigned, uint16_t>;
using SourceCalleeParameterReads = std::map<va_t, SourceRegisterParameterReads>;

/// Extend source spill evidence through current direct calls. Identity copies
/// and PHIs retain byte positions; narrow views may read the retained prefix.
/// Opaque implicit readers, changed call bindings and other transports reject
/// a suffix proof. The shared per-function budget also bounds repeated queries.
SourceRegisterParameterReads
sourceRegisterParameterReads(const MedFunc &Func,
                             const SourceCalleeParameterReads &Callees,
                             size_t &Remaining);

/// Choose zero for unobserved argument bytes only when the complete retained
/// prefix is an exact scalar constant. Follow COPY/CONCAT/SUBBYTES/ZEXT views
/// without evaluating an unavailable neighbor or removing producer effects.
/// Parameter positions, widths, native operands and signatures stay intact.
void replaceKnownSourceCallArguments(MedFunc &Func,
                                     const SourceCalleeParameterReads &Callees);

/// After call argument recovery, omit private stores only when a complete
/// noncapturing use proof of the frame finds no reads of their surviving
/// bytes on any path. Explicit partial overwrites kill only their bytes. Direct
/// callees contribute their actual bounded pointer reads, including negative
/// displacements. Unknown callees, escapes and unsupported uses keep stores.
void markUnobservedBorrowedFrameStores(
    MedFunc &Func, Arch Architecture, BinaryFormat Format,
    const std::map<va_t, const MedFunc *> &Callees);

/// In source mode, mark each store that saves a callee-saved register's entry
/// value into prologue storage as a PrologueSave.  Prologue storage is the
/// function's own frame below the entry stack pointer, or on Win64 the home
/// slots the caller hands it.  A save stays unmarked when anything but an
/// unused restore of the same register reads its bytes, or when another store
/// writes them.  Operations keep their positions: call records index them.
void markCalleeSavePrologueSaves(MedFunc &Func, Arch Architecture,
                                 BinaryFormat Format,
                                 StackEntryKind Entry = StackEntryKind::Call);

/// In source mode, mark each pointer-width load of the slot at the entry stack
/// pointer as a ReturnAddressRead when the call pushed its return address
/// there and no store in \p Func writes that slot: the value is the function's
/// own return address, which C spells `__builtin_return_address(0)`.
void markReturnAddressReads(MedFunc &Func, Arch Architecture,
                            BinaryFormat Format,
                            StackEntryKind Entry = StackEntryKind::Call);

} // namespace neverd

#endif // NEVERD_IR_MED_MEDPROLOGUESAVES_H
