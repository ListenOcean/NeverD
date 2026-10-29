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

#include <map>

namespace neverd {

/// Whether \p V is the value register \p RegOff holds at \p Func's entry:
/// its version zero, or the entry seed that copies it (`COPY RSI.1 = RSI`).
bool isEntryLiveInValue(const MedFunc &Func, const MedVar &V, uint64_t RegOff);

/// Mark source-mode prologue saves, unobserved scratch spills and
/// return-address reads using one frame access analysis. Complete fixed integer
/// call operands reading private frame bytes proved never written on any
/// incoming path become explicit unavailable values in source only. General
/// partial-byte observations are separate. The analysis is discarded before
/// returning; operation positions stay stable.
void markSourceStackAccesses(MedFunc &Func, Arch Architecture,
                             BinaryFormat Format,
                             StackEntryKind Entry = StackEntryKind::Call);

/// After call argument recovery, omit private stores only when a complete
/// noncapturing use proof of the frame finds no reads of their bytes. Direct
/// callees contribute their actual bounded pointer reads, including negative
/// displacements. Unknown callees, escapes and unsupported uses keep stores.
void markUnobservedBorrowedFrameStores(
    MedFunc &Func, Arch Architecture, BinaryFormat Format,
    const std::map<va_t, const MedFunc *> &Callees);

/// After call argument recovery, omit each store of a scratch register's
/// undefined incoming value (holdsUndefinedIncomingScratch), as an alignment
/// `push rax` makes one, into the function's own frame below the entry stack
/// pointer, where no load or stack variable of the function reads those
/// bytes: they held no defined value before the store and hold none after
/// it.  A store of the convention's variadic count register (System V's
/// RAX), which carries nothing into a function that is not variadic, goes
/// also where a call receives an address in its slot before anything may
/// read the bytes, as for a local a routine fills through its address
/// (`int x; get(&x, a); return x;`): a read then sees what the routine wrote
/// or bytes the program never defined, as the local's would.  Any other
/// store whose bytes the function reads back stays, so that the read fails
/// where it uses the value.  A variadic function's register save area and a
/// function an exception dispatcher enters keep theirs.
void markUndefinedScratchStores(MedFunc &Func, Arch Architecture,
                                BinaryFormat Format);

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
