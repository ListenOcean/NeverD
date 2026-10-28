//===- X64SEHFinallyBodies.cpp - __finally termination bodies ------------===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//

#include "neverd/ir/high/X64SEHFinallyBodies.h"

#include "../../pass/HighFrameAddress.h"

#include "neverd/Limits.h"
#include "neverd/ir/TargetRegInfo.h"
#include "neverd/ir/high/HighSourceFlow.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringRef.h"

#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace neverd {
namespace {

/// A deep copy of \p E with fresh nodes, so mutations do not reach the
/// original funclet body (which other parents may also attach).
ExprPtr cloneExpr(const ExprPtr &E) {
  if (!E)
    return nullptr;
  auto Copy = std::make_shared<HighExpr>(*E);
  for (ExprPtr &Operand : Copy->Operands)
    Operand = cloneExpr(Operand);
  Copy->IndirectTarget = cloneExpr(Copy->IndirectTarget);
  return Copy;
}

std::vector<HighStmt> cloneStmts(const std::vector<HighStmt> &Stmts);

HighStmt cloneStmt(const HighStmt &S) {
  HighStmt Copy = S;
  Copy.Dst = cloneExpr(S.Dst);
  Copy.Val = cloneExpr(S.Val);
  Copy.Cond = cloneExpr(S.Cond);
  Copy.RetVal = cloneExpr(S.RetVal);
  Copy.StoreAddr = cloneExpr(S.StoreAddr);
  Copy.StoreVal = cloneExpr(S.StoreVal);
  Copy.CallExpr = cloneExpr(S.CallExpr);
  Copy.SwitchExpr = cloneExpr(S.SwitchExpr);
  Copy.Body = cloneStmts(S.Body);
  Copy.ElseBody = cloneStmts(S.ElseBody);
  Copy.DefaultBody = cloneStmts(S.DefaultBody);
  for (SwitchCase &C : Copy.Cases)
    C.Body = cloneStmts(C.Body);
  for (HighEHClause &Clause : Copy.EHClauses)
    Clause.FilterValue = cloneExpr(Clause.FilterValue);
  for (auto &ClauseBody : Copy.EHClauseBodies)
    ClauseBody = cloneStmts(ClauseBody);
  return Copy;
}

std::vector<HighStmt> cloneStmts(const std::vector<HighStmt> &Stmts) {
  std::vector<HighStmt> Result;
  Result.reserve(Stmts.size());
  for (const HighStmt &S : Stmts)
    Result.push_back(cloneStmt(S));
  return Result;
}

/// Rewrite every expression of \p Stmts through \p Fn, children first, so a
/// substitution of a leaf is itself rewritten by its new parent's visit.
void mapExprs(std::vector<HighStmt> &Stmts,
              const std::function<ExprPtr(ExprPtr)> &Fn) {
  std::function<ExprPtr(ExprPtr)> Visit = [&](ExprPtr E) -> ExprPtr {
    if (!E)
      return nullptr;
    for (ExprPtr &Operand : E->Operands)
      Operand = Visit(Operand);
    E->IndirectTarget = Visit(E->IndirectTarget);
    return Fn(std::move(E));
  };
  walkStmts(Stmts, [&](HighStmt &S) {
    forEachExpr(S, [&](ExprPtr &E) { E = Visit(E); });
    for (HighEHClause &Clause : S.EHClauses)
      Clause.FilterValue = Visit(Clause.FilterValue);
  });
}

/// A pure integer value re-evaluated to one constant, when every leaf is a
/// constant.  Covers the two's-complement idiom a compiler emits for
/// `AbnormalTermination()` (`(0 - (int)(flag != 0)) + k`), so the clause with
/// the flag folded false can be matched against the inline normal-path copy.
std::optional<uint64_t> foldToConstant(const HighExpr &E, unsigned Depth = 0) {
  if (Depth > limits::kMaxCExprPrintDepth)
    return std::nullopt;
  const uint64_t Mask = E.Type && E.Type->Size && E.Type->Size < 8
                            ? (uint64_t(1) << (E.Type->Size * 8)) - 1
                            : ~uint64_t(0);
  auto Trunc = [&](uint64_t V) { return V & Mask; };
  if (E.Kind == ExprKind::Const)
    return Trunc(E.ConstVal);
  auto Operand = [&](size_t I) -> std::optional<uint64_t> {
    return I < E.Operands.size() && E.Operands[I]
               ? foldToConstant(*E.Operands[I], Depth + 1)
               : std::nullopt;
  };
  if (E.Kind == ExprKind::Cast || E.Kind == ExprKind::BitCast) {
    if (auto V = Operand(0))
      return Trunc(*V);
    return std::nullopt;
  }
  if (E.Kind == ExprKind::UnaryOp) {
    const auto V = Operand(0);
    if (!V)
      return std::nullopt;
    switch (E.Op) {
    case NdOp::INT_ZEXT:
    case NdOp::CAST:
      return Trunc(*V);
    case NdOp::INT_SEXT: {
      const auto &Src = E.Operands[0];
      const unsigned Bits =
          Src && Src->Type && Src->Type->Size ? Src->Type->Size * 8u : 0;
      if (!Bits || Bits >= 64)
        return Trunc(*V);
      const uint64_t Low = (uint64_t(1) << Bits) - 1;
      uint64_t S = *V & Low;
      if (S & (uint64_t(1) << (Bits - 1)))
        S |= ~Low;
      return Trunc(S);
    }
    case NdOp::INT_NEG2:
    case NdOp::INT_NEGATE:
      return Trunc(0 - *V);
    case NdOp::INT_NOT:
      return Trunc(~*V);
    default:
      return std::nullopt;
    }
  }
  if (E.Kind != ExprKind::BinOp || E.Operands.size() != 2)
    return std::nullopt;
  const auto A = Operand(0);
  const auto B = Operand(1);
  if (!A || !B)
    return std::nullopt;
  switch (E.Op) {
  case NdOp::INT_ADD:
    return Trunc(*A + *B);
  case NdOp::INT_SUB:
    return Trunc(*A - *B);
  case NdOp::INT_AND:
    return Trunc(*A & *B);
  case NdOp::INT_OR:
    return Trunc(*A | *B);
  case NdOp::INT_XOR:
    return Trunc(*A ^ *B);
  case NdOp::INT_EQUAL:
    return *A == *B ? 1 : 0;
  case NdOp::INT_NOTEQUAL:
    return *A != *B ? 1 : 0;
  default:
    return std::nullopt;
  }
}

/// Replace every integer subtree of \p Stmts that evaluates to a constant with
/// that constant, so a straight-line body with the abnormal flag pinned folds
/// to its concrete effect.
void foldConstants(std::vector<HighStmt> &Stmts) {
  mapExprs(Stmts, [](ExprPtr E) -> ExprPtr {
    if (!E || E->Kind == ExprKind::Const || !E->Type ||
        E->Type->Kind != NdTypeKind::Int)
      return E;
    if (auto V = foldToConstant(*E)) {
      auto Const = HighExpr::makeConst(*V, E->Type->Size,
                                       ConstantAddressProvenance::Scalar);
      Const->Type = E->Type;
      return Const;
    }
    return E;
  });
}

/// Inline trivial copies (`v = <param|const>`) into their uses and drop the
/// defining assignment, so a home-slot load the rebase turned into a parameter
/// reads as that parameter.  Only straight-line pure copies are inlined.
void inlineTrivialCopies(std::vector<HighStmt> &Stmts) {
  std::map<std::pair<int, int>, ExprPtr> Copies;
  auto key = [](const MedVar &V) { return std::make_pair(V.Id, V.SSAVer); };
  auto substitutable = [](const ExprPtr &V) {
    return V && (V->Kind == ExprKind::Var || V->Kind == ExprKind::Const) &&
           !V->IndirectTarget;
  };
  std::vector<HighStmt> Result;
  for (HighStmt &S : Stmts) {
    if (!S.Body.empty() || !S.ElseBody.empty() || !S.Cases.empty() ||
        !S.DefaultBody.empty() || !S.EHClauseBodies.empty()) {
      // Only straight-line funclet bodies reach here; a nested region is not
      // a copy and keeps the whole statement.
      Result.push_back(std::move(S));
      continue;
    }
    auto replace = [&](ExprPtr &E) {
      if (E && E->Kind == ExprKind::Var) {
        auto It = Copies.find(key(E->Var));
        if (It != Copies.end())
          E = cloneExpr(It->second);
      }
    };
    std::function<void(ExprPtr &)> apply = [&](ExprPtr &E) {
      if (!E)
        return;
      for (ExprPtr &Operand : E->Operands)
        apply(Operand);
      apply(E->IndirectTarget);
      replace(E);
    };
    forEachExpr(S, [&](ExprPtr &E) { apply(E); });
    if (S.Kind == StmtKind::Assign && S.Dst && S.Dst->Kind == ExprKind::Var &&
        substitutable(S.Val)) {
      Copies[key(S.Dst->Var)] = S.Val;
      continue; // drop the copy; its uses now read the value directly
    }
    Result.push_back(std::move(S));
  }
  Stmts = std::move(Result);
}

/// The incoming parameter a function homes at entry-SP displacement \p Offset,
/// as a Win64 prologue spills `[rsp + k] = arg`.  Only the statements before
/// the first structured region are consulted, and a displacement written more
/// than once, or by a non-parameter, yields nothing there.
std::map<int64_t, MedVar> homedParameters(const HighFunc &Func,
                                          Arch TargetArch) {
  std::map<int64_t, MedVar> Homed;
  std::set<int64_t> Ambiguous;
  size_t Budget = limits::kMaxCxxObjectAddressWork;
  for (const HighStmt &S : Func.Body) {
    if (S.Kind == StmtKind::SEHTry || S.Kind == StmtKind::CxxTry ||
        S.Kind == StmtKind::ItaniumTry)
      break;
    if (S.Kind != StmtKind::Store || !S.StoreAddr || !S.StoreVal)
      continue;
    const auto Offset =
        high_detail::frameAddressOffset(S.StoreAddr, Func, TargetArch, Budget);
    if (!Offset)
      continue;
    if (!Ambiguous.insert(*Offset).second) {
      Homed.erase(*Offset);
      continue;
    }
    const ExprPtr &V = S.StoreVal;
    if (V->Kind == ExprKind::Var && V->Var.Kind == MedVar::Param &&
        S.StoreAddr->Type &&
        S.StoreAddr->Type->Size == getTargetRegInfo(TargetArch).PointerSize)
      Homed.emplace(*Offset, V->Var);
  }
  return Homed;
}

struct FuncletShape {
  std::vector<HighStmt> Body;
  bool NoReturnTail = false;
};

/// The funclet's straight-line body, with its trailing `return` dropped (a
/// `__finally` yields no value), when its shape is supported; nullopt keeps the
/// address comment.  The body must be straight line, with no nested region, no
/// control transfer, no reference to its own stack pointer or a third
/// parameter, and no exception metadata of its own.
std::optional<FuncletShape> funcletShape(const HighFunc &Funclet,
                                         Arch TargetArch) {
  if (Funclet.Body.empty() ||
      (Funclet.ExceptionMetadata && Funclet.ExceptionMetadata->SEH &&
       !Funclet.ExceptionMetadata->SEH->Scopes.empty()) ||
      (Funclet.ExceptionMetadata && Funclet.ExceptionMetadata->Cxx) ||
      (Funclet.ExceptionMetadata && Funclet.ExceptionMetadata->Itanium) ||
      (Funclet.ExceptionMetadata && Funclet.ExceptionMetadata->Registration))
    return std::nullopt;
  const uint64_t SP = getTargetRegInfo(TargetArch).StackPointer;
  bool Bad = false;
  bool NoReturnTail = false;
  for (size_t I = 0; I < Funclet.Body.size(); ++I) {
    const HighStmt &S = Funclet.Body[I];
    const bool Last = I + 1 == Funclet.Body.size();
    switch (S.Kind) {
    case StmtKind::Assign:
    case StmtKind::Store:
    case StmtKind::ExprStmt:
    case StmtKind::Call:
    case StmtKind::Nop:
    case StmtKind::Block:
      break;
    case StmtKind::Return:
      if (!Last)
        Bad = true;
      break;
    default:
      Bad = true;
      break;
    }
    if (!S.Body.empty() || !S.ElseBody.empty() || !S.Cases.empty() ||
        !S.DefaultBody.empty() || !S.EHClauseBodies.empty())
      Bad = true;
    forEachExpr(S, [&](const ExprPtr &Root) {
      std::function<void(const ExprPtr &)> Visit = [&](const ExprPtr &E) {
        if (!E)
          return;
        if (E->Kind == ExprKind::Var) {
          if (E->Var.Kind == MedVar::Reg && E->Var.RegOff == SP)
            Bad = true; // its own frame would alias the parent's
          if (E->Var.Kind == MedVar::Param && E->Var.Id >= 2)
            Bad = true; // a finally callback takes only (flag, frame)
        }
        E->forEachChildExpr(Visit);
      };
      Visit(Root);
    });
    if (Last && S.Kind == StmtKind::Call && isTerminatingHighCall(S.CallExpr))
      NoReturnTail = true;
  }
  if (Bad)
    return std::nullopt;
  FuncletShape Shape;
  Shape.Body = cloneStmts(Funclet.Body);
  Shape.NoReturnTail = NoReturnTail;
  if (!Shape.Body.empty() && Shape.Body.back().Kind == StmtKind::Return)
    Shape.Body.pop_back();
  return Shape;
}

/// The funclet body projected into the parent frame: the establisher-frame
/// parameter rebased onto the parent's entry stack pointer, each home-slot load
/// turned back into the parameter it holds, and the abnormal-termination
/// parameter replaced by \p AbnormalFlag (a call to `AbnormalTermination()`, or
/// a folded constant for the dedup check).
std::vector<HighStmt>
projectFuncletBody(const std::vector<HighStmt> &FuncletBody,
                   const HighFunc &Parent, Arch TargetArch, uint64_t FrameBytes,
                   const ExprPtr &AbnormalFlag,
                   const std::map<int64_t, MedVar> &Homed, int RenameBase) {
  const TargetRegInfo &TRI = getTargetRegInfo(TargetArch);
  std::vector<HighStmt> Body = cloneStmts(FuncletBody);

  MedVar EntrySP;
  EntrySP.Kind = MedVar::Reg;
  EntrySP.TheArch = TargetArch;
  EntrySP.RenameTag = -1;
  EntrySP.SSAVer = 0;
  EntrySP.RegOff = TRI.StackPointer;
  EntrySP.Size = TRI.PointerSize;

  // arg0 -> abnormal flag, arg1 -> entry SP - FrameBytes.  Give the funclet's
  // own temporaries fresh rename tags so their printed `tN`/`vN` names cannot
  // collide with the parent's.
  mapExprs(Body, [&](ExprPtr E) -> ExprPtr {
    if (!E || E->Kind != ExprKind::Var)
      return E;
    if (E->Var.Kind == MedVar::Param && E->Var.Id == 0 && AbnormalFlag) {
      ExprPtr Flag = cloneExpr(AbnormalFlag);
      if (E->Type)
        Flag->Type = E->Type;
      return Flag;
    }
    if (E->Var.Kind == MedVar::Param && E->Var.Id == 1) {
      ExprPtr Base = HighExpr::makeVar(EntrySP, NdType::makeInt(8, false));
      ExprPtr Rebased = HighExpr::makeBinop(
          NdOp::INT_SUB, Base,
          HighExpr::makeConst(FrameBytes, 8,
                              ConstantAddressProvenance::Scalar));
      Rebased->Type = E->Type ? E->Type : NdType::makeInt(8, false);
      return Rebased;
    }
    if (E->Var.RenameTag >= 0 &&
        RenameBase <= std::numeric_limits<int16_t>::max() - E->Var.RenameTag)
      E->Var.RenameTag = static_cast<int16_t>(RenameBase + E->Var.RenameTag);
    return E;
  });

  // A pointer-width load of a homed slot is the homed parameter.
  if (!Homed.empty()) {
    size_t Budget = limits::kMaxCxxObjectAddressWork;
    mapExprs(Body, [&](ExprPtr E) -> ExprPtr {
      if (!E || E->Kind != ExprKind::Load || E->Operands.size() != 1 ||
          !E->Type || E->Type->Size != TRI.PointerSize ||
          E->MemoryOrdering != NdMemoryOrdering::None ||
          E->MemoryAddressSpace != NdMemoryAddressSpace::Default)
        return E;
      const auto Offset = high_detail::frameAddressOffset(
          E->Operands[0], Parent, TargetArch, Budget);
      if (!Offset)
        return E;
      auto It = Homed.find(*Offset);
      if (It == Homed.end())
        return E;
      return HighExpr::makeVar(It->second, E->Type);
    });
  }

  foldConstants(Body);
  inlineTrivialCopies(Body);
  return Body;
}

ExprPtr makeAbnormalTermination() {
  // `AbnormalTermination()` is a compiler intrinsic declared by <excpt.h>,
  // like `GetExceptionCode()`; it takes no arguments and needs no declaration.
  ExprPtr Call = HighExpr::makeCall("AbnormalTermination", 0, {});
  Call->Type = NdType::makeInt(4);
  return Call;
}

int maxRenameTag(const std::vector<HighStmt> &Stmts) {
  int Max = -1;
  walkStmts(Stmts, [&](const HighStmt &S) {
    forEachExpr(S, [&](const ExprPtr &Root) {
      std::function<void(const ExprPtr &)> Visit = [&](const ExprPtr &E) {
        if (!E)
          return;
        Max = std::max<int>(Max, E->Var.RenameTag);
        for (const MedVar &Out : E->IntrinsicOutputs)
          Max = std::max<int>(Max, Out.RenameTag);
        E->forEachChildExpr(Visit);
      };
      Visit(Root);
    });
  });
  return Max;
}

/// Whether \p Stmts call a routine that unwinds this frame to a target in the
/// function (`_local_unwind`, `RtlUnwind[Ex]`).  The machine then runs the
/// termination handler with the abnormal flag set, but C reads the call as an
/// ordinary one followed by a normal exit, so a filled `__finally` would not
/// run there.  Such a region keeps its out-of-line form until the call becomes
/// a structured jump.
bool callsLocalUnwind(const std::vector<HighStmt> &Stmts) {
  bool Found = false;
  auto IsUnwind = [](llvm::StringRef Name) {
    Name = Name.ltrim('_');
    return Name.starts_with("local_unwind") || Name == "RtlUnwind" ||
           Name == "RtlUnwindEx";
  };
  walkStmts(Stmts, [&](const HighStmt &S) {
    forEachExpr(S, [&](const ExprPtr &Root) {
      std::function<void(const ExprPtr &)> Visit = [&](const ExprPtr &E) {
        if (!E || Found)
          return;
        if (E->Kind == ExprKind::Call && IsUnwind(E->CallTarget))
          Found = true;
        E->forEachChildExpr(Visit);
      };
      Visit(Root);
    });
  });
  return Found;
}

/// Whether any expression of \p Stmts reads the abnormal-termination
/// parameter (the funclet's first argument).
bool referencesAbnormalFlag(const std::vector<HighStmt> &Stmts) {
  bool Found = false;
  walkStmts(Stmts, [&](const HighStmt &S) {
    forEachExpr(S, [&](const ExprPtr &Root) {
      std::function<void(const ExprPtr &)> Visit = [&](const ExprPtr &E) {
        if (!E)
          return;
        if (E->Kind == ExprKind::Var && E->Var.Kind == MedVar::Param &&
            E->Var.Id == 0)
          Found = true;
        E->forEachChildExpr(Visit);
      };
      Visit(Root);
    });
  });
  return Found;
}

bool stmtEqual(const HighStmt &A, const HighStmt &B) {
  // `*p = v` reaches HighIR as a Store or as an assignment to a load; compare
  // the address and value either way.
  auto deref = [](const HighStmt &S, ExprPtr &Addr, ExprPtr &Val) {
    if (S.Kind == StmtKind::Store) {
      Addr = S.StoreAddr;
      Val = S.StoreVal;
      return true;
    }
    if (S.Kind == StmtKind::Assign && S.Dst && S.Dst->Kind == ExprKind::Load &&
        !S.Dst->Operands.empty()) {
      Addr = S.Dst->Operands[0];
      Val = S.Val;
      return true;
    }
    return false;
  };
  auto eq = [](const ExprPtr &X, const ExprPtr &Y) {
    if (!X || !Y)
      return X == Y;
    return X->structuralEq(*Y);
  };
  ExprPtr AAddr, AVal, BAddr, BVal;
  const bool ADeref = deref(A, AAddr, AVal);
  const bool BDeref = deref(B, BAddr, BVal);
  if (ADeref && BDeref)
    return eq(AAddr, BAddr) && eq(AVal, BVal);
  if (ADeref || BDeref)
    return false;
  return A.Kind == B.Kind && eq(A.Dst, B.Dst) && eq(A.Val, B.Val) &&
         eq(A.CallExpr, B.CallExpr);
}

/// The dereferenced address of a `*p = v` statement, either spelling, else
/// null.
const HighExpr *storeAddress(const HighStmt &S) {
  if (S.Kind == StmtKind::Store)
    return S.StoreAddr.get();
  if (S.Kind == StmtKind::Assign && S.Dst && S.Dst->Kind == ExprKind::Load &&
      !S.Dst->Operands.empty())
    return S.Dst->Operands[0].get();
  return nullptr;
}

/// Where the parent's statements after \p TryIndex begin the inline normal-path
/// copy of the finally: the leading run equal to the funclet body with the
/// abnormal flag folded false.  Returns the count to remove, or nullopt when no
/// such run is proved.  A deleted statement must not be a branch target, and
/// the run must not be an ambiguous prefix of a longer repetition, so removing
/// it cannot drop the parent's real continuation or a label a goto needs.
std::optional<size_t> inlineCopyLength(const std::vector<HighStmt> &Body,
                                       size_t TryIndex,
                                       const std::vector<HighStmt> &NormalBody,
                                       const std::set<va_t> &Targets) {
  if (NormalBody.empty() || TryIndex + 1 + NormalBody.size() > Body.size())
    return std::nullopt;
  for (size_t I = 0; I < NormalBody.size(); ++I) {
    const HighStmt &S = Body[TryIndex + 1 + I];
    if (!stmtEqual(S, NormalBody[I]))
      return std::nullopt;
    if (S.Addr && S.Addr != InvalidVA && Targets.count(S.Addr))
      return std::nullopt;
  }
  // If the statement right after the run repeats the last store's address, the
  // run could be a coincidental prefix rather than exactly the copy.
  const size_t After = TryIndex + 1 + NormalBody.size();
  if (const HighExpr *Last = storeAddress(Body[After - 1]);
      Last && After < Body.size())
    if (const HighExpr *Next = storeAddress(Body[After]);
        Next && Next->structuralEq(*Last))
      return std::nullopt;
  return NormalBody.size();
}

} // namespace

void attachSEHFinallyBodies(std::vector<HighFunc> &Funcs, Arch TargetArch,
                            std::set<va_t> *Merged) {
  if (TargetArch != Arch::X64)
    return;
  // Only a parent with a certified termination frame can gain a body. Index
  // just the funclets those parents name, so a unit without one pays nothing.
  std::map<va_t, const HighFunc *> ByEntry;
  for (const HighFunc &Func : Funcs)
    for (const auto &Entry : Func.SEHTerminationFrameBytes)
      ByEntry.emplace(Entry.first, nullptr);
  if (ByEntry.empty())
    return;
  for (const HighFunc &Func : Funcs)
    if (auto It = ByEntry.find(Func.Entry); It != ByEntry.end() && !It->second)
      It->second = &Func;

  for (HighFunc &Parent : Funcs) {
    if (!Parent.ExceptionMetadata || !Parent.ExceptionMetadata->SEH ||
        Parent.SEHTerminationFrameBytes.empty() || Parent.FrameSize <= 0)
      continue;
    // Whole-body facts, computed once a region of this parent qualifies.
    std::optional<std::map<int64_t, MedVar>> Homed;
    std::optional<std::set<va_t>> Targets;
    int NextTag = 0;

    // Top-level only: a termination region the structurer kept is a direct
    // statement of the body, and the inline normal-path copy follows it there.
    for (size_t I = 0; I < Parent.Body.size(); ++I) {
      HighStmt &Stmt = Parent.Body[I];
      if (Stmt.Kind != StmtKind::SEHTry || !Stmt.EHIsReducible ||
          Stmt.EHClauses.size() != 1 || Stmt.EHClauseBodies.size() != 1 ||
          Stmt.EHClauses.front().Kind != HighEHClauseKind::SEHFinally ||
          !Stmt.EHClauseBodies.front().empty())
        continue;
      // A protected body that itself transfers control cannot gain a non-empty
      // finally: the writer no longer redirects its `__leave` to the finally.
      // A nested exception region in the body is also left alone: a same-range
      // inner `__except` reaches its handler by a `goto` that leaves this try,
      // and a filled `__finally` would run on that edge, before the handler.
      bool TransfersOut = false;
      walkStmts(Stmt.Body, [&](const HighStmt &S) {
        if (S.Kind == StmtKind::Return || S.Kind == StmtKind::Goto ||
            S.Kind == StmtKind::Break || S.Kind == StmtKind::Continue ||
            S.Kind == StmtKind::SEHTry || S.Kind == StmtKind::CxxTry ||
            S.Kind == StmtKind::ItaniumTry)
          TransfersOut = true;
      });
      if (TransfersOut || callsLocalUnwind(Stmt.Body))
        continue;
      const va_t FuncletVA = Stmt.EHClauses.front().FilterOrActionVA;
      auto Frame = Parent.SEHTerminationFrameBytes.find(FuncletVA);
      auto Funclet = ByEntry.find(FuncletVA);
      if (Frame == Parent.SEHTerminationFrameBytes.end() ||
          Funclet == ByEntry.end() || !Funclet->second ||
          Funclet->second == &Parent)
        continue;
      const std::optional<FuncletShape> Shape =
          funcletShape(*Funclet->second, TargetArch);
      if (!Shape)
        continue;
      if (!Homed) {
        Homed = homedParameters(Parent, TargetArch);
        NextTag = maxRenameTag(Parent.Body) + 1;
      }

      // When the body does not depend on the abnormal flag, it runs the same
      // on both exits: prove the statements after the `__try` are the inline
      // normal-path copy and, if so, drop them and run the body itself in the
      // clause (`__finally { *Counter += 1; }`).  Otherwise, keep that copy
      // and run only the abnormal work while unwinding, so the finally never
      // runs twice (`__finally { if (AbnormalTermination()) *Counter = 99; }`).
      const bool DependsOnFlag = referencesAbnormalFlag(Shape->Body);
      std::optional<size_t> CopyLength;
      if (!DependsOnFlag && !Shape->NoReturnTail) {
        std::vector<HighStmt> Normal = projectFuncletBody(
            Shape->Body, Parent, TargetArch, Frame->second,
            HighExpr::makeConst(0, 4, ConstantAddressProvenance::Scalar),
            *Homed, NextTag);
        if (!Targets)
          Targets = gotoTargets(Parent.Body);
        CopyLength = inlineCopyLength(Parent.Body, I, Normal, *Targets);
      }

      if (CopyLength) {
        Stmt.EHClauseBodies.front() = projectFuncletBody(
            Shape->Body, Parent, TargetArch, Frame->second, /*AbnormalFlag=*/
            HighExpr::makeConst(0, 4, ConstantAddressProvenance::Scalar),
            *Homed, NextTag);
        Parent.Body.erase(Parent.Body.begin() + I + 1,
                          Parent.Body.begin() + I + 1 + *CopyLength);
      } else {
        std::vector<HighStmt> Abnormal = projectFuncletBody(
            Shape->Body, Parent, TargetArch, Frame->second,
            HighExpr::makeConst(1, 4, ConstantAddressProvenance::Scalar),
            *Homed, NextTag);
        HighStmt Guard;
        Guard.Kind = StmtKind::If;
        Guard.Cond = makeAbnormalTermination();
        Guard.Body = std::move(Abnormal);
        Stmt.EHClauseBodies.front().push_back(std::move(Guard));
      }
      if (Merged)
        Merged->insert(FuncletVA);
      // A later attach must take fresh names past this one's. Only the clause
      // just filled can raise the maximum; a dropped copy can only lower it.
      NextTag =
          std::max(NextTag, maxRenameTag(Stmt.EHClauseBodies.front()) + 1);
    }
  }
}

} // namespace neverd
