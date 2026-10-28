//===- X87NativeState.h - Native x87 state C calls ------------*- C++ -*-===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
/// \file
/// Render native x87 state operations and their exact instruction fallbacks.
//===----------------------------------------------------------------------===//

#ifndef NEVERD_BACKEND_C_RENDER_X86_X87NATIVESTATE_H
#define NEVERD_BACKEND_C_RENDER_X86_X87NATIVESTATE_H

#include "neverd/backend/llvm/X86/LLVMX86X87StateAsm.h"
#include "neverd/backend/llvm/X86/LLVMX87NativeState.h"

#include "llvm/ADT/StringRef.h"

#include <string>

namespace neverd {

inline std::string renderX87NativeState(const X87NativeStateSpec &Spec,
                                        llvm::StringRef Address = {},
                                        llvm::StringRef Result = {}) {
  std::string Text = "\n#if __has_builtin(" + std::string(Spec.Builtin) + ")\n";
  if (Spec.ReturnsStatus && !Result.empty())
    Text += Result.str() + " = ";
  Text += std::string(Spec.Builtin) + "(";
  if (Spec.HasPointer)
    Text += std::string(Spec.Kind == X87NativeStateKind::WriteControl
                            ? "(const unsigned short *)("
                            : "(unsigned short *)(") +
            Address.str() + ")";
  Text += ");\n#else\n__asm__ volatile(\"" + std::string(Spec.Mnemonic);
  if (Spec.HasPointer)
    Text += " (%0)\" :: \"r\"(" + Address.str() + ") : \"memory\");";
  else if (Spec.ReturnsStatus)
    Text += Result.empty()
                ? " %%ax\" ::: \"ax\", \"memory\");"
                : " %%ax\" : \"=a\"(" + Result.str() + ") :: \"memory\");";
  else
    Text += "\" ::: " +
            x87StateCClobbers(Spec.Kind == X87NativeStateKind::Initialize
                                  ? X87StateEffect::Reset
                                  : X87StateEffect::Status)
                .str() +
            ");";
  return Text + "\n#endif\n";
}

inline std::string renderX87ControlAccess(bool Write, llvm::StringRef Address) {
  return renderX87NativeState(
      x87NativeStateSpec(Write ? X87NativeStateKind::WriteControl
                               : X87NativeStateKind::ReadControl),
      Address);
}

} // namespace neverd

#endif // NEVERD_BACKEND_C_RENDER_X86_X87NATIVESTATE_H
