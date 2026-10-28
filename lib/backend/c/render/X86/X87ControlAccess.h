//===- X87ControlAccess.h - Native x87 control-word C calls ----*- C++ -*-===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
/// \file
/// Render shared control-word memory operations for both C projections.
//===----------------------------------------------------------------------===//

#ifndef NEVERD_BACKEND_C_RENDER_X86_X87CONTROLACCESS_H
#define NEVERD_BACKEND_C_RENDER_X86_X87CONTROLACCESS_H

#include "llvm/ADT/StringRef.h"

#include <string>

namespace neverd {

inline std::string renderX87ControlAccess(bool Write, llvm::StringRef Address) {
  const std::string Instruction = Write ? "fldcw" : "fnstcw";
  return "\n#if __has_builtin(__builtin_ia32_" + Instruction + ")\n" +
         "__builtin_ia32_" + Instruction + "((" +
         (Write ? "const unsigned short *" : "unsigned short *") + ")(" +
         Address.str() + "));\n#else\n" + "__asm__ volatile(\"" + Instruction +
         " (%0)\" :: \"r\"(" + Address.str() + ") : \"memory\");\n#endif\n";
}

} // namespace neverd

#endif // NEVERD_BACKEND_C_RENDER_X86_X87CONTROLACCESS_H
