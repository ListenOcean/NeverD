//===- LLVMCSourcePointerTests.cpp - Source call pointer bridges --------===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Execute calls whose source declarations and machine carriers differ.
///
//===----------------------------------------------------------------------===//

#include "SourceCallExecution.h"
#include "gtest/gtest.h"

#include "neverd/backend/RewriteSourceIdentity.h"
#include "neverd/backend/c/LLVMC/LLVMCEmitter.h"
#include "neverd/backend/llvm/LLVMSourceTypeHints.h"

#include "llvm/AsmParser/Parser.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/SourceMgr.h"

#include <map>
#include <optional>
#include <string>

namespace {
using namespace neverd;

class PointerContext final : public NullDebugContext {
public:
  std::map<va_t, FunctionSym> Functions;
  std::optional<FunctionSym> resolveFunction(va_t Address) const override {
    const auto It = Functions.find(Address);
    return It == Functions.end() ? std::nullopt : std::optional(It->second);
  }
  bool hasInfo() const override { return true; }
};

TEST(LLVMCSourcePointers, DefinitionAndCallsShareObjectAndCallbackTypes) {
  for (const auto Arch : {Arch::X64, Arch::AArch64})
    for (const auto Format :
         {BinaryFormat::COFF, BinaryFormat::ELF, BinaryFormat::MachO})
      for (unsigned Mode = 0; Mode != 5; ++Mode) {
        SCOPED_TRACE(static_cast<int>(Arch));
        SCOPED_TRACE(static_cast<int>(Format));
        SCOPED_TRACE(Mode);
        const bool Selected = Mode == 1;
        const bool Preserved = Mode == 2;
        const bool Alias = Mode == 3;
        llvm::LLVMContext C;
        llvm::Module M("source-pointer-calls", C);
        M.setDataLayout("e-p:64:64");
        llvm::IRBuilder<> B(C);
        auto *Word = B.getInt64Ty();
        auto *Unary = llvm::FunctionType::get(Word, {Word}, false);
        // The caller precedes its definitions, as a module's physical order
        // carries no authority over a source prototype.
        auto *Caller = llvm::Function::Create(
            Unary, llvm::GlobalValue::ExternalLinkage, "bridge_entry", M);
        auto *RoundTrip = llvm::Function::Create(
            Unary, llvm::GlobalValue::ExternalLinkage, "round_trip", M);
        auto *Apply = llvm::Function::Create(
            llvm::FunctionType::get(Word, {Word, Word}, false),
            llvm::GlobalValue::ExternalLinkage, "apply_callback", M);
        auto *Callback = llvm::Function::Create(
            Unary, llvm::GlobalValue::ExternalLinkage, "add_seven", M);
        rewrite_source::setOriginalVA(*RoundTrip, 0x2000);
        rewrite_source::setOriginalVA(*Apply, 0x3000);
        B.SetInsertPoint(llvm::BasicBlock::Create(C, "entry", Caller));
        auto *Pointer = B.CreateCall(RoundTrip, {Caller->getArg(0)});
        auto *Value =
            B.CreateLoad(Word, B.CreateIntToPtr(Pointer, B.getPtrTy()));
        B.CreateRet(
            B.CreateCall(Apply, {B.CreatePtrToInt(Callback, Word), Value}));
        B.SetInsertPoint(llvm::BasicBlock::Create(C, "entry", RoundTrip));
        B.CreateRet(RoundTrip->getArg(0));
        B.SetInsertPoint(llvm::BasicBlock::Create(C, "entry", Apply));
        B.CreateRet(B.CreateCall(
            Unary, B.CreateIntToPtr(Apply->getArg(0), B.getPtrTy()),
            {Apply->getArg(1)}));
        B.SetInsertPoint(llvm::BasicBlock::Create(C, "entry", Callback));
        B.CreateRet(B.CreateAdd(Callback->getArg(0), B.getInt64(7)));
        ASSERT_FALSE(llvm::verifyModule(M, &llvm::errs()));
        const auto Scalar = NdType::makeInt(8, false);
        const auto PointerType = NdType::makePtr(Scalar);
        // A source pointer narrower than its machine carrier cannot change
        // either side of the signature into the compiler's native pointer.
        if (Mode == 4)
          PointerType->Size = 4;
        if (Alias)
          PointerType->TypedefName = "WORD_POINTER";
        auto Function = std::make_shared<NdType>();
        Function->Kind = NdTypeKind::Func;
        Function->RetType = Scalar;
        Function->ParamTypes = {Scalar};
        PointerContext Debug;
        FunctionSym Round;
        Round.Addr = 0x2000;
        Round.Name = "round_trip";
        Round.ReturnType = PointerType;
        Round.Params = {{"address", PointerType}};
        Debug.Functions[Round.Addr] = Round;
        FunctionSym Call;
        Call.Addr = 0x3000;
        Call.Name = "apply_callback";
        Call.ReturnType = Scalar;
        Call.Params = {{"callback", NdType::makePtr(Function)},
                       {"value", Scalar}};
        Debug.Functions[Call.Addr] = Call;
        CEmitterOptions Options;
        Options.TheArch = Arch;
        Options.Format = Format;
        Options.PreserveLLVMFunctionTypes = Preserved;
        Options.RecordDefinitions = [Alias](const std::vector<TypeRef> &) {
          CRecordDefinitions Definitions;
          if (Alias) {
            Definitions.Text = "typedef uint64_t *WORD_POINTER;\n";
            Definitions.Identifiers = {"WORD_POINTER"};
          }
          return Definitions;
        };
        std::string Text;
        llvm::raw_string_ostream Out(Text);
        ASSERT_TRUE(LLVMCEmitter().emit(M, Out, Options, &Debug, nullptr,
                                        Selected ? Caller : nullptr));
        Out.flush();
        if (Selected)
          Text += R"c(
uint64_t round_trip(uint64_t address) { return address; }
uint64_t apply_callback(uint64_t callback, uint64_t value) {
  return ((uint64_t (*)(uint64_t))(uintptr_t)callback)(value);
}
uint64_t add_seven(uint64_t value) { return value + 7; }
)c";
        Text += R"c(
int main(void) {
  uint64_t value = 11;
  if (bridge_entry((uintptr_t)&value) != 18) return 1;
  value = 71;
  return bridge_entry((uintptr_t)&value) != 78;
}
)c";
        for (const auto Optimization : {"-O0", "-O2"})
          source_call_execution_test::compileAndRun(
              Text, {Optimization, "-Werror=int-conversion",
                     "-Werror=incompatible-pointer-types",
                     "-fsanitize=undefined", "-fsanitize-trap=all"});
      }
}
TEST(LLVMCSourcePointers, InferredPointeesSurviveSerializationAndShareCalls) {
  for (unsigned Kind : {0u, 1u, 2u})
    for (unsigned Mode : {0u, 1u, 2u, 3u}) {
      SCOPED_TRACE(Kind);
      SCOPED_TRACE(Mode);
      const bool Nested = Kind == 2;
      const bool Explicit = Mode == 1;
      const bool Preserve = Mode == 2;
      const bool Selected = Mode == 3;
      llvm::LLVMContext Context;
      llvm::Module Module("inferred-source-pointers", Context);
      Module.setDataLayout("e-p:64:64");
      llvm::IRBuilder<> Builder(Context);
      const auto Scalar = NdType::makeInt(2, false);
      const auto Record = NdType::makeNamedRecord("PointerPayload", 64);
      auto Type = NdType::makePtr(Kind ? Record : Scalar);
      if (Nested)
        Type = NdType::makePtr(Type);
      auto *Entry = llvm::Function::Create(
          llvm::FunctionType::get(Builder.getInt16Ty(), {Builder.getInt64Ty()},
                                  false),
          llvm::GlobalValue::ExternalLinkage, "pointer_entry", Module);
      auto *Forward = llvm::Function::Create(
          llvm::FunctionType::get(Builder.getInt16Ty(), {Builder.getPtrTy()},
                                  false),
          llvm::GlobalValue::ExternalLinkage, "pointer_forward", Module);
      rewrite_source::setOriginalVA(*Forward, 0x2000);
      writeLLVMSourcePointerParameter(*Forward->getArg(0), Type);
      const auto Read = readLLVMSourcePointerParameter(*Forward->getArg(0));
      ASSERT_TRUE(Read);
      auto Leaf = Read;
      while (Leaf->Kind == NdTypeKind::Ptr)
        Leaf = Leaf->Pointee;
      if (Kind) {
        EXPECT_EQ(Leaf->Size, 0u);
        EXPECT_TRUE(Leaf->Fields.empty());
      }
      Builder.SetInsertPoint(llvm::BasicBlock::Create(Context, "entry", Entry));
      Builder.CreateRet(Builder.CreateCall(
          Forward,
          {Builder.CreateIntToPtr(Entry->getArg(0), Builder.getPtrTy())}));
      Builder.SetInsertPoint(
          llvm::BasicBlock::Create(Context, "entry", Forward));
      llvm::Value *Address = Forward->getArg(0);
      if (Nested)
        Address = Builder.CreateLoad(Builder.getPtrTy(), Address);
      Builder.CreateRet(Builder.CreateLoad(Builder.getInt16Ty(), Address));
      ASSERT_FALSE(llvm::verifyModule(Module, &llvm::errs()));
      std::string Serialized;
      llvm::raw_string_ostream IR(Serialized);
      Module.print(IR, nullptr);
      llvm::LLVMContext RestoredContext;
      llvm::SMDiagnostic Diagnostic;
      const auto Restored =
          llvm::parseAssemblyString(Serialized, Diagnostic, RestoredContext);
      ASSERT_TRUE(Restored);
      PointerContext Debug;
      if (Explicit) {
        FunctionSym Declared;
        Declared.Addr = 0x2000;
        Declared.ReturnType = Scalar;
        Declared.Params = {{"input", NdType::makePtr()}};
        Debug.Functions.emplace(Declared.Addr, Declared);
      }
      CEmitterOptions Options;
      Options.TheArch = Arch::X64;
      Options.Format = BinaryFormat::COFF;
      Options.PreserveLLVMFunctionTypes = Preserve;
      std::string Text;
      llvm::raw_string_ostream Out(Text);
      ASSERT_TRUE(LLVMCEmitter().emit(
          *Restored, Out, Options, Explicit ? &Debug : nullptr, nullptr,
          Selected ? Restored->getFunction("pointer_entry") : nullptr));
      Out.flush();
      if (Explicit || Preserve || Selected)
        EXPECT_EQ(Text.find("PointerPayload"), std::string::npos) << Text;
      else
        EXPECT_NE(Text.find(std::string(Kind ? "PointerPayload" : "uint16_t") +
                            (Nested ? "** " : "* ")),
                  std::string::npos)
            << Text;
      if (Selected)
        Text +=
            std::string("\nuint16_t pointer_forward(void *input) { return ") +
            (Nested ? "**(uint16_t **)input; }\n" : "*(uint16_t *)input; }\n");
      Text += R"c(
struct PointerPayload { uint16_t value; };
int main(void) {
  struct PointerPayload value = {0x1234};
  struct PointerPayload *pointer = &value;
)c";
      Text += std::string("  return pointer_entry((uintptr_t)") +
              (Nested ? "&pointer" : "&value") + " ) != 0x1234;\n}\n";
      for (const auto Optimization : {"-O0", "-O2"})
        source_call_execution_test::compileAndRun(
            Text, {Optimization, "-Werror=int-conversion",
                   "-Werror=incompatible-pointer-types", "-fsanitize=undefined",
                   "-fsanitize-trap=all"});
    }
}

TEST(LLVMCSourcePointers, PointerSpellingRetainsSourceABIDepthBoundary) {
  llvm::LLVMContext Context;
  llvm::Module Module("pointer-attribute-depth", Context);
  Module.setDataLayout("e-p:64:64");
  llvm::IRBuilder<> Builder(Context);
  auto *Function = llvm::Function::Create(
      llvm::FunctionType::get(Builder.getVoidTy(), {Builder.getPtrTy()}, false),
      llvm::GlobalValue::ExternalLinkage, "depth_boundary", Module);
  auto &Argument = *Function->getArg(0);
  for (bool Record : {false, true})
    for (unsigned Depth : {16u, 17u, 18u}) {
      SCOPED_TRACE(Record);
      SCOPED_TRACE(Depth);
      auto Type = Record ? NdType::makeNamedRecord("DepthPayload", 0)
                         : NdType::makeInt(2, false);
      std::string Text = "[";
      for (unsigned I = 0; I < Depth; ++I) {
        Type = NdType::makePtr(Type);
        Text += "[\"ptr\",8,false,\"\"],";
      }
      Text += Record ? "[\"record\",0,false,\"DepthPayload\"]]"
                     : "[\"int\",2,false,\"\"]]";
      // The record leaf is checked at its pointer's depth; scalar leaves
      // consume another recursion level. Keep these expectations independent
      // of the implementation's limit expression.
      const bool Accepted = Depth == 16 || (Record && Depth == 17);
      writeLLVMSourcePointerParameter(Argument, Type);
      const auto Restored = readLLVMSourcePointerParameter(Argument);
      ASSERT_EQ(bool(Restored), Accepted);
      if (Restored) {
        auto Leaf = Restored;
        for (unsigned I = 0; I < Depth; ++I) {
          ASSERT_EQ(Leaf->Kind, NdTypeKind::Ptr);
          Leaf = Leaf->Pointee;
          ASSERT_TRUE(Leaf);
        }
        EXPECT_EQ(Leaf->Kind, Record ? NdTypeKind::Struct : NdTypeKind::Int);
        if (Record)
          EXPECT_EQ(Leaf->SourceName, "DepthPayload");
      }
      // Direct attributes must retain the semantic limit too, rather than
      // relying on the writer to reject an unsupported chain first.
      Argument.addAttr(
          llvm::Attribute::get(Context, LLVMSourcePointerParameter, Text));
      EXPECT_EQ(bool(readLLVMSourcePointerParameter(Argument)), Accepted);
    }
}

TEST(LLVMCSourcePointers, MalformedOrChangedPointerCarriersIgnoreSpelling) {
  llvm::LLVMContext Context;
  llvm::Module Module("pointer-attribute-boundary", Context);
  Module.setDataLayout("e-p:64:64-p1:32:32");
  llvm::IRBuilder<> Builder(Context);
  auto *Function = llvm::Function::Create(
      llvm::FunctionType::get(
          Builder.getVoidTy(),
          {Builder.getPtrTy(), Builder.getInt64Ty(), Builder.getPtrTy(1)},
          false),
      llvm::GlobalValue::ExternalLinkage, "boundary", Module);
  const auto Type = NdType::makePtr(NdType::makeInt(2, false));
  writeLLVMSourcePointerParameter(*Function->getArg(0), Type);
  const auto Good =
      Function->getAttributes().getParamAttr(0, LLVMSourcePointerParameter);
  ASSERT_TRUE(readLLVMSourcePointerParameter(*Function->getArg(0)));
  for (unsigned Index : {1u, 2u}) {
    Function->getArg(Index)->addAttr(Good);
    EXPECT_FALSE(readLLVMSourcePointerParameter(*Function->getArg(Index)));
  }
  Module.setDataLayout("e-p:32:32");
  EXPECT_FALSE(readLLVMSourcePointerParameter(*Function->getArg(0)));
  Module.setDataLayout("e-p:64:64");
  for (llvm::StringRef Text :
       {"invalid", "[]", "[[\"ptr\",8,false,\"\"]]",
        "[[\"ptr\",4,false,\"\"],[\"int\",2,false,\"\"]]",
        "[[\"ptr\",8,false,\"\"],[\"int\",3,false,\"\"]]",
        "[[\"ptr\",8,false,\"\"],[\"record\",8,false,\"Record\"]]",
        "[[\"ptr\",8,false,\"\"],[\"record\",0,false,\"bad;name\"]]",
        "[[\"ptr\",8,false,\"\"],[\"function\",0,false,\"\"]]"}) {
    Function->getArg(0)->addAttr(
        llvm::Attribute::get(Context, LLVMSourcePointerParameter, Text));
    EXPECT_FALSE(readLLVMSourcePointerParameter(*Function->getArg(0)))
        << Text.str();
  }
}
} // namespace
