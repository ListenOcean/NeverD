#include "../../lib/loader/ReadOnlyBytesIndex.h"
#include "gtest/gtest.h"

#include "neverd/loader/BinaryImage.h"
#include "neverd/loader/ReadOnlyBytes.h"
#include "neverd/support/BinaryEncoding.h"

namespace neverd {
namespace {
constexpr va_t TextVA = 0x401000;
constexpr va_t ReadVA = TextVA + 0x10;
constexpr va_t OperandVA = ReadVA + 1;
constexpr va_t TargetVA = 0x402020;

BinaryImage codeImage() {
  BinaryImage Image;
  Image.Arch = Arch::X86;
  Image.Bits = Bitness::Bits32;
  Image.Format = BinaryFormat::COFF;
  Image.Base = 0x400000;
  Segment Code;
  Code.VA = TextVA;
  Code.Flags = SegmentFlags::Readable | SegmentFlags::Executable;
  Code.Data.resize(0x100, 0xcc);
  Code.Data[0x10] = 0xb8;
  writeLE<uint32_t>(Code.Data.data() + 0x11, TargetVA);
  Code.Data[0x15] = 0xc3;
  Code.Size = Code.FileSz = Code.Data.size();
  Section Section;
  Section.VA = Code.VA;
  Section.Flags = Code.Flags;
  Section.Size = Section.FileSz = Code.Size;
  Image.Segments.push_back(std::move(Code));
  Image.Sections.push_back(std::move(Section));
  Image.BaseRelocations.push_back({OperandVA, 3});
  return Image;
}

TEST(ImmutableImageScalar, ELFRelroSectionKeepsScalarsButNotRelocatedPointers) {
  auto Image = codeImage();
  Image.Format = BinaryFormat::ELF;
  Image.Arch = Arch::AArch64;
  Image.Bits = Bitness::Bits64;
  Image.BaseRelocations.clear();
  Image.Segments.front().Flags =
      SegmentFlags::Readable | SegmentFlags::Writable;
  Image.Sections.front().Flags = Image.Segments.front().Flags;
  Image.Sections.front().Name = ".data.rel.ro";
  EXPECT_EQ(readImmutableImageScalar(Image, ReadVA, 1), 0xb8u);
  Image.BaseRelocations.push_back({ReadVA - 3, 10});
  EXPECT_FALSE(readImmutableImageScalar(Image, ReadVA, 1));
  Image.BaseRelocations.clear();
  Image.Sections.front().Name = ".data";
  EXPECT_FALSE(readImmutableImageScalar(Image, ReadVA, 1));
  Image.Sections.front().Name = ".data.rel.ro";
  Image.Sections.push_back(Image.Sections.front());
  EXPECT_FALSE(readImmutableImageScalar(Image, ReadVA, 1));
}

TEST(ImmutablePE32Code, IndexedAndOrdinaryReadersKeepEveryFixupBoundary) {
  for (unsigned Mutation = 0; Mutation != 29; ++Mutation) {
    SCOPED_TRACE(Mutation);
    auto Image = codeImage();
    RelocatedAddressField Field;
    Field.Width = 4;
    Field.TargetVA = TargetVA;
    Field.EncodedValue = TargetVA;
    bool Expected = Mutation <= 5 || Mutation == 10 || Mutation == 17 ||
                    Mutation == 18 || Mutation == 25;
    switch (Mutation) {
    case 1:
      Image.BaseRelocations.insert(Image.BaseRelocations.begin(),
                                   {ReadVA + 0x40, 3});
      Image.BaseRelocations.push_back({ReadVA - 8, 3});
      break;
    case 2:
      Image.BaseRelocations.push_back({ReadVA, 0});
      break;
    case 3:
      Image.CodeAddressRelocOperands.emplace(OperandVA, Field);
      break;
    case 4:
      Image.DataAddressRelocOperands.emplace(OperandVA, Field);
      break;
    case 5:
      Image.CodeAddressRelocOperands.emplace(OperandVA, Field);
      Image.DataAddressRelocOperands.emplace(OperandVA, Field);
      break;
    case 6:
      Image.BaseRelocations.clear();
      Image.CodeAddressRelocOperands.emplace(OperandVA, Field);
      break;
    case 7:
      Image.BaseRelocations.push_back(Image.BaseRelocations.front());
      break;
    case 8:
      Image.BaseRelocations.front().Type = 10;
      break;
    case 9:
      Image.BaseRelocations.push_back({ReadVA - 3, 3});
      break;
    case 10:
      Image.BaseRelocations.push_back({ReadVA - 4, 3});
      break;
    case 11:
      ++Field.TargetVA;
      Image.CodeAddressRelocOperands.emplace(OperandVA, Field);
      break;
    case 12:
      Field.Width = 8;
      Image.CodeAddressRelocOperands.emplace(OperandVA, Field);
      break;
    case 13:
      Field.PCRelativeFromInstructionEnd = true;
      Image.CodeAddressRelocOperands.emplace(OperandVA, Field);
      break;
    case 14:
      Field.Kind = RelocatedAddressFieldKind::I386ELFGOTOFF;
      Image.CodeAddressRelocOperands.emplace(OperandVA, Field);
      break;
    case 15:
      Image.CodeAddressRelocOperands.emplace(OperandVA + 1, Field);
      break;
    case 16:
    case 17:
      Field.Width = 255;
      Image.CodeAddressRelocOperands.emplace(
          ReadVA - (Mutation == 16 ? 254 : 255), Field);
      break;
    case 18:
      Field.Width = 0;
      Image.CodeAddressRelocOperands.emplace(ReadVA, Field);
      break;
    case 19:
      Image.CodePtrRelocSlots.insert(ReadVA - 3);
      break;
    case 20:
      Image.DataPtrRelocSlots.insert(ReadVA - 3);
      break;
    case 21:
      Image.RelCodeRelocSlots.insert(ReadVA - 3);
      break;
    case 22:
      Image.RelDataPtrRelocSlots.insert(ReadVA - 3);
      break;
    case 23:
      Image.RuntimeCallablePointerSlots.push_back({ReadVA - 3});
      break;
    case 24:
    case 25: {
      RelocationEntry Entry;
      Entry.Address = ReadVA - (Mutation == 24 ? 7 : 8);
      Image.Relocations.push_back(Entry);
      break;
    }
    case 26:
      Image.Segments.front().Flags =
          Image.Segments.front().Flags | SegmentFlags::Writable;
      break;
    case 27:
      Image.Segments.push_back(Image.Segments.front());
      break;
    case 28:
      Image.Segments.front().FileSz = 0x15;
      break;
    default:
      break;
    }
    const auto Ordinary =
        readImmutablePE32CodeBytes(Image, ReadVA, 6, {OperandVA});
    size_t Work = 0;
    IndexedPE32CodeBytes Index(Image, Work, 10000);
    const auto Indexed = Index.read(ReadVA, 6, {OperandVA});
    EXPECT_EQ(Ordinary.has_value(), Expected);
    EXPECT_EQ(Indexed, Ordinary);
    EXPECT_GT(Work, 0u);
    if (Expected) {
      ASSERT_TRUE(Indexed);
      EXPECT_EQ(*Indexed,
                (std::vector<uint8_t>{0xb8, 0x20, 0x20, 0x40, 0, 0xc3}));
    }
  }
}

TEST(ImmutableScalar, ScalarBitsDoNotGrantPointerIdentity) {
  auto Image = codeImage();
  Image.BaseRelocations.clear();
  Image.Arch = Arch::X64;
  Image.Bits = Bitness::Bits64;
  for (uint32_t Size : {1, 2, 4, 8}) {
    writeLE<uint64_t>(Image.Segments.front().Data.data() + 0x40,
                      UINT64_C(0xfedcba9876543210));
    EXPECT_EQ(readImmutableImageScalar(Image, TextVA + 0x40, Size),
              UINT64_C(0xfedcba9876543210) & (UINT64_MAX >> ((8 - Size) * 8)));
  }
  writeLE<uint64_t>(Image.Segments.front().Data.data() + 0x40, TextVA);
  EXPECT_FALSE(readImmutableImageScalar(Image, TextVA + 0x40, 8));
  EXPECT_EQ(readImmutableImageScalar(Image, TextVA + 0x40, 4), TextVA);
  EXPECT_FALSE(readImmutableImageScalar(Image, TextVA + 0x40, 0));
  EXPECT_FALSE(readImmutableImageScalar(Image, TextVA + 0x40, 9));
  Image.BaseRelocations.push_back({TextVA + 0x42, 3});
  EXPECT_FALSE(readImmutableImageScalar(Image, TextVA + 0x40, 4));
}

TEST(ImmutableScalar, BudgetChargesTheInventoryBeforeARead) {
  auto Image = codeImage();
  Image.BaseRelocations.clear();
  size_t Remaining = 10000;
  ASSERT_EQ(readImmutableImageScalar(Image, ReadVA, 1, &Remaining), 0xb8u);
  const size_t Required = 10000 - Remaining;
  ASSERT_GT(Required, 0u);
  for (size_t Budget : {size_t{0}, Required - 1, Required}) {
    Remaining = Budget;
    EXPECT_EQ(
        readImmutableImageScalar(Image, ReadVA, 1, &Remaining).has_value(),
        Budget == Required);
    EXPECT_EQ(Remaining, Budget == Required ? 0 : Budget);
  }
  // An unrelated fixup still contributes to the cold-query work. The failed
  // reservation must leave room for the caller's independent arithmetic.
  Image.BaseRelocations.push_back({ReadVA + 0x40, 3});
  Remaining = Required;
  EXPECT_FALSE(readImmutableImageScalar(Image, ReadVA, 1, &Remaining));
  EXPECT_EQ(Remaining, Required);
  ++Remaining;
  EXPECT_EQ(readImmutableImageScalar(Image, ReadVA, 1, &Remaining), 0xb8u);
  EXPECT_EQ(Remaining, 0u);
}

TEST(ImmutableScalar, WideOperandFixupsCannotSupplyStableBytes) {
  for (bool CodeOperand : {false, true})
    for (uint8_t Width : {8, 16, UINT8_MAX}) {
      auto Image = codeImage();
      Image.BaseRelocations.clear();
      RelocatedAddressField Field;
      Field.Width = Width;
      auto &Operands = CodeOperand ? Image.CodeAddressRelocOperands
                                   : Image.DataAddressRelocOperands;
      // The field starts more than one pointer width before the read but its
      // final byte still changes that byte when relocated. Malformed wide
      // metadata is not permission to freeze the file's initial contents.
      Operands.emplace(ReadVA - (Width - 1), Field);
      EXPECT_FALSE(readImmutableCodeBytes(Image, ReadVA, 1));
      EXPECT_FALSE(readImmutableImageScalar(Image, ReadVA, 1));
      Operands.clear();
      Operands.emplace(ReadVA - Width, Field);
      EXPECT_EQ(readImmutableImageScalar(Image, ReadVA, 1), 0xb8u);
    }
}

TEST(ImmutablePE32Code, IndexedQueriesChargeColdAndRepeatedWork) {
  const auto Image = codeImage();
  size_t Required = 0;
  {
    IndexedPE32CodeBytes Index(Image, Required, 10000);
    ASSERT_TRUE(Index.read(ReadVA, 6, {OperandVA}));
  }
  for (size_t Limit : {size_t{0}, Required - 1, Required}) {
    size_t Work = 0;
    IndexedPE32CodeBytes Index(Image, Work, Limit);
    EXPECT_EQ(Index.read(ReadVA, 6, {OperandVA}).has_value(),
              Limit == Required);
    EXPECT_EQ(Work, Limit);
    EXPECT_FALSE(Index.read(ReadVA, 6, {OperandVA}));
  }
  size_t Work = 0;
  IndexedPE32CodeBytes Index(Image, Work, 10000);
  ASSERT_TRUE(Index.read(ReadVA, 6, {OperandVA}));
  const auto Before = Work;
  EXPECT_TRUE(Index.read(ReadVA, 6, {OperandVA}));
  EXPECT_GT(Work, Before);
  EXPECT_FALSE(Index.read(ReadVA, 6, {OperandVA, OperandVA}));
  EXPECT_FALSE(Index.read(ReadVA, 6, {ReadVA - 1}));
  EXPECT_FALSE(Index.read(ReadVA, 0, {}));
  EXPECT_FALSE(Index.read(UINT64_MAX, 6, {}));
}
} // namespace
} // namespace neverd
