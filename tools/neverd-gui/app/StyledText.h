#pragma once

#include "Address.h"

#include <QColor>
#include <QFont>
#include <QJsonArray>
#include <QString>
#include <QTextLayout>
#include <QVector>
#include <functional>
#include <memory>
#include <optional>
#include <utility>

namespace neverd::gui {

/// How a dot sits in a word: a listing's names keep theirs (`.text`,
/// `main.cold`, `RSP.3`), while C splits a member access (`frame.var_8`)
/// and keeps a decimal number (`1.5`) whole.
enum class TokenDots { Join, Split };

/// A run of styled text: character range, role code and the location a name
/// denotes (for navigation).
struct StyledSpan {
  int start = 0;
  int length = 0;
  int role = 0;
  std::optional<Address> address;
};

/// One line of styled text with a lazily built, cached text layout.  Layouts
/// are rebuilt when the font or palette stamp changes.
struct StyledLine {
  QString text;
  QVector<StyledSpan> spans;

  StyledLine() = default;
  /// Copies share text and spans; the layout cache is rebuilt on demand.
  StyledLine(const StyledLine &other) : text(other.text), spans(other.spans) {}
  StyledLine &operator=(const StyledLine &other) {
    text = other.text;
    spans = other.spans;
    layout_.reset();
    stamp_ = 0;
    return *this;
  }
  StyledLine(StyledLine &&) noexcept = default;
  StyledLine &operator=(StyledLine &&) noexcept = default;

  /// Convert worker spans, whose offsets count UTF-8 bytes, to this line's
  /// UTF-16 positions.
  void setFromWorker(const QString &line, const QJsonArray &workerSpans);
  /// Span covering \p position, if any.
  const StyledSpan *spanAt(int position) const;
  /// Identifier-like token around \p position.
  QString tokenAt(int position, TokenDots dots = TokenDots::Join) const;

  using ColorOf = std::function<QColor(int role)>;
  QTextLayout &layout(const QFont &font, quint64 stamp,
                      const ColorOf &colorOf) const;

private:
  mutable std::unique_ptr<QTextLayout> layout_;
  mutable quint64 stamp_ = 0;
};

/// Whole-word occurrences of \p token in \p text.
QVector<int> tokenOccurrences(const QString &text, const QString &token,
                              TokenDots dots = TokenDots::Join);
/// Bounds [first, second) of the identifier-like token around \p position in
/// \p text; an empty range where no token touches it.
std::pair<int, int> tokenRange(const QString &text, int position,
                               TokenDots dots = TokenDots::Join);
bool isTokenCharacter(QChar c);

} // namespace neverd::gui
