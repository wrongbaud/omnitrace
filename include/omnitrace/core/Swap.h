// Swap.h — derived views over a Source with byte order transforms.
//
// Some dumpers and some SPI/parallel-flash captures store the image with the
// bytes of every 16-bit or 32-bit word reversed. A SwappedSource presents the
// corrected byte stream without copying the image, so every parser and the
// signature scanner work unchanged. Provenance: id() = parent id + "|swap16"
// or "|swap32"; offsets are unchanged.
/// @file Swap.h
/// @brief `SwappedSource` (a word-swapped view of another Source) and
/// `detect_word_swap` (the heuristic that decides whether one is needed).
///
/// `discovery::analyze` runs `detect_word_swap` on every image unless an
/// `ImageViewHook` is supplied, and analyses the swapped view when it fires;
/// docs/formats/word-swap.md documents the thresholds.
#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>

#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"

namespace omnitrace {

/// Word size whose bytes are reversed. Serialized via `swap_kind_name`.
enum class SwapKind : std::uint8_t { None, Swap16, Swap32 };
/// "none", "swap16", "swap32".
const char* swap_kind_name(SwapKind k);

/// The parent Source with the bytes of every complete 16- or 32-bit word
/// reversed. Word alignment is absolute (parent offset 0), so a read never
/// depends on where it starts; a trailing partial word (parent size not a
/// multiple of the word size) is passed through unchanged. Same size and
/// offsets as the parent; `id()` is `parent->id() + "|swap16"` or "|swap32".
class SwappedSource final : public Source {
   public:
    /// View `parent` under `kind` (`SwapKind::None` forwards unchanged).
    SwappedSource(std::shared_ptr<const Source> parent, SwapKind kind);
    std::uint64_t size() const override;
    std::string id() const override;
    /// Reads the covering aligned words from the parent, swaps them, and
    /// copies the requested window out (a stack buffer for reads up to 512 bytes).
    std::size_t read(std::uint64_t off, std::span<std::uint8_t> out) const override;
    // Always returns an empty span: a swapped view cannot be zero-copy mapped.
    /// Always empty: a swapped view cannot be zero-copy mapped, so
    /// `Span::view` returns `nullopt` and callers fall back to `bytes()`/`read()`.
    std::span<const std::uint8_t> map(std::uint64_t off, std::size_t len) const override;
    /// The swap applied.
    SwapKind kind() const { return kind_; }
    /// The unswapped Source.
    const std::shared_ptr<const Source>& parent() const { return parent_; }

   private:
    std::shared_ptr<const Source> parent_;
    SwapKind kind_;
};

/// Result of `detect_word_swap`.
struct SwapDetection {
    SwapKind kind = SwapKind::None;  ///< `None` when the raw view should be used.
    std::uint8_t confidence = 0;     ///< 0-100; 0 when `kind == None`.
    std::string evidence;  ///< Why, e.g. "swap32 structure score 96 is 12x the raw view's 8: ...".
                           ///< Recorded as the "image-word-swapped" diagnostic.
};

// Heuristic: sample the Span (bounded work, at most `budget` bytes examined)
// and decide whether known magics / printable ASCII runs are far more common
// under a 16- or 32-bit word swap than in the raw bytes. Never claims a swap
// when the raw view already yields findings.
/// Sample at most `budget` bytes of `span` in 64 KiB windows and score the
/// raw, swap16 and swap32 renderings by well-known magics and ARM code words
/// (structure), falling back to printable-ASCII runs (text). A swap is chosen
/// only when the raw view has no unambiguous magic hit and the winning score
/// is at least twice the raw view's and at least one strong hit's worth.
/// Bounded work; never fails (an empty span yields `None`).
SwapDetection detect_word_swap(const Span& span, std::uint64_t budget = 64u << 20);

}  // namespace omnitrace
