// Swap.h — derived views over a Source with byte order transforms.
//
// Some dumpers and some SPI/parallel-flash captures store the image with the
// bytes of every 16-bit or 32-bit word reversed. A SwappedSource presents the
// corrected byte stream without copying the image, so every parser and the
// signature scanner work unchanged. Provenance: id() = parent id + "|swap16"
// or "|swap32"; offsets are unchanged.
#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>

#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"

namespace omnitrace {

enum class SwapKind : std::uint8_t { None, Swap16, Swap32 };
const char* swap_kind_name(SwapKind k);

class SwappedSource final : public Source {
   public:
    SwappedSource(std::shared_ptr<const Source> parent, SwapKind kind);
    std::uint64_t size() const override;
    std::string id() const override;
    std::size_t read(std::uint64_t off, std::span<std::uint8_t> out) const override;
    // Always returns an empty span: a swapped view cannot be zero-copy mapped.
    std::span<const std::uint8_t> map(std::uint64_t off, std::size_t len) const override;
    SwapKind kind() const { return kind_; }
    const std::shared_ptr<const Source>& parent() const { return parent_; }

   private:
    std::shared_ptr<const Source> parent_;
    SwapKind kind_;
};

struct SwapDetection {
    SwapKind kind = SwapKind::None;
    std::uint8_t confidence = 0;  // 0-100
    std::string evidence;  // e.g. "31 known magics and 412 ASCII runs appear only under swap32"
};

// Heuristic: sample the Span (bounded work, at most `budget` bytes examined)
// and decide whether known magics / printable ASCII runs are far more common
// under a 16- or 32-bit word swap than in the raw bytes. Never claims a swap
// when the raw view already yields findings.
SwapDetection detect_word_swap(const Span& span, std::uint64_t budget = 64u << 20);

}  // namespace omnitrace
