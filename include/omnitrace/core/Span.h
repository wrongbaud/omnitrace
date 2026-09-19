// Span.h — the one bounds-checked reader.
//
// Design guardrail: ALL access to image bytes goes through Span. No code outside
// core/ does raw pointer + length arithmetic on evidence. Every accessor returns
// std::optional and is range-checked, so an attacker-controlled offset or size in
// a header yields std::nullopt, never an out-of-bounds read.
//
// A Span is a window [base, base+len) over a Source. Offsets passed to accessors
// are relative to the Span. sub() narrows; absolute() converts back to Source
// coordinates for provenance.
/// @file Span.h
/// @brief `Span`, the bounds-checked window every parser reads evidence through
/// (docs/ARCHITECTURE.md rule 1), and `ByteRange`.
///
/// Every check is written as `off > len || n > len - off`, so an offset near
/// `UINT64_MAX` fails the comparison instead of overflowing an addition.
/// Copying a Span is cheap (a shared_ptr and two integers) and the copy keeps
/// the Source alive.
#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "omnitrace/core/Endian.h"
#include "omnitrace/core/Source.h"

namespace omnitrace {

/// A half-open byte range `[offset, offset+length)` in Source coordinates.
struct ByteRange {
    std::uint64_t offset = 0;  ///< First byte.
    std::uint64_t length = 0;  ///< Byte count; `end()` is the first byte after.
    /// `offset + length`, not overflow-checked: only call on ranges a Span produced.
    std::uint64_t end() const { return offset + length; }
};

/// Read-only window `[base, base+len)` over a `Source`. All offsets given to
/// accessors are relative to the window; `absolute()` converts back.
///
/// Error behaviour: every accessor is range-checked and returns
/// `std::nullopt` (or 0 / false / an empty Span) on overrun; nothing throws.
/// Lifetime: the Span holds a `shared_ptr<const Source>`, so the Source, and
/// any `std::span` that `view()` handed out, stay valid for as long as this
/// Span or any other owner of the Source exists. A `view()` result must not
/// outlive the last such owner.
///
/// ```cpp
/// // Parse a SquashFS superblock at the start of `fs`.
/// const omnitrace::Span sb = fs.sub(0, 96);
/// const auto magic = sb.at<std::uint32_t>(0, omnitrace::Endian::Little);
/// const auto block_size = sb.at<std::uint32_t>(12, omnitrace::Endian::Little);
/// if (!magic || !block_size) return std::nullopt;            // truncated header
/// static constexpr std::uint8_t kMagic[] = {'h', 's', 'q', 's'};
/// if (!fs.matches_at(0, kMagic)) return std::nullopt;
/// const omnitrace::Span data = fs.sub(96);                   // rest of the image
/// if (auto v = data.view(0, 4096)) use(*v);                  // zero-copy when mappable
/// else if (auto b = data.bytes(0, 4096)) use(*b);            // copy otherwise
/// ```
class Span {
   public:
    /// An empty Span with no Source: `size()` is 0 and every read fails.
    Span() = default;
    /// Window `[base, base+len)` over `src`, clamped so it never describes
    /// bytes the Source does not have (base past the end becomes empty).
    Span(std::shared_ptr<const Source> src, std::uint64_t base, std::uint64_t len);
    /// The whole Source (a null `src` gives an empty Span).
    static Span whole(std::shared_ptr<const Source> src);

    /// Bytes in the window.
    std::uint64_t size() const { return len_; }
    /// True when `size()` is 0.
    bool empty() const { return len_ == 0; }
    /// Window start in Source coordinates.
    std::uint64_t base() const { return base_; }
    /// The underlying Source (may be null for a default-constructed Span).
    const std::shared_ptr<const Source>& source() const { return src_; }
    /// `Source::id()` for provenance, or "" when there is no Source.
    std::string source_id() const { return src_ ? src_->id() : std::string{}; }
    // Absolute Source offset of a Span-relative offset.
    /// Source offset of a window-relative offset (`base() + rel`, unchecked).
    std::uint64_t absolute(std::uint64_t rel) const { return base_ + rel; }
    /// `{base(), size()}` in Source coordinates.
    ByteRange range() const { return {base_, len_}; }

    // Narrow to [off, off+len). Clamps len to what is available; returns an empty
    // Span if off is out of range.
    /// Narrow to `[off, off+len)`. `len` is clamped to what is available; an
    /// `off` past the end yields an empty Span positioned at the end that still
    /// carries the Source, so `source_id()` keeps working on the result.
    Span sub(std::uint64_t off, std::uint64_t len) const;
    /// Narrow to `[off, size())`.
    Span sub(std::uint64_t off) const { return sub(off, len_ > off ? len_ - off : 0); }

    // Integer at `off` in the given byte order. nullopt on overrun.
    /// Integer of type `T` at `off` in byte order `e`; `nullopt` on overrun.
    /// @tparam T an integral type (`std::uint16_t`, `std::int64_t`, ...).
    template <class T>
    std::optional<T> at(std::uint64_t off, Endian e) const {
        std::uint8_t buf[sizeof(T)];
        if (read(off, std::span<std::uint8_t>(buf, sizeof(T))) != sizeof(T)) return std::nullopt;
        return load_int<T>(buf, e);
    }
    /// One byte at `off`; `nullopt` on overrun.
    std::optional<std::uint8_t> u8(std::uint64_t off) const {
        return at<std::uint8_t>(off, Endian::Little);
    }

    // Copy n bytes at off into a vector. nullopt on overrun.
    /// Copy `n` bytes at `off` into a new vector; `nullopt` if `[off, off+n)`
    /// is not inside the window or the Source reads short. `n == 0` gives an
    /// empty vector. Allocates `n` bytes, so bound `n` by a Limits field first.
    std::optional<std::vector<std::uint8_t>> bytes(std::uint64_t off, std::size_t n) const;
    // Zero-copy view of n bytes at off, if the Source supports mapping. nullopt
    // on overrun OR when mapping is unavailable; callers then use bytes().
    /// Zero-copy view of `n` bytes at `off`. `nullopt` on overrun *or* when the
    /// Source cannot map (`SwappedSource`); callers then use `bytes()` or
    /// `read()`. The returned span is valid while the Source lives.
    std::optional<std::span<const std::uint8_t>> view(std::uint64_t off, std::size_t n) const;
    // Copy up to out.size() bytes at off; returns bytes copied (short at end).
    /// Copy up to `out.size()` bytes at `off` into a caller buffer.
    /// @return bytes copied: short at the end of the window, 0 when `off` is
    /// outside it, `out` is empty or there is no Source.
    std::size_t read(std::uint64_t off, std::span<std::uint8_t> out) const;
    // True if pattern occurs exactly at off.
    /// True when `pattern` occurs exactly at `off` (false if it would run past
    /// the end; true for an empty pattern inside the window).
    bool matches_at(std::uint64_t off, std::span<const std::uint8_t> pattern) const;
    // NUL-terminated or fixed-width string at off (max n bytes), stops at first NUL.
    /// String at `off`: at most `n` bytes, stopping at the first NUL. Reads
    /// only what the window has, so a fixed-width field that runs past a
    /// truncated image comes back shorter rather than failing; `nullopt` only
    /// when `off` is past the end. The result is raw bytes: pass it through
    /// `sanitize_utf8()` before it leaves the process.
    std::optional<std::string> cstring(std::uint64_t off, std::size_t n) const;

   private:
    std::shared_ptr<const Source> src_;
    std::uint64_t base_ = 0;
    std::uint64_t len_ = 0;
};

}  // namespace omnitrace
