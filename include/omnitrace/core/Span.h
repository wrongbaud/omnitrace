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

struct ByteRange {
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
    std::uint64_t end() const { return offset + length; }
};

class Span {
public:
    Span() = default;
    Span(std::shared_ptr<const Source> src, std::uint64_t base, std::uint64_t len);
    static Span whole(std::shared_ptr<const Source> src);

    std::uint64_t size() const { return len_; }
    bool empty() const { return len_ == 0; }
    std::uint64_t base() const { return base_; }
    const std::shared_ptr<const Source>& source() const { return src_; }
    std::string source_id() const { return src_ ? src_->id() : std::string{}; }
    // Absolute Source offset of a Span-relative offset.
    std::uint64_t absolute(std::uint64_t rel) const { return base_ + rel; }
    ByteRange range() const { return {base_, len_}; }

    // Narrow to [off, off+len). Clamps len to what is available; returns an empty
    // Span if off is out of range.
    Span sub(std::uint64_t off, std::uint64_t len) const;
    Span sub(std::uint64_t off) const { return sub(off, len_ > off ? len_ - off : 0); }

    // Integer at `off` in the given byte order. nullopt on overrun.
    template <class T>
    std::optional<T> at(std::uint64_t off, Endian e) const {
        std::uint8_t buf[sizeof(T)];
        if (read(off, std::span<std::uint8_t>(buf, sizeof(T))) != sizeof(T)) return std::nullopt;
        return load_int<T>(buf, e);
    }
    std::optional<std::uint8_t> u8(std::uint64_t off) const { return at<std::uint8_t>(off, Endian::Little); }

    // Copy n bytes at off into a vector. nullopt on overrun.
    std::optional<std::vector<std::uint8_t>> bytes(std::uint64_t off, std::size_t n) const;
    // Zero-copy view of n bytes at off, if the Source supports mapping. nullopt
    // on overrun OR when mapping is unavailable; callers then use bytes().
    std::optional<std::span<const std::uint8_t>> view(std::uint64_t off, std::size_t n) const;
    // Copy up to out.size() bytes at off; returns bytes copied (short at end).
    std::size_t read(std::uint64_t off, std::span<std::uint8_t> out) const;
    // True if pattern occurs exactly at off.
    bool matches_at(std::uint64_t off, std::span<const std::uint8_t> pattern) const;
    // NUL-terminated or fixed-width string at off (max n bytes), stops at first NUL.
    std::optional<std::string> cstring(std::uint64_t off, std::size_t n) const;

private:
    std::shared_ptr<const Source> src_;
    std::uint64_t base_ = 0;
    std::uint64_t len_ = 0;
};

}  // namespace omnitrace
