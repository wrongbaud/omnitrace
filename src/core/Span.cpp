// Span.cpp — the bounds-checked window over a Source.
//
// Every check is written as `off > len || n > len - off` so that no addition
// can overflow: an attacker-controlled offset near UINT64_MAX simply fails the
// first comparison.
#include "omnitrace/core/Span.h"

#include <algorithm>
#include <cstring>

namespace omnitrace {

namespace {

// True when [off, off+n) lies inside [0, len). Overflow-safe.
bool in_range(std::uint64_t len, std::uint64_t off, std::uint64_t n) {
    return off <= len && n <= len - off;
}

}  // namespace

Span::Span(std::shared_ptr<const Source> src, std::uint64_t base, std::uint64_t len)
    : src_(std::move(src)), base_(base), len_(len) {
    // Clamp to the source so a Span can never describe bytes that do not exist.
    const std::uint64_t ssize = src_ ? src_->size() : 0;
    if (base_ > ssize) base_ = ssize;
    len_ = std::min(len_, ssize - base_);
}

Span Span::whole(std::shared_ptr<const Source> src) {
    const std::uint64_t n = src ? src->size() : 0;
    return Span(std::move(src), 0, n);
}

Span Span::sub(std::uint64_t off, std::uint64_t len) const {
    if (off > len_) {
        // Out of range: an empty window at the end, keeping the source so
        // provenance (source_id) still works on the result.
        return Span(src_, base_ + len_, 0);
    }
    const std::uint64_t n = std::min(len, len_ - off);
    return Span(src_, base_ + off, n);
}

std::optional<std::vector<std::uint8_t>> Span::bytes(std::uint64_t off, std::size_t n) const {
    if (!in_range(len_, off, n)) return std::nullopt;
    std::vector<std::uint8_t> out(n);
    if (n == 0) return out;
    if (read(off, std::span<std::uint8_t>(out.data(), out.size())) != n) return std::nullopt;
    return out;
}

std::optional<std::span<const std::uint8_t>> Span::view(std::uint64_t off, std::size_t n) const {
    if (!in_range(len_, off, n)) return std::nullopt;
    if (n == 0) return std::span<const std::uint8_t>{};
    if (!src_) return std::nullopt;
    auto m = src_->map(base_ + off, n);
    if (m.size() != n) return std::nullopt;
    return m;
}

std::size_t Span::read(std::uint64_t off, std::span<std::uint8_t> out) const {
    if (!src_ || off >= len_ || out.empty()) return 0;
    const std::uint64_t avail = len_ - off;
    const std::uint64_t n64 = std::min<std::uint64_t>(avail, out.size());
    return src_->read(base_ + off, out.first(static_cast<std::size_t>(n64)));
}

bool Span::matches_at(std::uint64_t off, std::span<const std::uint8_t> pattern) const {
    if (!in_range(len_, off, pattern.size())) return false;
    if (pattern.empty()) return true;
    if (auto v = view(off, pattern.size())) {
        return std::memcmp(v->data(), pattern.data(), pattern.size()) == 0;
    }
    // Source cannot map: compare through a bounded stack buffer.
    std::uint8_t buf[256];
    std::size_t done = 0;
    while (done < pattern.size()) {
        const std::size_t chunk = std::min(sizeof(buf), pattern.size() - done);
        if (read(off + done, std::span<std::uint8_t>(buf, chunk)) != chunk) return false;
        if (std::memcmp(buf, pattern.data() + done, chunk) != 0) return false;
        done += chunk;
    }
    return true;
}

std::optional<std::string> Span::cstring(std::uint64_t off, std::size_t n) const {
    if (off > len_) return std::nullopt;
    // A fixed-width field may extend past the end of a truncated image; read
    // what is there rather than allocating `n` bytes for a hostile n.
    const std::uint64_t limit = std::min<std::uint64_t>(n, len_ - off);
    std::string out;
    std::uint8_t buf[256];
    std::uint64_t done = 0;
    while (done < limit) {
        const std::size_t chunk =
            static_cast<std::size_t>(std::min<std::uint64_t>(sizeof(buf), limit - done));
        const std::size_t got = read(off + done, std::span<std::uint8_t>(buf, chunk));
        if (got == 0) break;
        const void* nul = std::memchr(buf, 0, got);
        if (nul != nullptr) {
            const std::size_t upto =
                static_cast<std::size_t>(static_cast<const std::uint8_t*>(nul) - buf);
            out.append(reinterpret_cast<const char*>(buf), upto);
            return out;
        }
        out.append(reinterpret_cast<const char*>(buf), got);
        done += got;
        if (got < chunk) break;
    }
    return out;
}

}  // namespace omnitrace
