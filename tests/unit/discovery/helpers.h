// helpers.h — shared test helpers for the discovery layer tests.
#pragma once
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#include <zlib.h>

#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/discovery/Signature.h"

namespace omnitrace::discovery::test {

using Bytes = std::vector<std::uint8_t>;

inline Span span_of(Bytes b, const std::string& label = "test") {
    return Span::whole(std::make_shared<MemorySource>(std::move(b), label));
}

// A Source that refuses to map, so Span::view fails and callers must read().
class NoMapSource final : public Source {
   public:
    explicit NoMapSource(Bytes b) : bytes_(std::move(b)) {}
    std::uint64_t size() const override { return bytes_.size(); }
    std::string id() const override { return "nomap"; }
    std::size_t read(std::uint64_t off, std::span<std::uint8_t> out) const override {
        if (off >= bytes_.size()) return 0;
        const std::size_t n =
            std::min<std::size_t>(out.size(), bytes_.size() - static_cast<std::size_t>(off));
        std::memcpy(out.data(), bytes_.data() + off, n);
        return n;
    }
    std::span<const std::uint8_t> map(std::uint64_t, std::size_t) const override { return {}; }

   private:
    Bytes bytes_;
};

inline void put_u16le(Bytes& b, std::size_t off, std::uint16_t v) {
    b[off] = static_cast<std::uint8_t>(v & 0xFF);
    b[off + 1] = static_cast<std::uint8_t>(v >> 8);
}
inline void put_u32le(Bytes& b, std::size_t off, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i)
        b[off + i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF);
}
inline void put_u64le(Bytes& b, std::size_t off, std::uint64_t v) {
    for (std::size_t i = 0; i < 8; ++i)
        b[off + i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF);
}
inline void put_u16be(Bytes& b, std::size_t off, std::uint16_t v) {
    b[off] = static_cast<std::uint8_t>(v >> 8);
    b[off + 1] = static_cast<std::uint8_t>(v & 0xFF);
}
inline void put_u32be(Bytes& b, std::size_t off, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i)
        b[off + i] = static_cast<std::uint8_t>((v >> (8 * (3 - i))) & 0xFF);
}
inline void put_u64be(Bytes& b, std::size_t off, std::uint64_t v) {
    for (std::size_t i = 0; i < 8; ++i)
        b[off + i] = static_cast<std::uint8_t>((v >> (8 * (7 - i))) & 0xFF);
}
inline void put_bytes(Bytes& b, std::size_t off, const char* s) {
    std::memcpy(b.data() + off, s, std::strlen(s));
}

// Independent CRC oracle: zlib's crc32 re-parameterised. init/xorout as in
// src/discovery/crc32.h.
inline std::uint32_t oracle_crc32(const std::uint8_t* p, std::size_t n, std::uint32_t init,
                                  std::uint32_t xorout) {
    const auto reg =
        static_cast<std::uint32_t>(::crc32(init ^ 0xFFFFFFFFu, p, static_cast<uInt>(n))) ^
        0xFFFFFFFFu;
    return reg ^ xorout;
}
inline std::uint32_t crc_zlib(const Bytes& b, std::size_t off, std::size_t n) {
    return oracle_crc32(b.data() + off, n, 0xFFFFFFFFu, 0xFFFFFFFFu);
}
inline std::uint32_t crc_jffs2(const Bytes& b, std::size_t off, std::size_t n) {
    return oracle_crc32(b.data() + off, n, 0u, 0u);
}
inline std::uint32_t crc_ubi(const Bytes& b, std::size_t off, std::size_t n) {
    return oracle_crc32(b.data() + off, n, 0xFFFFFFFFu, 0u);
}

inline std::string fixture_path(const std::string& name) {
    return std::string(OMNITRACE_TEST_DATA_DIR) + "/out/" + name;
}
inline bool fixture_exists(const std::string& name) {
    return std::filesystem::exists(fixture_path(name));
}

// Signature set holding only the builtin signatures whose name is in `names`.
inline SignatureSet only(std::initializer_list<const char*> names) {
    SignatureSet s;
    for (const Signature& sig : SignatureSet::builtin().signatures)
        for (const char* n : names)
            if (sig.name == n) s.signatures.push_back(sig);
    return s;
}

inline const Finding* find_at(const std::vector<Finding>& v, std::uint64_t off,
                              const std::string& format = {}) {
    for (const Finding& f : v)
        if (f.offset == off && (format.empty() || f.format == format)) return &f;
    return nullptr;
}

}  // namespace omnitrace::discovery::test
