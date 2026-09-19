// Hash.cpp — MD5, SHA-1 and SHA-256 computed together in one pass over the
// data (OpenSSL EVP). Spans and files are streamed in bounded chunks.
#include "omnitrace/core/Hash.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <vector>

#include <openssl/evp.h>

#include "omnitrace/core/Span.h"

namespace omnitrace {

namespace {

constexpr std::size_t kFileChunk = 8u << 20;

std::string hex_lower(const unsigned char* p, std::size_t n) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string s;
    s.resize(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        s[2 * i] = kDigits[p[i] >> 4];
        s[2 * i + 1] = kDigits[p[i] & 0x0f];
    }
    return s;
}

// One digest context that can be re-initialised for reuse. A context whose
// algorithm is unavailable in this OpenSSL build (e.g. MD5 under a FIPS
// provider) stays inactive and yields an empty hex string.
struct Digest {
    EVP_MD_CTX* ctx = nullptr;
    const EVP_MD* md = nullptr;
    bool active = false;

    explicit Digest(const EVP_MD* algo) : ctx(EVP_MD_CTX_new()), md(algo) { reset(); }
    ~Digest() { EVP_MD_CTX_free(ctx); }
    Digest(const Digest&) = delete;
    Digest& operator=(const Digest&) = delete;

    void reset() {
        active = ctx != nullptr && md != nullptr && EVP_DigestInit_ex(ctx, md, nullptr) == 1;
    }
    void update(const std::uint8_t* p, std::size_t n) {
        if (active && n != 0 && EVP_DigestUpdate(ctx, p, n) != 1) active = false;
    }
    std::string finish() {
        if (!active) return {};
        unsigned char buf[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        if (EVP_DigestFinal_ex(ctx, buf, &len) != 1) return {};
        return hex_lower(buf, len);
    }
};

}  // namespace

struct Hasher::Impl {
    Digest md5{EVP_md5()};
    Digest sha1{EVP_sha1()};
    Digest sha256{EVP_sha256()};
    std::uint64_t bytes = 0;
};

Hasher::Hasher() : impl_(std::make_unique<Impl>()) {}
Hasher::~Hasher() = default;

void Hasher::update(std::span<const std::uint8_t> data) {
    impl_->md5.update(data.data(), data.size());
    impl_->sha1.update(data.data(), data.size());
    impl_->sha256.update(data.data(), data.size());
    impl_->bytes += data.size();
}

Digests Hasher::finish() {
    Digests d;
    d.md5 = impl_->md5.finish();
    d.sha1 = impl_->sha1.finish();
    d.sha256 = impl_->sha256.finish();
    d.bytes = impl_->bytes;
    impl_->md5.reset();
    impl_->sha1.reset();
    impl_->sha256.reset();
    impl_->bytes = 0;
    return d;
}

Digests Hasher::of(std::span<const std::uint8_t> data) {
    Hasher h;
    h.update(data);
    return h.finish();
}

Digests hash_span(const Span& span, std::size_t chunk) {
    if (chunk == 0) chunk = 1;
    Hasher h;
    const std::uint64_t total = span.size();
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(std::min<std::uint64_t>(chunk, total)));
    std::uint64_t off = 0;
    while (off < total) {
        const std::size_t n = span.read(off, std::span<std::uint8_t>(buf.data(), buf.size()));
        if (n == 0) break;  // Source refused to read further; digest what we have
        h.update(std::span<const std::uint8_t>(buf.data(), n));
        off += n;
    }
    return h.finish();
}

Status hash_file(const std::string& path, Digests& out) {
    std::error_code ec;
    const auto st = std::filesystem::status(path, ec);
    if (ec || !std::filesystem::is_regular_file(st)) return Status::fail("hash-file-not-regular");
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if (!f) return Status::fail("hash-file-open");
    Hasher h;
    std::vector<char> buf(kFileChunk);
    for (;;) {
        f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = f.gcount();
        if (got > 0)
            h.update(std::span<const std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(buf.data()), static_cast<std::size_t>(got)));
        if (f.bad()) return Status::fail("hash-file-read");
        if (f.eof()) break;
        if (f.fail()) return Status::fail("hash-file-read");
    }
    out = h.finish();
    return Status::success();
}

}  // namespace omnitrace
