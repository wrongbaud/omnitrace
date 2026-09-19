// Hash.h — MD5, SHA-1, SHA-256 in one pass (OpenSSL EVP).
#pragma once
#include <cstdint>
#include <memory>
#include <span>
#include <string>

#include "omnitrace/core/Status.h"

namespace omnitrace {

class Span;

struct Digests {
    std::string md5;     // lowercase hex, 32 chars
    std::string sha1;    // 40 chars
    std::string sha256;  // 64 chars
    std::uint64_t bytes = 0;
    bool empty() const { return sha256.empty(); }
};

class Hasher {
   public:
    Hasher();
    ~Hasher();
    Hasher(const Hasher&) = delete;
    Hasher& operator=(const Hasher&) = delete;
    void update(std::span<const std::uint8_t> data);
    Digests finish();  // resets for reuse
    static Digests of(std::span<const std::uint8_t> data);

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Hash a whole Span in bounded chunks (never maps more than chunk bytes at once).
Digests hash_span(const Span& span, std::size_t chunk = 8u << 20);
Status hash_file(const std::string& path, Digests& out);

}  // namespace omnitrace
