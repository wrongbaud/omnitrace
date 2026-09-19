// Hash.h — MD5, SHA-1, SHA-256 in one pass (OpenSSL EVP).
/// @file Hash.h
/// @brief `Digests`, the streaming `Hasher`, and the two helpers that hash a
/// `Span` or a host file.
#pragma once
#include <cstdint>
#include <memory>
#include <span>
#include <string>

#include "omnitrace/core/Status.h"

namespace omnitrace {

class Span;

/// The three digests every evidence object carries. Hex is lowercase. A digest
/// whose algorithm the OpenSSL build refuses (MD5 under a FIPS provider) is an
/// empty string; the others are still filled.
struct Digests {
    std::string md5;          ///< 32 hex chars, or empty.
    std::string sha1;         ///< 40 hex chars, or empty.
    std::string sha256;       ///< 64 hex chars, or empty.
    std::uint64_t bytes = 0;  ///< Bytes hashed.
    /// True when nothing was hashed (keyed on `sha256`).
    bool empty() const { return sha256.empty(); }
};

/// Streaming MD5 + SHA-1 + SHA-256 over one pass of the data. Neither copyable
/// nor movable (it owns OpenSSL contexts); not thread-safe.
class Hasher {
   public:
    /// Fresh contexts.
    Hasher();
    /// Frees the contexts.
    ~Hasher();
    /// Not copyable.
    Hasher(const Hasher&) = delete;
    /// Not assignable.
    Hasher& operator=(const Hasher&) = delete;
    /// Feed bytes.
    void update(std::span<const std::uint8_t> data);
    /// Finish and return the digests, then reset so the Hasher can be reused.
    Digests finish();  // resets for reuse
    /// One-shot digests of an in-memory buffer.
    static Digests of(std::span<const std::uint8_t> data);

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Hash a whole Span in bounded chunks (never maps more than chunk bytes at once).
/// Digests of a whole Span, read through `Span::read` in `chunk`-byte pieces
/// so at most `chunk` bytes are resident. Stops at the first short read and
/// digests what was read (`Digests::bytes` says how much).
Digests hash_span(const Span& span, std::size_t chunk = 8u << 20);
/// Digests of a host file (the CLI's `hash` command and `--copy-image`
/// verification). Fails with "hash-file-not-regular", "hash-file-open" or
/// "hash-file-read". Readers never call this; they hash through Sink.
Status hash_file(const std::string& path, Digests& out);

}  // namespace omnitrace
