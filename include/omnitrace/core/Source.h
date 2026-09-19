// Source.h — read-only byte sources.
//
// Every parser in omnitrace reads through Span (see Span.h), and every Span is a
// window over a Source. Sources are: a memory-mapped file, an in-memory buffer,
// a sub-range of another Source, or a derived view (e.g. NAND with OOB stripped).
// A Source knows its stable `id` so provenance chains survive serialization.
/// @file Source.h
/// @brief `Source`, the read-only byte provider every `Span` sits on, and its
/// three concrete forms: `MemorySource`, `MappedFile`, `SubSource`
/// (`SwappedSource` lives in Swap.h).
///
/// Ownership: Sources are always held by `std::shared_ptr<const Source>`. A
/// `Span`, a `SubSource` and a `SwappedSource` each keep a shared_ptr to the
/// Source they read, so the evidence stays mapped for as long as anything
/// can still look at it. Thread-safety: no Source has mutable state after
/// construction, so `read()` and `map()` may be called concurrently.
#pragma once
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "omnitrace/core/Status.h"

namespace omnitrace {

/// Abstract read-only byte provider. Implementations clamp every request to
/// their own size; a caller can never read past the end or make them throw.
class Source : public std::enable_shared_from_this<Source> {
   public:
    /// Virtual so a `shared_ptr<const Source>` destroys the concrete type.
    virtual ~Source() = default;
    /// Total bytes available (0 for an empty file or buffer).
    virtual std::uint64_t size() const = 0;
    // Stable identifier: file path for a MappedFile, "<parent-id>@<off>+<len>"
    // for a SubSource, "mem:<label>" for MemorySource.
    /// Stable identifier used in `Location::source_id`: the path for a
    /// MappedFile, "mem:<label>" for a MemorySource, "<parent-id>@0x<off>+0x<len>"
    /// for a SubSource, "<parent-id>|swap16" / "|swap32" for a SwappedSource.
    virtual std::string id() const = 0;
    // Copy up to out.size() bytes starting at `off`. Returns bytes copied (short
    // at EOF, 0 if off >= size()).
    /// Copy up to `out.size()` bytes starting at `off`.
    /// @return bytes copied: short at EOF, 0 when `off >= size()` or `out` is empty.
    virtual std::size_t read(std::uint64_t off, std::span<std::uint8_t> out) const = 0;
    // Zero-copy view of [off, off+len) valid for the lifetime of this Source, or an
    // empty span if the range is out of bounds or the source cannot map. Callers
    // must fall back to read() when this returns empty.
    /// Zero-copy view of `[off, off+len)`, valid for the lifetime of this Source.
    /// @return an empty span when the range is out of bounds, `len` is 0, or
    /// this Source cannot map (SwappedSource never can). Callers must then fall
    /// back to `read()`; `Span::view` / `Span::bytes` do this for you.
    virtual std::span<const std::uint8_t> map(std::uint64_t off, std::size_t len) const = 0;
};

/// Bytes owned by the Source itself. Used by tests and by readers that
/// decompress a payload and then scan it. `id()` is "mem:<label>".
class MemorySource final : public Source {
   public:
    /// Take ownership of `bytes`; `label` becomes the id suffix.
    MemorySource(std::vector<std::uint8_t> bytes, std::string label);
    std::uint64_t size() const override;
    std::string id() const override;
    std::size_t read(std::uint64_t off, std::span<std::uint8_t> out) const override;
    std::span<const std::uint8_t> map(std::uint64_t off, std::size_t len) const override;

   private:
    std::vector<std::uint8_t> bytes_;
    std::string label_;
};

// Whole-file read-only mapping (mmap on POSIX, MapViewOfFile on Windows).
// Files larger than the address space are not supported yet; see docs/ARCHITECTURE.md.
/// Whole-file read-only mapping (mmap on POSIX, MapViewOfFile on Windows).
/// This is one of the three files allowed to touch the host OS
/// (docs/ARCHITECTURE.md rule 8). `id()` is the path as given to `open()`.
///
/// A zero-length file opens successfully with no mapping: `read()` returns 0
/// and `map()` an empty span. Files larger than the address space are refused
/// rather than windowed.
///
/// ```cpp
/// std::shared_ptr<omnitrace::MappedFile> file;
/// if (auto st = omnitrace::MappedFile::open("router.bin", file); !st) return st;
/// omnitrace::Span whole = omnitrace::Span::whole(file);
/// ```
class MappedFile final : public Source {
   public:
    /// Open and map `path`. Fails ("cannot open ...", "cannot stat ...",
    /// "cannot map ...") for a missing file, a directory, a file larger than
    /// `size_t`, or an mmap/MapViewOfFile error; `out` is reset first and
    /// set only on success.
    static Status open(const std::string& path, std::shared_ptr<MappedFile>& out);
    /// Unmaps the file.
    ~MappedFile() override;
    /// Not copyable: the mapping is owned.
    MappedFile(const MappedFile&) = delete;
    /// Not assignable.
    MappedFile& operator=(const MappedFile&) = delete;

    std::uint64_t size() const override;
    std::string id() const override;
    std::size_t read(std::uint64_t off, std::span<std::uint8_t> out) const override;
    std::span<const std::uint8_t> map(std::uint64_t off, std::size_t len) const override;
    /// The path passed to `open()`, unchanged.
    const std::string& path() const { return path_; }

   private:
    MappedFile() = default;
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::string path_;
};

// A sub-range of another Source. Never copies.
/// A sub-range `[off, off+len)` of another Source. Never copies: `read()` and
/// `map()` forward to the parent with the offset added, and the parent is kept
/// alive by the shared_ptr this holds. The range is clamped to the parent at
/// construction, so a hostile (off, len) cannot reach outside it.
///
/// Note that `discovery::analyze` does not use SubSource for nested finds;
/// it narrows with `Span::sub` so `Location::source_id` stays the evidence id.
class SubSource final : public Source {
   public:
    /// View `[off, off+len)` of `parent`, clamped to the parent's size.
    SubSource(std::shared_ptr<const Source> parent, std::uint64_t off, std::uint64_t len);
    std::uint64_t size() const override;
    /// "<parent-id>@0x<off>+0x<len>" with lowercase hex.
    std::string id() const override;
    std::size_t read(std::uint64_t off, std::span<std::uint8_t> out) const override;
    std::span<const std::uint8_t> map(std::uint64_t off, std::size_t len) const override;
    /// The Source this is a window into.
    const std::shared_ptr<const Source>& parent() const { return parent_; }
    /// Where this window starts inside `parent()`.
    std::uint64_t offset_in_parent() const { return off_; }

   private:
    std::shared_ptr<const Source> parent_;
    std::uint64_t off_, len_;
};

}  // namespace omnitrace
