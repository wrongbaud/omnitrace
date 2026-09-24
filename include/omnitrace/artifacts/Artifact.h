// Artifact.h — things worth naming that were extracted from the evidence.
/// @file Artifact.h
/// @brief `Artifact` (one extracted record), `Extractor` and its registry, and
/// the `collect()` pass that runs them over a finished case.
///
/// Three layers now answer three different questions about the same bytes, and
/// it is worth being precise about which is which:
///
/// * **rules** — *does this pattern appear anywhere?* A hit is an offset and
///   some context. It finds a `-----BEGIN CERTIFICATE-----` block.
/// * **analyzers** — *what kind of system is this, and what does it say about
///   itself?* One report per filesystem.
/// * **artifacts** (here) — *this file is a known thing; parse it and say what
///   it contains.* One record per object, with fields.
///
/// The difference is parsing. A rule can say a certificate is present; only a
/// parser can say it expired in 2019, was issued to `CN=router.local`, and has
/// its private key sitting in the same file.
///
/// Like `analyzers`, this layer takes what the extraction produced and nothing
/// about how it was produced: a list of (node id, entries) pairs, no Span, no
/// Manifest, no `discovery::` type. A finished case on disk can be re-examined
/// without re-extracting it.
#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "omnitrace/core/Diagnostics.h"
#include "omnitrace/core/Sink.h"

/// @namespace omnitrace::artifacts
/// @brief Extractors that parse a known file type into named records.
namespace omnitrace::artifacts {

/// One filesystem's extracted entries, keyed by the node id they belong to.
/// Structurally what `discovery::Listings` is, deliberately not that type.
using FilesystemEntries = std::vector<std::pair<std::string, std::vector<EntryResult>>>;

/// One extracted record.
///
/// `fields` is ordered so output is byte-identical run to run. Nothing secret
/// is ever copied into it: a private key's record says a key is there and what
/// kind, never the key.
struct Artifact {
    std::string kind;  ///< "certificate", "private-key", "dh-parameters", ...
    std::string node;  ///< Filesystem node the file came from.
    std::string path;  ///< Entry path inside that filesystem.
    /// What makes this record *the same record* in another case, within its
    /// kind: a certificate's fingerprint, a module's name, a kernel's version.
    ///
    /// The extractor sets it because only the extractor knows. Comparing two
    /// cases needs an identity that survives the file moving and the node ids
    /// changing (`docs/DIFF.md`), and the path is not one -- a vendor moving
    /// `server.pem` has not issued a new certificate. Empty means the kind has
    /// no identity beyond where it was found, and the path is used instead.
    std::string identity;
    Severity severity = Severity::Info;
    std::map<std::string, std::string> fields;
};

/// A file an extractor is looking at.
struct FileRef {
    std::string node;
    std::string path;
    std::span<const std::uint8_t> bytes;
};

/// A file an extractor produced that is too big to be a field.
///
/// A kernel's symbol table is thirty thousand lines: it belongs in the case
/// directory, not in a record and not in a report table. The extractor
/// composes the bytes and names a path relative to the case root; it never
/// writes anything, because this layer does not touch the host filesystem
/// (docs/ARCHITECTURE.md rule 2) and has to keep working when the caller is
/// re-examining a case rather than making one.
///
/// `path` is validated by whoever writes it: relative, no `..`, no absolute
/// root. See `safe_relative_path`.
struct ExtractedFile {
    std::string path;     ///< Relative to the case directory, '/' separated.
    std::string content;  ///< Written verbatim.
};

/// Is `p` a path an extractor may ask the caller to write?
///
/// Relative, non-empty, no component that is `.` or `..`, no drive letter or
/// leading separator, and no NUL or backslash. An extractor is built in and
/// not evidence, but what it names a file after can be -- a kernel image's own
/// path reaches this -- so the check is on the path rather than on trust.
bool safe_relative_path(std::string_view p);

/// What one extractor produced.
struct Yield {
    std::vector<Artifact> artifacts;
    std::vector<Diagnostic> diagnostics;
    /// Records the extractor deliberately summarised rather than emitted. A
    /// CA trust store is 253 certificates and 253 records is not a report;
    /// see `collect()`.
    std::uint64_t summarised = 0;
    /// Files for the caller to write into the case directory.
    std::vector<ExtractedFile> files;
};

/// A parser for one kind of file.
class Extractor {
   public:
    virtual ~Extractor() = default;
    /// Stable name, used in diagnostics and to look one up.
    virtual std::string name() const = 0;

    /// Cheap screen: is this file worth reading whole? `head` is the first few
    /// bytes. Called for every extracted file in the case, so it must not
    /// parse -- a path test or a magic test only.
    virtual bool applies(std::string_view path, std::span<const std::uint8_t> head) const = 0;

    /// Parse `file` and append what it holds.
    virtual void extract(const FileRef& file, Yield& out) const = 0;
};

/// Makes a fresh extractor.
using ExtractorFactory = std::function<std::unique_ptr<Extractor>()>;

/// Name -> extractor factory, populated at static initialization.
class ExtractorRegistry {
   public:
    /// The process-wide registry.
    static ExtractorRegistry& instance();
    /// Register or replace. Static-init time only; not synchronized.
    void add(const std::string& name, ExtractorFactory f);
    /// One of each registered extractor.
    std::vector<std::unique_ptr<Extractor>> all() const;
    /// A fresh extractor by name, or nullptr.
    std::unique_ptr<Extractor> create(const std::string& name) const;

   private:
    std::map<std::string, ExtractorFactory> factories_;
};

/// Constructing one registers `f`.
struct ExtractorRegistrar {
    /// Registers immediately.
    ExtractorRegistrar(const char* name, ExtractorFactory f) {
        ExtractorRegistry::instance().add(name, std::move(f));
    }
};
/// Register `Type` under `name`. Also give it an anchor and call that from
/// `link_builtin_extractors()` (src/artifacts/Registry.cpp).
#define OMNITRACE_REGISTER_EXTRACTOR(name, Type)                                            \
    static ::omnitrace::artifacts::ExtractorRegistrar _omnitrace_extractor_##Type {         \
        name, [] { return std::unique_ptr<::omnitrace::artifacts::Extractor>(new Type()); } \
    }

/// @cond
namespace detail {
/// Referenced by `collect()` so static linking keeps every extractor.
void link_builtin_extractors();
}  // namespace detail
/// @endcond

/// Caps on a collection run. A case holds tens of thousands of files and a
/// parser is only as trustworthy as the worst input it is shown.
struct CollectLimits {
    std::uint64_t max_bytes_per_file = 16U << 20;  ///< Read no more of one file than this.
    std::uint64_t max_artifacts = 100'000;         ///< Whole-run ceiling.
    /// Bytes of `ExtractedFile` content kept across the run. A symbol table
    /// is around a megabyte; this is the guard against an image that claims
    /// hundreds of them.
    std::uint64_t max_extracted_file_bytes = 64U << 20;
};

/// Everything the extractors produced.
struct Collection {
    std::vector<Artifact> artifacts;
    std::uint64_t files_examined = 0;  ///< Files an extractor claimed and read.
    std::uint64_t summarised = 0;      ///< Records counted rather than emitted.
    bool truncated = false;
    std::vector<Diagnostic> diagnostics;
    /// Files the extractors want written into the case directory, already
    /// checked against `safe_relative_path` and deduplicated by path.
    std::vector<ExtractedFile> files;
};

/// Run every registered extractor over every extracted file.
///
/// Never fails as a whole: an unreadable file or a parser that refuses its
/// input is a diagnostic, because one bad file is not a reason to abandon the
/// other seventy thousand.
Status collect(const FilesystemEntries& filesystems, const CollectLimits& limits, Collection& out);

/// `certificates.yaml` and friends: the records, machine-readable. One file
/// per `kind` family keeps a case readable as the extractor set grows.
std::string to_yaml(const Collection& c);
/// The same for a person.
std::string to_markdown(const Collection& c);

}  // namespace omnitrace::artifacts
