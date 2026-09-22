// Platform.h — what kind of system an extracted filesystem came from.
/// @file Platform.h
/// @brief Platform models: `Tree` (a filesystem as the analyzers see it),
/// `Analyzer` and its registry, `Report`, and the `survey()` pass that runs
/// them over a finished case.
///
/// Discovery answers "what is this?" and rules answer "is the thing an
/// examiner came looking for in here?". This answers the question between
/// them: **what kind of system is this, and what does it say about itself?**
/// A case that lists 2,716 files is an inventory; one that says "OpenWrt
/// 18.06.1, mipsel_24kc, five accounts, two with a password hash" is a
/// starting point.
///
/// Like `rules::sweep`, the survey runs **after** the evidence graph exists.
/// `discovery` has no business knowing what OpenWrt looks like, and a report
/// has to name the filesystem node it describes, which only exists once the
/// graph is built.
///
/// One report per filesystem, not one per case. An image routinely holds
/// several systems -- an automotive Android unit infotainment unit carries QNX IFS images and an
/// Android `super` in the same eMMC -- and collapsing them to a single answer
/// would lose the more interesting half.
///
/// **Nothing here depends on how the evidence was extracted.** The input is a
/// list of (node id, entries) pairs and nothing else: no Span, no Source, no
/// `discovery::Listings`, no Manifest. That is deliberate. An analyzer asks
/// what a *filesystem* is, which is a question about a set of paths and their
/// contents, not about the image they were carved out of -- and a layer that
/// took the extraction's types could not be run over a case directory that
/// already exists on disk, which is exactly what re-analysing an old case
/// means. `FilesystemEntries` is structurally what `discovery::Listings` is,
/// so `analyze()` passes its listings straight in, but the dependency points
/// nowhere.
///
/// Thread-safety: the registry is populated at static initialization and
/// read-only afterwards; a `Tree` is immutable once built.
#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "omnitrace/core/Diagnostics.h"
#include "omnitrace/core/Sink.h"

/// @namespace omnitrace::analyzers
/// @brief Platform detection and the facts a platform reports about itself.
namespace omnitrace::analyzers {

/// One filesystem's extracted entries, keyed by the node id they belong to.
///
/// Structurally identical to `discovery::Listings` and deliberately not that
/// type: see the note above. Anything that can produce entries -- a live
/// `analyze()` run, a `listing.yaml` read back from a finished case, a test
/// building them by hand -- can drive an analyzer.
using FilesystemEntries = std::vector<std::pair<std::string, std::vector<EntryResult>>>;

/// The system families this build models.
enum class Platform : std::uint8_t {
    Unknown,  ///< Nothing claimed it.
    Linux,    ///< Any Linux userland, OpenWrt included.
    Android,  ///< Android, which is Linux and is reported as Android.
    Qnx,      ///< QNX Neutrino.
    Rtos,     ///< A small real-time or bare-metal system.
};
/// "unknown" | "linux" | "android" | "qnx" | "rtos".
const char* platform_name(Platform p);

/// One fact an analyzer established, and the entry it came from.
///
/// `source` is what makes a report checkable: every line an examiner reads
/// names the file it was read out of, so it can be opened in the case
/// directory and disagreed with.
struct Fact {
    std::string key;     ///< Dotted and stable: `os.pretty_name`, `user.root.hash_type`.
    std::string value;   ///< Sanitised; never raw bytes.
    std::string source;  ///< Entry path inside the filesystem, after symlink resolution.
};

/// What one analyzer concluded about one filesystem.
struct Report {
    std::string node;  ///< Filesystem or container node id the tree came from.
    Platform platform = Platform::Unknown;
    /// Markers that matched, as a count. Comparable only between analyzers of
    /// the same `rank`; see `Analyzer::rank`.
    unsigned score = 0;
    std::string evidence;  ///< One line naming the markers that decided it.
    std::vector<Fact> facts;
    std::vector<Diagnostic> diagnostics;
};

/// One extracted filesystem, as the analyzers see it: a path namespace with
/// its symlinks resolved **inside the tree**.
///
/// Resolution matters more than it looks. `/etc/os-release` is a symlink to
/// `../usr/lib/os-release` on every modern Linux, and the router corpus image
/// has 438 symlinks in one tree; an analyzer that only looked at regular files
/// would miss the single most useful file on the system. Resolution walks the
/// listing rather than the host filesystem, so it cannot escape the case
/// directory and gives the same answer whatever the host made of the links.
class Tree {
   public:
    /// Build from one filesystem's entries.
    explicit Tree(const std::vector<EntryResult>& entries);

    /// The entry at `path`, following symlinks; nullptr when there is none or
    /// the links do not resolve.
    const EntryResult* find(std::string_view path) const;
    /// A regular file exists at `path` (after symlink resolution).
    bool has_file(std::string_view path) const;
    /// A directory exists at `path`.
    bool has_dir(std::string_view path) const;
    /// The first of `paths` that is a regular file, or empty.
    std::string first_of(const std::vector<std::string>& paths) const;

    /// Up to `max` bytes of the regular file at `path`, sanitised to valid
    /// UTF-8. nullopt when it is not there or could not be read back.
    std::optional<std::string> read(std::string_view path, std::size_t max = 1u << 20) const;

    /// Entry paths directly inside `dir`, sorted; empty when it is not a
    /// directory. Names only, not full paths.
    std::vector<std::string> list_dir(std::string_view dir) const;

    /// Entries in the tree, live ones only (a deleted or superseded version is
    /// history, not the system as it was running).
    std::size_t size() const;

   private:
    struct Entry {
        const EntryResult* e = nullptr;
    };
    std::map<std::string, Entry, std::less<>> by_path_;
};

/// A platform model: does this tree look like mine, and what does it say?
class Analyzer {
   public:
    virtual ~Analyzer() = default;
    /// The platform this models.
    virtual Platform platform() const = 0;

    /// How specific this platform is. When two analyzers both claim a tree,
    /// the higher rank wins regardless of score, because the question is which
    /// answer is *more precise* rather than which found more files. Android is
    /// Linux and must be reported as Android; a Linux analyzer will always
    /// also match an Android tree, and no amount of marker counting fixes
    /// that.
    virtual unsigned rank() const = 0;

    /// Markers matched. 0 means "not mine"; nothing else is read from it
    /// except to compare with another analyzer of the same rank.
    virtual unsigned detect(const Tree& tree) const = 0;

    /// Fill in `facts` and `evidence`. Only called on the winner.
    virtual void describe(const Tree& tree, Report& out) const = 0;
};

/// Makes a fresh analyzer.
using AnalyzerFactory = std::function<std::unique_ptr<Analyzer>()>;

/// Platform -> analyzer factory. Populated at static initialization by
/// `OMNITRACE_REGISTER_ANALYZER`, read-only afterwards.
class AnalyzerRegistry {
   public:
    /// The process-wide registry.
    static AnalyzerRegistry& instance();
    /// Register or replace. Static-init time only; not synchronized.
    void add(Platform p, AnalyzerFactory f);
    /// One of each registered analyzer.
    std::vector<std::unique_ptr<Analyzer>> all() const;
    /// A fresh analyzer for `p`, or nullptr.
    std::unique_ptr<Analyzer> create(Platform p) const;

   private:
    std::map<Platform, AnalyzerFactory> factories_;
};

/// Constructing one registers `f`.
struct AnalyzerRegistrar {
    /// Registers immediately.
    AnalyzerRegistrar(Platform p, AnalyzerFactory f) {
        AnalyzerRegistry::instance().add(p, std::move(f));
    }
};
/// Register `Type` for `p`. Also give it an anchor and call that from
/// `link_builtin_analyzers()` (src/analyzers/Registry.cpp), so static linking
/// keeps the registrar.
#define OMNITRACE_REGISTER_ANALYZER(p, Type)                                            \
    static ::omnitrace::analyzers::AnalyzerRegistrar _omnitrace_analyzer_##Type {       \
        p, [] { return std::unique_ptr<::omnitrace::analyzers::Analyzer>(new Type()); } \
    }

/// @cond
namespace detail {
/// Referenced by `survey()` so static linking keeps every analyzer's registrar.
void link_builtin_analyzers();
}  // namespace detail
/// @endcond

/// Every filesystem's report, plus what the pass itself has to say.
struct Survey {
    std::vector<Report> reports;  ///< One per filesystem an analyzer claimed, in node order.
    std::uint64_t trees_examined = 0;
    std::uint64_t trees_unclaimed = 0;  ///< Walked, but nothing recognised them.
    std::vector<Diagnostic> diagnostics;
};

/// Run every registered analyzer over every filesystem in `filesystems`.
///
/// Never fails as a whole: a tree nothing claims is counted, not an error,
/// because an unrecognised system is a finding in itself.
Status survey(const FilesystemEntries& filesystems, Survey& out);

/// `platform.yaml`: the reports, machine-readable.
std::string platform_to_yaml(const Survey& s);
/// `platform.md`: the same for a person.
std::string platform_to_markdown(const Survey& s);

}  // namespace omnitrace::analyzers
