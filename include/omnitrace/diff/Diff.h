// Diff.h — what changed between two cases.
/// @file Diff.h
/// @brief Comparing two finished cases: which files differ, what each system
/// says about itself, and what its kernel contains.
///
/// The question is "these are two units of the same model — what is different
/// about this one?", and it is asked of *cases* rather than of images, so it
/// works months later on evidence that is no longer attached. Everything here
/// takes recovered entries and nothing about how they were extracted, exactly
/// like `analyzers`, `artifacts` and `report`.
///
/// **Nothing is matched by node id.** Ids are assigned in discovery order, so
/// the same filesystem is `n000018` in one case and `n000021` in the other as
/// soon as anything earlier in the image differs by a byte. Files are compared
/// by *path* and, separately, by *content*; that second view is what survives
/// a vendor moving a directory, and it is the same lesson the parity harness
/// learned about comparing tools (`docs/PARITY.md`).
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "omnitrace/analyzers/Platform.h"
#include "omnitrace/core/Diagnostics.h"

/// @namespace omnitrace::diff
/// @brief Two-case comparison.
namespace omnitrace::diff {

/// One path that is not the same in both cases.
struct FileChange {
    std::string path;    ///< Entry path, as the listing records it.
    std::string node_a;  ///< Filesystem node it came from, per case.
    std::string node_b;
    std::string sha_a;  ///< Empty when the path is absent on that side.
    std::string sha_b;
    std::uint64_t size_a = 0;
    std::uint64_t size_b = 0;
};

/// Files, compared two ways.
///
/// By path, which is what an examiner reads; and by content, which is what
/// survives a rename. A file that moved shows up as one removal and one
/// addition in the path view and as neither in the content view, and the gap
/// between the two numbers is the interesting part.
struct FileDiff {
    std::vector<FileChange> added;    ///< Path only in B. Capped; see the totals.
    std::vector<FileChange> removed;  ///< Path only in A. Capped.
    std::vector<FileChange> changed;  ///< Path in both, different contents. Capped.
    /// Exact counts. The vectors above are truncated to `DiffLimits::max_listed`,
    /// so `added.size()` is not how many there were -- reporting it as one is
    /// how a diff comes to understate what it found.
    std::uint64_t added_total = 0, removed_total = 0, changed_total = 0;
    std::uint64_t same = 0;  ///< Path in both, identical contents.

    std::uint64_t files_a = 0, files_b = 0;      ///< Live regular files per case.
    std::uint64_t contents_a = 0, contents_b = 0;  ///< Distinct sha256 per case.
    std::uint64_t contents_common = 0;             ///< Distinct sha256 in both.
    /// Contents in both cases that no shared path accounts for: a file that
    /// was moved or renamed rather than edited.
    std::uint64_t moved = 0;
};

/// One platform fact, or one kernel property, that disagrees.
struct FactChange {
    std::string key;
    std::string a;  ///< Empty when only the other case states it.
    std::string b;
};

/// Kernel symbol tables, compared by name.
struct SymbolDiff {
    bool present_a = false, present_b = false;
    std::uint64_t symbols_a = 0, symbols_b = 0;
    std::uint64_t common = 0;
    std::vector<std::string> only_a;  ///< Capped; `only_a_total` is the count.
    std::vector<std::string> only_b;
    std::uint64_t only_a_total = 0, only_b_total = 0;
};

/// The whole comparison.
struct CaseDiff {
    std::string label_a, label_b;
    FileDiff files;
    std::vector<FactChange> platform;  ///< Facts that differ or are one-sided.
    SymbolDiff symbols;
    std::vector<Diagnostic> diagnostics;
    /// Nothing at all differs. Worth stating plainly: an examiner who diffs
    /// two acquisitions of one device wants to be told they match.
    bool identical() const {
        return files.added_total == 0 && files.removed_total == 0 && files.changed_total == 0 &&
               platform.empty() && symbols.only_a_total == 0 && symbols.only_b_total == 0;
    }
};

/// How much of a list to keep. A diff of two different models is every file in
/// both, and a report that lists 60,000 of them is not a report.
struct DiffLimits {
    std::size_t max_listed = 200;  ///< Per list; totals are always exact.
};

/// Compare the entries of two cases.
///
/// `symbols_a`/`symbols_b` are the kernel symbol tables as
/// `symbols/*.txt` holds them (nm format); pass empty strings when a case has
/// none. The caller reads them, because this layer does not touch the host
/// filesystem.
CaseDiff compare(const analyzers::FilesystemEntries& a, const analyzers::FilesystemEntries& b,
                 const analyzers::Survey& survey_a, const analyzers::Survey& survey_b,
                 const std::string& symbols_a, const std::string& symbols_b,
                 const DiffLimits& limits = {});

/// `diff.md`: the comparison for a person.
std::string to_markdown(const CaseDiff& d);
/// `diff.yaml`: the same for a machine.
std::string to_yaml(const CaseDiff& d);

}  // namespace omnitrace::diff
