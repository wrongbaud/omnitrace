// Diagnostics.h — confidence rubric and structured diagnostics.
//
// A Diagnostic tells the examiner something the identification itself does not:
// a degraded result, a caveat, a missing capability. `code` is a stable
// machine slug (kebab-case, e.g. "yaffs2-no-oob", "jffs2-crc-mismatch") that
// tests and downstream agents key on; `message` is the human sentence.
/// @file Diagnostics.h
/// @brief `Diagnostic` (a structured caveat) and `Confidence` (the 0-100 trust
/// score with named tiers).
///
/// Diagnostics never abort anything: a reader that meets a bad CRC records
/// `{Warning, "jffs2-crc-mismatch", ...}` on the entry or node and continues.
/// The code is the contract; tests and other agents match on it, so once a
/// code has shipped in a manifest it never changes meaning.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace omnitrace {

/// How serious a Diagnostic is. `Error` means the result is missing or wrong,
/// `Warning` means it is degraded, `Info` is a note (e.g. `sink-special-skipped`).
enum class Severity : std::uint8_t { Info, Warning, Error };
/// Stable name of a severity: "info", "warning", "error" (never null; "unknown"
/// for an out-of-range value). These strings land in manifest.yaml.
const char* severity_name(Severity s);

/// One caveat attached to a Node, Finding, EntryResult, WalkResult or the run.
struct Diagnostic {
    Severity severity = Severity::Info;  ///< Info, Warning or Error.
    std::string code;                    ///< Stable kebab-case slug, e.g. "squashfs-truncated".
    std::string message;  ///< Human sentence; may quote evidence bytes (sanitized before output).
};

// Numeric 0-100 with named tiers. The enum value IS the score.
/// Trust in an identification, 0-100. The enumerator value is the score, so
/// `static_cast<std::uint8_t>(Confidence::Structural) == 60` and `Node::confidence`
/// holds the same number. Validators assign the tier they could verify (see
/// docs/ARCHITECTURE.md "Confidence tiers"); conflict resolution compares
/// findings by this value.
enum class Confidence : std::uint8_t {
    Reject = 0,  ///< Not this format; the finding is dropped.
    Magic = 25,  ///< Magic bytes matched; structure not validated (or the header was corrupt).
    Structural =
        60,  ///< Header parsed; every hard constraint holds (sizes in range, version known).
    Consistent = 85,  ///< Cross-field consistency verified: table pointers land inside the
                      ///< structure, counts agree.
    Verified = 99,    ///< A CRC or checksum verified, or a decode probe succeeded.
};
/// Tier name for a Confidence: "reject", "magic", "structural", "consistent",
/// "verified". Any score is accepted: it is snapped down to the tier it
/// satisfies first, so a Confidence built from a raw 70 still names "structural".
const char* confidence_tier(Confidence c);
/// The highest tier whose threshold `score` reaches (70 -> Structural, 99 -> Verified).
Confidence confidence_from_score(std::uint8_t score);

}  // namespace omnitrace
