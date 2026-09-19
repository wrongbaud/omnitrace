// Diagnostics.h — confidence rubric and structured diagnostics.
//
// A Diagnostic tells the examiner something the identification itself does not:
// a degraded result, a caveat, a missing capability. `code` is a stable
// machine slug (kebab-case, e.g. "yaffs2-no-oob", "jffs2-crc-mismatch") that
// tests and downstream agents key on; `message` is the human sentence.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace omnitrace {

enum class Severity : std::uint8_t { Info, Warning, Error };
const char* severity_name(Severity s);

struct Diagnostic {
    Severity severity = Severity::Info;
    std::string code;
    std::string message;
};

// Numeric 0-100 with named tiers. The enum value IS the score.
enum class Confidence : std::uint8_t {
    Reject = 0,
    Magic = 25,       // magic matched; structure not validated
    Structural = 60,  // header parsed, all hard constraints pass
    Consistent = 85,  // cross-field / internal pointer consistency verified
    Verified = 99,    // CRC/checksum verified or a decode probe succeeded
};
const char* confidence_tier(Confidence c);
Confidence confidence_from_score(std::uint8_t score);

}  // namespace omnitrace
