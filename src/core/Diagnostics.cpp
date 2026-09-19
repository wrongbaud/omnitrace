// Diagnostics.cpp — names for severities and confidence tiers.
#include "omnitrace/core/Diagnostics.h"

namespace omnitrace {

const char* severity_name(Severity s) {
    switch (s) {
        case Severity::Info:
            return "info";
        case Severity::Warning:
            return "warning";
        case Severity::Error:
            return "error";
    }
    return "unknown";
}

const char* confidence_tier(Confidence c) {
    // Any score is accepted: it is snapped down to the tier it satisfies, so a
    // Confidence built from a raw score still gets a stable name.
    switch (confidence_from_score(static_cast<std::uint8_t>(c))) {
        case Confidence::Reject:
            return "reject";
        case Confidence::Magic:
            return "magic";
        case Confidence::Structural:
            return "structural";
        case Confidence::Consistent:
            return "consistent";
        case Confidence::Verified:
            return "verified";
    }
    return "unknown";
}

Confidence confidence_from_score(std::uint8_t score) {
    if (score >= static_cast<std::uint8_t>(Confidence::Verified)) return Confidence::Verified;
    if (score >= static_cast<std::uint8_t>(Confidence::Consistent)) return Confidence::Consistent;
    if (score >= static_cast<std::uint8_t>(Confidence::Structural)) return Confidence::Structural;
    if (score >= static_cast<std::uint8_t>(Confidence::Magic)) return Confidence::Magic;
    return Confidence::Reject;
}

}  // namespace omnitrace
