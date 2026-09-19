// diagnostics_test.cpp — severity names, confidence tiers, score snapping.
#include "omnitrace/core/Diagnostics.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

namespace omnitrace {
namespace {

TEST(Diagnostics, SeverityNames) {
    EXPECT_STREQ(severity_name(Severity::Info), "info");
    EXPECT_STREQ(severity_name(Severity::Warning), "warning");
    EXPECT_STREQ(severity_name(Severity::Error), "error");
}

TEST(Diagnostics, ConfidenceTierNames) {
    EXPECT_STREQ(confidence_tier(Confidence::Reject), "reject");
    EXPECT_STREQ(confidence_tier(Confidence::Magic), "magic");
    EXPECT_STREQ(confidence_tier(Confidence::Structural), "structural");
    EXPECT_STREQ(confidence_tier(Confidence::Consistent), "consistent");
    EXPECT_STREQ(confidence_tier(Confidence::Verified), "verified");
}

TEST(Diagnostics, EnumValueIsScore) {
    EXPECT_EQ(static_cast<std::uint8_t>(Confidence::Reject), 0u);
    EXPECT_EQ(static_cast<std::uint8_t>(Confidence::Magic), 25u);
    EXPECT_EQ(static_cast<std::uint8_t>(Confidence::Structural), 60u);
    EXPECT_EQ(static_cast<std::uint8_t>(Confidence::Consistent), 85u);
    EXPECT_EQ(static_cast<std::uint8_t>(Confidence::Verified), 99u);
}

TEST(Diagnostics, ConfidenceFromScoreBoundaries) {
    EXPECT_EQ(confidence_from_score(0), Confidence::Reject);
    EXPECT_EQ(confidence_from_score(24), Confidence::Reject);
    EXPECT_EQ(confidence_from_score(25), Confidence::Magic);
    EXPECT_EQ(confidence_from_score(59), Confidence::Magic);
    EXPECT_EQ(confidence_from_score(60), Confidence::Structural);
    EXPECT_EQ(confidence_from_score(84), Confidence::Structural);
    EXPECT_EQ(confidence_from_score(85), Confidence::Consistent);
    EXPECT_EQ(confidence_from_score(98), Confidence::Consistent);
    EXPECT_EQ(confidence_from_score(99), Confidence::Verified);
    EXPECT_EQ(confidence_from_score(100), Confidence::Verified);
    EXPECT_EQ(confidence_from_score(255), Confidence::Verified);
}

TEST(Diagnostics, RoundTripsEveryTier) {
    for (Confidence c : {Confidence::Reject, Confidence::Magic, Confidence::Structural,
                         Confidence::Consistent, Confidence::Verified}) {
        EXPECT_EQ(confidence_from_score(static_cast<std::uint8_t>(c)), c);
    }
}

TEST(Diagnostics, TierNameOfNonCanonicalScoreSnapsDown) {
    EXPECT_STREQ(confidence_tier(static_cast<Confidence>(70)), "structural");
    EXPECT_STREQ(confidence_tier(static_cast<Confidence>(10)), "reject");
    EXPECT_STREQ(confidence_tier(static_cast<Confidence>(100)), "verified");
}

TEST(Diagnostics, StructDefaults) {
    Diagnostic d;
    EXPECT_EQ(d.severity, Severity::Info);
    EXPECT_TRUE(d.code.empty());
    EXPECT_TRUE(d.message.empty());
    Diagnostic w{Severity::Warning, "jffs2-crc-mismatch", "node CRC does not match"};
    EXPECT_EQ(w.severity, Severity::Warning);
    EXPECT_EQ(w.code, "jffs2-crc-mismatch");
}

}  // namespace
}  // namespace omnitrace
