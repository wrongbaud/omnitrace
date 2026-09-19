// clock_test.cpp — Clock override determinism and ISO-8601 formatting.
#include "omnitrace/core/Clock.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

namespace omnitrace {
namespace {

struct RestoreClock {
    ~RestoreClock() { Clock::set_override(nullptr); }
};

TEST(Clock, Iso8601KnownValues) {
    EXPECT_EQ(Clock::iso8601(0), "1970-01-01T00:00:00Z");
    EXPECT_EQ(Clock::iso8601(1), "1970-01-01T00:00:01Z");
    EXPECT_EQ(Clock::iso8601(86399), "1970-01-01T23:59:59Z");
    EXPECT_EQ(Clock::iso8601(86400), "1970-01-02T00:00:00Z");
    EXPECT_EQ(Clock::iso8601(951782400), "2000-02-29T00:00:00Z");  // leap day
    EXPECT_EQ(Clock::iso8601(1234567890), "2009-02-13T23:31:30Z");
    EXPECT_EQ(Clock::iso8601(2147483647), "2038-01-19T03:14:07Z");  // int32 max
    EXPECT_EQ(Clock::iso8601(2147483648), "2038-01-19T03:14:08Z");  // past it
    EXPECT_EQ(Clock::iso8601(-1), "1969-12-31T23:59:59Z");
    EXPECT_EQ(Clock::iso8601(253402300799), "9999-12-31T23:59:59Z");
}

TEST(Clock, Iso8601IsFixedWidth) {
    const std::string s = Clock::iso8601(1700000000);
    ASSERT_EQ(s.size(), 20u);
    EXPECT_EQ(s[4], '-');
    EXPECT_EQ(s[7], '-');
    EXPECT_EQ(s[10], 'T');
    EXPECT_EQ(s[13], ':');
    EXPECT_EQ(s[16], ':');
    EXPECT_EQ(s[19], 'Z');
}

TEST(Clock, OverrideIsDeterministic) {
    RestoreClock restore;
    Clock::set_override([] { return std::int64_t{1234567890}; });
    EXPECT_EQ(Clock::now(), 1234567890);
    EXPECT_EQ(Clock::now(), 1234567890);
    EXPECT_EQ(Clock::now_iso8601(), "2009-02-13T23:31:30Z");
    EXPECT_EQ(Clock::now_iso8601(), Clock::now_iso8601());

    int calls = 0;
    Clock::set_override([&calls] { return std::int64_t{100} + calls++; });
    EXPECT_EQ(Clock::now(), 100);
    EXPECT_EQ(Clock::now(), 101);
    EXPECT_EQ(Clock::now_iso8601(), "1970-01-01T00:01:42Z");
}

TEST(Clock, RestoreSystemClock) {
    RestoreClock restore;
    Clock::set_override([] { return std::int64_t{0}; });
    EXPECT_EQ(Clock::now(), 0);
    Clock::set_override(nullptr);
    // 2020-01-01T00:00:00Z; a real clock is well past this.
    EXPECT_GT(Clock::now(), 1577836800);
    const std::string s = Clock::now_iso8601();
    EXPECT_EQ(s.size(), 20u);
    EXPECT_EQ(s.back(), 'Z');
}

TEST(Clock, AbsurdValuesDoNotCrash) {
    // Either a well-formed string or empty, never a crash or garbage.
    const std::string big = Clock::iso8601(std::int64_t{1} << 62);
    EXPECT_TRUE(big.empty() || big.back() == 'Z');
    const std::string neg = Clock::iso8601(-(std::int64_t{1} << 62));
    EXPECT_TRUE(neg.empty() || neg.back() == 'Z');
}

}  // namespace
}  // namespace omnitrace
