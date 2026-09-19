// span_test.cpp — Span accessors incl. off-by-one and uint64 overflow cases.
#include "omnitrace/core/Span.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace omnitrace {
namespace {

constexpr std::uint64_t kU64Max = std::numeric_limits<std::uint64_t>::max();
constexpr std::size_t kSizeMax = std::numeric_limits<std::size_t>::max();

std::vector<std::uint8_t> ramp(std::size_t n) {
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<std::uint8_t>(i & 0xFF);
    return v;
}

// A Source that refuses to map, so view() must return nullopt and the copy
// fallbacks (bytes/matches_at/cstring) get exercised through read().
class NoMapSource final : public Source {
   public:
    explicit NoMapSource(std::vector<std::uint8_t> b) : bytes_(std::move(b)) {}
    std::uint64_t size() const override { return bytes_.size(); }
    std::string id() const override { return "nomap"; }
    std::size_t read(std::uint64_t off, std::span<std::uint8_t> out) const override {
        if (off >= bytes_.size()) return 0;
        const std::size_t n =
            static_cast<std::size_t>(std::min<std::uint64_t>(bytes_.size() - off, out.size()));
        std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(off), n, out.begin());
        return n;
    }
    std::span<const std::uint8_t> map(std::uint64_t, std::size_t) const override { return {}; }

   private:
    std::vector<std::uint8_t> bytes_;
};

Span make_span(std::size_t n = 16) {
    return Span::whole(std::make_shared<MemorySource>(ramp(n), "t"));
}

// ------------------------------------------------------------- construction

TEST(Span, DefaultIsEmpty) {
    Span s;
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.size(), 0u);
    EXPECT_EQ(s.source(), nullptr);
    EXPECT_EQ(s.source_id(), "");
    EXPECT_FALSE(s.u8(0).has_value());
    EXPECT_FALSE(s.bytes(0, 1).has_value());
    EXPECT_FALSE(s.view(0, 1).has_value());
    EXPECT_FALSE(s.cstring(1, 1).has_value());
    std::uint8_t b[4];
    EXPECT_EQ(s.read(0, b), 0u);
    EXPECT_TRUE(s.sub(0, 4).empty());
}

TEST(Span, WholeCoversSource) {
    auto src = std::make_shared<MemorySource>(ramp(32), "w");
    Span s = Span::whole(src);
    EXPECT_EQ(s.size(), 32u);
    EXPECT_EQ(s.base(), 0u);
    EXPECT_EQ(s.source_id(), "mem:w");
    EXPECT_EQ(s.range().offset, 0u);
    EXPECT_EQ(s.range().length, 32u);
    EXPECT_EQ(s.range().end(), 32u);
    EXPECT_EQ(s.absolute(5), 5u);
}

TEST(Span, ConstructorClampsToSource) {
    auto src = std::make_shared<MemorySource>(ramp(32), "c");
    Span a(src, 8, 100);
    EXPECT_EQ(a.base(), 8u);
    EXPECT_EQ(a.size(), 24u);
    Span b(src, 40, 4);
    EXPECT_TRUE(b.empty());
    Span c(src, kU64Max - 1, 4);
    EXPECT_TRUE(c.empty());
    Span d(nullptr, 0, 10);
    EXPECT_TRUE(d.empty());
}

// --------------------------------------------------------------------- sub

TEST(Span, SubNarrowsAndClamps) {
    Span s = make_span(16);
    Span m = s.sub(4, 8);
    EXPECT_EQ(m.base(), 4u);
    EXPECT_EQ(m.size(), 8u);
    EXPECT_EQ(m.absolute(0), 4u);
    EXPECT_EQ(m.u8(0).value(), 4u);
    EXPECT_EQ(m.u8(7).value(), 11u);
    EXPECT_FALSE(m.u8(8).has_value());

    Span clamped = s.sub(12, 100);
    EXPECT_EQ(clamped.size(), 4u);
    EXPECT_EQ(clamped.u8(3).value(), 15u);

    Span at_end = s.sub(16, 1);
    EXPECT_TRUE(at_end.empty());
    Span past = s.sub(17, 1);
    EXPECT_TRUE(past.empty());
    EXPECT_EQ(past.source_id(), "mem:t");  // provenance survives
    Span wrap = s.sub(kU64Max - 1, 4);
    EXPECT_TRUE(wrap.empty());
    Span huge = s.sub(2, kU64Max);
    EXPECT_EQ(huge.size(), 14u);

    Span tail = s.sub(10);
    EXPECT_EQ(tail.size(), 6u);
    EXPECT_TRUE(s.sub(16).empty());
    EXPECT_TRUE(s.sub(kU64Max).empty());
}

TEST(Span, NestedSubIsAbsoluteInSource) {
    Span s = make_span(64);
    Span a = s.sub(16, 32);
    Span b = a.sub(8, 8);
    EXPECT_EQ(b.base(), 24u);
    EXPECT_EQ(b.size(), 8u);
    EXPECT_EQ(b.u8(0).value(), 24u);
    Span c = b.sub(4, 100);  // clamps to b, not to the source
    EXPECT_EQ(c.size(), 4u);
}

// ---------------------------------------------------------------------- at

TEST(Span, AtU8OffByOne) {
    Span s = make_span(16);
    EXPECT_EQ(s.u8(0).value(), 0u);
    EXPECT_EQ(s.u8(15).value(), 15u);
    EXPECT_FALSE(s.u8(16).has_value());
    EXPECT_FALSE(s.u8(kU64Max).has_value());
}

TEST(Span, AtU32BigVsLittleEndian) {
    auto src = std::make_shared<MemorySource>(
        std::vector<std::uint8_t>{0x12, 0x34, 0x56, 0x78, 0x9A}, "e");
    Span s = Span::whole(src);
    EXPECT_EQ(s.at<std::uint32_t>(0, Endian::Little).value(), 0x78563412u);
    EXPECT_EQ(s.at<std::uint32_t>(0, Endian::Big).value(), 0x12345678u);
    EXPECT_EQ(s.at<std::uint32_t>(1, Endian::Little).value(), 0x9A785634u);
    EXPECT_EQ(s.at<std::uint32_t>(1, Endian::Big).value(), 0x3456789Au);
    EXPECT_FALSE(s.at<std::uint32_t>(2, Endian::Little).has_value());  // needs 4, only 3 left
    EXPECT_FALSE(s.at<std::uint32_t>(2, Endian::Big).has_value());
    EXPECT_EQ(s.at<std::uint16_t>(3, Endian::Big).value(), 0x789Au);
    EXPECT_EQ(s.at<std::uint16_t>(3, Endian::Little).value(), 0x9A78u);
    EXPECT_FALSE(s.at<std::uint16_t>(4, Endian::Little).has_value());
}

TEST(Span, AtU64AndSigned) {
    auto src = std::make_shared<MemorySource>(
        std::vector<std::uint8_t>{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xFF, 0xFF}, "e");
    Span s = Span::whole(src);
    EXPECT_EQ(s.at<std::uint64_t>(0, Endian::Big).value(), 0x0102030405060708ull);
    EXPECT_EQ(s.at<std::uint64_t>(0, Endian::Little).value(), 0x0807060504030201ull);
    EXPECT_EQ(s.at<std::int16_t>(8, Endian::Little).value(), -1);
    EXPECT_FALSE(s.at<std::uint64_t>(3, Endian::Big).has_value());
    EXPECT_FALSE(s.at<std::uint64_t>(kU64Max - 1, Endian::Big).has_value());
    EXPECT_FALSE(s.at<std::uint64_t>(kU64Max - 7, Endian::Big).has_value());
}

// ------------------------------------------------------------------- bytes

TEST(Span, BytesOffByOneAndOverflow) {
    Span s = make_span(16);
    auto all = s.bytes(0, 16);
    ASSERT_TRUE(all.has_value());
    EXPECT_EQ(*all, ramp(16));
    auto last = s.bytes(15, 1);
    ASSERT_TRUE(last.has_value());
    EXPECT_EQ((*last)[0], 15u);
    auto empty_at_end = s.bytes(16, 0);
    ASSERT_TRUE(empty_at_end.has_value());
    EXPECT_TRUE(empty_at_end->empty());
    EXPECT_FALSE(s.bytes(16, 1).has_value());
    EXPECT_FALSE(s.bytes(17, 0).has_value());
    EXPECT_FALSE(s.bytes(0, 17).has_value());
    EXPECT_FALSE(s.bytes(1, 16).has_value());
    EXPECT_FALSE(s.bytes(kU64Max - 1, 4).has_value());
    EXPECT_FALSE(s.bytes(kU64Max, 0).has_value());
    EXPECT_FALSE(s.bytes(8, kSizeMax).has_value());
}

// -------------------------------------------------------------------- view

TEST(Span, ViewZeroCopy) {
    auto src = std::make_shared<MemorySource>(ramp(16), "v");
    Span s = Span::whole(src);
    auto v = s.view(4, 4);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->size(), 4u);
    EXPECT_EQ((*v)[0], 4u);
    // Same memory as the source's own mapping: no copy was made.
    EXPECT_EQ(v->data(), src->map(4, 4).data());
    EXPECT_TRUE(s.view(0, 16).has_value());
    EXPECT_FALSE(s.view(0, 17).has_value());
    EXPECT_FALSE(s.view(16, 1).has_value());
    EXPECT_FALSE(s.view(kU64Max - 1, 4).has_value());
    EXPECT_FALSE(s.view(1, kSizeMax).has_value());
    auto z = s.view(16, 0);
    ASSERT_TRUE(z.has_value());
    EXPECT_TRUE(z->empty());
}

TEST(Span, ViewRespectsSubWindow) {
    Span s = make_span(16).sub(4, 8);
    auto v = s.view(0, 8);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ((*v)[0], 4u);
    EXPECT_EQ((*v)[7], 11u);
    EXPECT_FALSE(s.view(0, 9).has_value());  // the source has more, the span does not
    EXPECT_FALSE(s.view(8, 1).has_value());
}

TEST(Span, ViewNulloptWhenSourceCannotMap) {
    Span s = Span::whole(std::make_shared<NoMapSource>(ramp(16)));
    EXPECT_FALSE(s.view(0, 4).has_value());
    auto b = s.bytes(0, 4);
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ((*b)[3], 3u);
    EXPECT_EQ(s.u8(15).value(), 15u);
}

// -------------------------------------------------------------------- read

TEST(Span, ReadShortAtEnd) {
    Span s = make_span(16).sub(8, 8);
    std::uint8_t buf[32] = {};
    EXPECT_EQ(s.read(0, buf), 8u);
    EXPECT_EQ(buf[0], 8u);
    EXPECT_EQ(buf[7], 15u);
    EXPECT_EQ(s.read(6, buf), 2u);
    EXPECT_EQ(buf[0], 14u);
    EXPECT_EQ(s.read(8, buf), 0u);
    EXPECT_EQ(s.read(9, buf), 0u);
    EXPECT_EQ(s.read(kU64Max - 1, buf), 0u);
    EXPECT_EQ(s.read(0, std::span<std::uint8_t>{}), 0u);
}

// -------------------------------------------------------------- matches_at

TEST(Span, MatchesAt) {
    auto src =
        std::make_shared<MemorySource>(std::vector<std::uint8_t>{'h', 's', 'q', 's', 0, 1}, "m");
    Span s = Span::whole(src);
    const std::uint8_t hsqs[] = {'h', 's', 'q', 's'};
    const std::uint8_t sqs01[] = {'s', 'q', 's', 0, 1};
    EXPECT_TRUE(s.matches_at(0, hsqs));
    EXPECT_FALSE(s.matches_at(1, hsqs));
    EXPECT_TRUE(s.matches_at(1, sqs01));
    EXPECT_FALSE(s.matches_at(2, sqs01));                            // runs one byte past the end
    EXPECT_TRUE(s.matches_at(6, std::span<const std::uint8_t>{}));   // empty at end is a match
    EXPECT_FALSE(s.matches_at(7, std::span<const std::uint8_t>{}));  // but not past it
    EXPECT_FALSE(s.matches_at(kU64Max - 1, hsqs));
    EXPECT_FALSE(s.matches_at(kU64Max, hsqs));
}

TEST(Span, MatchesAtThroughReadFallback) {
    // Pattern longer than the 256-byte chunk buffer, source that cannot map.
    auto data = ramp(1000);
    Span s = Span::whole(std::make_shared<NoMapSource>(data));
    std::vector<std::uint8_t> pat(data.begin() + 100, data.begin() + 700);
    EXPECT_TRUE(s.matches_at(100, pat));
    EXPECT_FALSE(s.matches_at(101, pat));
    pat.back() ^= 0xFF;
    EXPECT_FALSE(s.matches_at(100, pat));
    std::vector<std::uint8_t> tail(data.begin() + 500, data.end());
    EXPECT_TRUE(s.matches_at(500, tail));
    EXPECT_FALSE(s.matches_at(501, tail));
}

// ----------------------------------------------------------------- cstring

TEST(Span, CString) {
    std::vector<std::uint8_t> raw = {'r', 'o', 'o', 't', 0, 'x', 'y', 'z', 'w'};  // 9 bytes
    Span s = Span::whole(std::make_shared<MemorySource>(raw, "c"));
    EXPECT_EQ(s.cstring(0, 16).value(), "root");  // stops at NUL, n larger than span
    EXPECT_EQ(s.cstring(0, 4).value(), "root");   // fixed-width, no NUL within n
    EXPECT_EQ(s.cstring(0, 2).value(), "ro");
    EXPECT_EQ(s.cstring(5, 4).value(), "xyzw");    // exact fit at the end
    EXPECT_EQ(s.cstring(5, 100).value(), "xyzw");  // clamps to the span
    EXPECT_EQ(s.cstring(5, kSizeMax).value(), "xyzw");
    EXPECT_EQ(s.cstring(4, 3).value(), "");      // NUL first
    EXPECT_EQ(s.cstring(9, 3).value(), "");      // at end: empty, not nullopt
    EXPECT_FALSE(s.cstring(10, 3).has_value());  // past end
    EXPECT_FALSE(s.cstring(kU64Max - 1, 4).has_value());
    EXPECT_FALSE(s.cstring(kU64Max, 0).has_value());
}

TEST(Span, CStringLongerThanChunk) {
    std::vector<std::uint8_t> raw(700, 'a');
    raw[600] = 0;
    Span s = Span::whole(std::make_shared<NoMapSource>(raw));
    auto v = s.cstring(0, 700);
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(v->size(), 600u);
    auto w = s.cstring(0, 300);
    ASSERT_TRUE(w.has_value());
    EXPECT_EQ(w->size(), 300u);
}

// --------------------------------------------------------- span over SubSource

TEST(Span, OverSubSourceNeverEscapes) {
    auto parent = std::make_shared<MemorySource>(ramp(256), "p");
    auto sub = std::make_shared<SubSource>(parent, 128, 16);
    Span s = Span::whole(sub);
    EXPECT_EQ(s.size(), 16u);
    EXPECT_EQ(s.source_id(), "mem:p@0x80+0x10");
    EXPECT_EQ(s.u8(0).value(), 128u);
    EXPECT_EQ(s.u8(15).value(), 143u);
    EXPECT_FALSE(s.u8(16).has_value());
    EXPECT_FALSE(s.bytes(15, 2).has_value());
    EXPECT_FALSE(s.view(15, 2).has_value());
    EXPECT_EQ(s.cstring(0, 1000).value().size(), 16u);
}

}  // namespace
}  // namespace omnitrace
