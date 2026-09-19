// scan_test.cpp — the multi-pattern scanner: offsets, alignment, chunk edges,
// unmappable sources, hit limits and determinism.
#include <gtest/gtest.h>

#include "helpers.h"

using namespace omnitrace;
using namespace omnitrace::discovery;
using test::Bytes;

namespace {

SignatureSet plain_set() {
    SignatureSet s;
    EXPECT_TRUE(s.load_toml(R"(
[[signature]]
name = "alpha"
format = "alpha"
category = "other"
magic = "ALPHA"

[[signature]]
name = "beta"
format = "beta"
category = "other"
hex = "deadbeef"

[[signature]]
name = "gamma-aligned"
format = "gamma"
category = "other"
magic = "GAMMA"
alignment = 4

[[signature]]
name = "delta-offset"
format = "delta"
category = "other"
magic = "DELTA"
magic_offset = 8
)",
                            "plain"));
    return s;
}

}  // namespace

TEST(Scan, FindsMagicsAtAlignedAndUnalignedOffsets) {
    Bytes buf(4096, 0);
    test::put_bytes(buf, 0, "ALPHA");
    test::put_bytes(buf, 1001, "ALPHA");
    buf[2000] = 0xDE;
    buf[2001] = 0xAD;
    buf[2002] = 0xBE;
    buf[2003] = 0xEF;
    buf[4092] = 0xDE;
    buf[4093] = 0xAD;
    buf[4094] = 0xBE;
    buf[4095] = 0xEF;                     // at the very end
    test::put_bytes(buf, 3000, "GAMMA");  // 3000 % 4 == 0 -> accepted
    test::put_bytes(buf, 3013, "GAMMA");  // unaligned -> rejected
    test::put_bytes(buf, 100, "DELTA");   // structure at 92
    test::put_bytes(buf, 5, "DELTA");     // structure would start at -3 -> skipped
    const auto found = scan(test::span_of(buf), plain_set());
    ASSERT_EQ(found.size(), 6u);
    EXPECT_EQ(found[0].offset, 0u);
    EXPECT_EQ(found[0].format, "alpha");
    EXPECT_EQ(found[1].offset, 92u);
    EXPECT_EQ(found[1].format, "delta");
    EXPECT_EQ(found[2].offset, 1001u);
    EXPECT_EQ(found[2].format, "alpha");
    EXPECT_EQ(found[3].offset, 2000u);
    EXPECT_EQ(found[3].format, "beta");
    EXPECT_EQ(found[4].offset, 3000u);
    EXPECT_EQ(found[4].format, "gamma");
    EXPECT_EQ(found[5].offset, 4092u);
    EXPECT_EQ(found[5].format, "beta");
    for (const Finding& f : found) {
        EXPECT_EQ(f.confidence, Confidence::Magic);
        EXPECT_EQ(f.size, 0u);
        EXPECT_FALSE(f.evidence.empty());
        EXPECT_EQ(f.category, "other");
    }
    EXPECT_EQ(found[1].signature, "delta-offset");
    EXPECT_NE(found[1].evidence.find("0x64"), std::string::npos);
}

TEST(Scan, FindsHitsAcrossChunkBoundaries) {
    // The scanner reads 16 MiB chunks; plant magics straddling that edge and
    // the 2-chunk edge in a 20 MB buffer.
    const std::size_t edge = 16u << 20;
    Bytes buf(20u * 1000 * 1000, 0x11);
    // Non-overlapping plants: inside chunk 1, straddling the edge by one
    // byte, just inside chunk 2, and at the very end of the buffer.
    std::vector<std::size_t> offsets{edge - 9, edge - 4, edge + 2, edge + 8, 12345, buf.size() - 5};
    for (const std::size_t o : offsets) test::put_bytes(buf, o, "ALPHA");
    const auto found = scan(test::span_of(buf), plain_set());
    std::vector<std::uint64_t> got;
    for (const Finding& f : found) got.push_back(f.offset);
    std::vector<std::uint64_t> want(offsets.begin(), offsets.end());
    std::sort(want.begin(), want.end());
    // Overlapping plants overwrite each other; keep those still intact.
    std::vector<std::uint64_t> intact;
    for (const std::uint64_t o : want)
        if (std::memcmp(buf.data() + o, "ALPHA", 5) == 0) intact.push_back(o);
    EXPECT_EQ(got, intact);
    EXPECT_EQ(intact.size(), 6u);
}

TEST(Scan, UnmappableSourceUsesReadPath) {
    const std::size_t edge = 16u << 20;
    Bytes buf(edge + 4096, 0);
    test::put_bytes(buf, 7, "ALPHA");
    test::put_bytes(buf, edge - 2, "ALPHA");
    test::put_bytes(buf, edge + 4091, "ALPHA");
    const Span sp = Span::whole(std::make_shared<test::NoMapSource>(buf));
    ASSERT_FALSE(sp.view(0, 16).has_value());
    const auto found = scan(sp, plain_set());
    ASSERT_EQ(found.size(), 3u);
    EXPECT_EQ(found[0].offset, 7u);
    EXPECT_EQ(found[1].offset, edge - 2);
    EXPECT_EQ(found[2].offset, edge + 4091);
}

TEST(Scan, EmptyInputsAndTinySpans) {
    EXPECT_TRUE(scan(test::span_of({}), plain_set()).empty());
    EXPECT_TRUE(scan(test::span_of({'A'}), plain_set()).empty());
    EXPECT_TRUE(scan(test::span_of({'A', 'L', 'P', 'H'}), plain_set()).empty());
    EXPECT_EQ(scan(test::span_of({'A', 'L', 'P', 'H', 'A'}), plain_set()).size(), 1u);
    EXPECT_TRUE(scan(test::span_of({'A', 'L', 'P', 'H', 'A'}), SignatureSet{}).empty());
    EXPECT_TRUE(scan(Span{}, plain_set()).empty());
}

TEST(Scan, MaxHitsStopsScanningWithDiagnostic) {
    Bytes buf(10000, 0);
    for (std::size_t o = 0; o + 5 <= buf.size(); o += 100) test::put_bytes(buf, o, "ALPHA");
    ScanOptions opts;
    opts.max_hits = 7;
    const auto found = scan(test::span_of(buf), plain_set(), opts);
    ASSERT_EQ(found.size(), 7u);
    ASSERT_FALSE(found.back().diagnostics.empty());
    EXPECT_EQ(found.back().diagnostics.back().code, "scan-hit-limit");
    EXPECT_EQ(scan(test::span_of(buf), plain_set()).size(), 100u);
}

TEST(Scan, MissingValidatorIsReportedNotSilent) {
    SignatureSet s;
    ASSERT_TRUE(
        s.load_toml("[[signature]]\nname='x'\nformat='x'\ncategory='other'\nmagic='XMAG'"
                    "\nvalidator='does-not-exist'\n",
                    "t"));
    Bytes buf(64, 0);
    test::put_bytes(buf, 10, "XMAG");
    auto found = scan(test::span_of(buf), s);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].confidence, Confidence::Magic);
    ASSERT_EQ(found[0].diagnostics.size(), 1u);
    EXPECT_EQ(found[0].diagnostics[0].code, "validator-missing");
    ScanOptions opts;
    opts.validate = false;
    found = scan(test::span_of(buf), s, opts);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_TRUE(found[0].diagnostics.empty());
}

TEST(Scan, ValidateFalseSkipsValidators) {
    Bytes buf(4096, 0);
    test::put_bytes(buf, 100, "hsqs");
    ScanOptions opts;
    opts.validate = false;
    const auto found = scan(test::span_of(buf), test::only({"squashfs-le"}), opts);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].confidence, Confidence::Magic);
    EXPECT_EQ(found[0].format, "squashfs");
    EXPECT_EQ(found[0].endian, Endian::Little);
}

TEST(Scan, DeterministicAcrossRuns) {
    Bytes buf(300000, 0x5A);
    for (std::size_t o = 17; o + 5 <= buf.size(); o += 4099) test::put_bytes(buf, o, "ALPHA");
    for (std::size_t o = 40; o + 5 <= buf.size(); o += 8000) test::put_bytes(buf, o, "GAMMA");
    const auto a = scan(test::span_of(buf), plain_set());
    const auto b = scan(test::span_of(buf), plain_set());
    ASSERT_EQ(a.size(), b.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        EXPECT_EQ(a[i].offset, b[i].offset);
        EXPECT_EQ(a[i].signature, b[i].signature);
        EXPECT_EQ(a[i].evidence, b[i].evidence);
    }
    EXPECT_TRUE(std::is_sorted(a.begin(), a.end(), [](const Finding& x, const Finding& y) {
        return x.offset < y.offset;
    }));
}

TEST(Scan, BuiltinSetOnRandomDataIsQuiet) {
    // Pseudo-random bytes: the builtin set must not produce validated findings
    // from noise (Magic-only hits from short magics are acceptable and rare).
    Bytes buf(4u << 20);
    std::uint32_t x = 0x12345678;
    for (auto& b : buf) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        b = static_cast<std::uint8_t>(x);
    }
    const auto found = scan(test::span_of(buf), SignatureSet::builtin());
    for (const Finding& f : found)
        EXPECT_EQ(f.confidence, Confidence::Magic) << f.format << " at " << f.offset;
}
