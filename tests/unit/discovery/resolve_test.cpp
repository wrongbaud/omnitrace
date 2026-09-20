// resolve_test.cpp — conflict resolution: nesting, same-offset duplicates,
// ordering, and the same-signature coverage skip.
#include <gtest/gtest.h>

#include "helpers.h"

using namespace omnitrace;
using namespace omnitrace::discovery;
using test::Bytes;

namespace {

// Validators that read a size and a tier from the bytes after the magic:
//   magic(4) tier(1: 0=magic,1=structural,2=consistent,3=verified) size(u32 LE)
std::optional<Finding> sized_validator(const Span& span, std::uint64_t start,
                                       const Signature& sig) {
    const std::uint64_t magic = start + sig.magic_offset;
    const auto tier = span.u8(magic + 4);
    const auto size = span.at<std::uint32_t>(magic + 5, Endian::Little);
    if (!size) return std::nullopt;
    Finding f;
    f.offset = start;
    f.size = *size;
    f.format = sig.format;
    f.category = sig.category;
    switch (*tier) {
        case 1:
            f.confidence = Confidence::Structural;
            break;
        case 2:
            f.confidence = Confidence::Consistent;
            break;
        case 3:
            f.confidence = Confidence::Verified;
            break;
        default:
            f.confidence = Confidence::Magic;
            break;
    }
    return f;
}

std::optional<Finding> reject_all(const Span&, std::uint64_t, const Signature&) {
    return std::nullopt;
}

struct Registered {
    Registered() {
        ValidatorRegistry::instance().add("test-sized", sized_validator);
        ValidatorRegistry::instance().add("test-reject", reject_all);
    }
};
const Registered registered;

SignatureSet set() {
    SignatureSet s;
    EXPECT_TRUE(s.load_toml(R"(
[[signature]]
name = "outer"
format = "outer"
category = "container"
magic = "OUT!"
validator = "test-sized"

[[signature]]
name = "inner"
format = "inner"
category = "other"
magic = "INN!"
validator = "test-sized"

[[signature]]
name = "plain"
format = "plain"
category = "other"
magic = "PLN!"

[[signature]]
name = "rejecting"
format = "rejecting"
category = "other"
magic = "PLN!"
validator = "test-reject"

[[signature]]
name = "stream"
format = "stream"
category = "compressed"
magic = "ZIP!"
validator = "test-sized"
)",
                            "resolve"));
    return s;
}

void plant(Bytes& b, std::size_t off, const char* magic, std::uint8_t tier, std::uint32_t size) {
    test::put_bytes(b, off, magic);
    b[off + 4] = tier;
    test::put_u32le(b, off + 5, size);
}

}  // namespace

TEST(Resolve, LowerConfidenceInsideHigherIsAbsorbed) {
    Bytes buf(4096, 0);
    plant(buf, 100, "OUT!", 2, 1000);   // consistent, [100, 1100)
    plant(buf, 200, "INN!", 1, 50);     // structural inside -> absorbed
    test::put_bytes(buf, 300, "PLN!");  // magic inside -> absorbed
    plant(buf, 1090, "INN!", 1, 50);    // straddles the end -> kept
    plant(buf, 2000, "INN!", 3, 10);    // outside -> kept
    const auto found = scan(test::span_of(buf), set());
    ASSERT_EQ(found.size(), 3u);
    EXPECT_EQ(found[0].offset, 100u);
    EXPECT_EQ(found[0].format, "outer");
    ASSERT_EQ(found[0].also_matched.size(), 2u);
    EXPECT_EQ(found[0].also_matched[0].offset, 200u);
    EXPECT_EQ(found[0].also_matched[1].offset, 300u);
    EXPECT_EQ(found[0].also_matched[1].format, "plain");
    EXPECT_EQ(found[1].offset, 1090u);
    EXPECT_EQ(found[2].offset, 2000u);

    ScanOptions raw;
    raw.resolve_conflicts = false;
    const auto all = scan(test::span_of(buf), set(), raw);
    EXPECT_EQ(all.size(), 5u);
    for (const Finding& f : all) EXPECT_TRUE(f.also_matched.empty());
}

TEST(Resolve, EqualConfidenceNestingIsKept) {
    Bytes buf(4096, 0);
    plant(buf, 100, "OUT!", 2, 1000);
    plant(buf, 200, "INN!", 2, 50);  // consistent inside consistent: both stay
    const auto found = scan(test::span_of(buf), set());
    ASSERT_EQ(found.size(), 2u);
    EXPECT_TRUE(found[0].also_matched.empty());
}

// The one exception to EqualConfidenceNestingIsKept. A SquashFS or JFFS2 is
// built out of gzip/xz/lz4/zstd blocks, which are its data and not separate
// finds, and tier ordering cannot express that: a truncated filesystem drops
// to Structural while a stream the validator walked to its end reaches
// Consistent. Containment decides instead, at any tier.
TEST(Resolve, CompressedStreamsInsideAnythingElseAreAbsorbed) {
    Bytes buf(4096, 0);
    plant(buf, 100, "OUT!", 1, 1000);  // structural container, [100, 1100)
    plant(buf, 200, "ZIP!", 1, 50);    // equal tier inside -> absorbed
    plant(buf, 300, "ZIP!", 2, 50);    // higher tier inside -> absorbed too
    plant(buf, 2000, "ZIP!", 1, 50);   // outside -> kept
    const auto found = scan(test::span_of(buf), set());
    ASSERT_EQ(found.size(), 2u);
    EXPECT_EQ(found[0].offset, 100u);
    ASSERT_EQ(found[0].also_matched.size(), 2u);
    EXPECT_EQ(found[0].also_matched[0].offset, 200u);
    EXPECT_EQ(found[0].also_matched[1].offset, 300u);
    EXPECT_EQ(found[1].offset, 2000u);
}

// A non-compressed find at a higher tier inside a lower-tier one is still
// kept: the exception is only for compressed streams.
TEST(Resolve, NonCompressedHigherTierInsideLowerIsStillKept) {
    Bytes buf(4096, 0);
    plant(buf, 100, "OUT!", 1, 1000);
    plant(buf, 200, "INN!", 2, 50);
    const auto found = scan(test::span_of(buf), set());
    ASSERT_EQ(found.size(), 2u);
    EXPECT_TRUE(found[0].also_matched.empty());
}

// Absorption at equal confidence is one-directional: a compressed stream is
// only ever the absorbed side, so two of them nest as before.
TEST(Resolve, CompressedStreamDoesNotAbsorbAnother) {
    Bytes buf(4096, 0);
    plant(buf, 100, "ZIP!", 1, 1000);
    plant(buf, 200, "ZIP!", 1, 50);
    const auto found = scan(test::span_of(buf), set());
    ASSERT_EQ(found.size(), 2u);
    EXPECT_TRUE(found[0].also_matched.empty());
}

TEST(Resolve, HigherConfidenceInsideLowerIsKept) {
    Bytes buf(4096, 0);
    plant(buf, 100, "OUT!", 1, 1000);
    plant(buf, 200, "INN!", 3, 50);
    const auto found = scan(test::span_of(buf), set());
    ASSERT_EQ(found.size(), 2u);
    EXPECT_EQ(found[1].offset, 200u);
    EXPECT_EQ(found[1].confidence, Confidence::Verified);
}

TEST(Resolve, SameOffsetDuplicatesKeepHigherThenLargerThenName) {
    Bytes buf(4096, 0);
    // "plain" and "rejecting" share a magic; rejecting validator drops itself.
    test::put_bytes(buf, 50, "PLN!");
    auto found = scan(test::span_of(buf), set());
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].signature, "plain");
    EXPECT_TRUE(found[0].also_matched.empty());

    // Two signatures with different magics cannot share an offset, so build
    // the duplicate through magic_offset: "INN!" at 116 with offset 16 -> 100.
    SignatureSet s = set();
    ASSERT_TRUE(
        s.load_toml("[[signature]]\nname='shifted'\nformat='shifted'\ncategory='other'\nmagic='INN!"
                    "'\nmagic_offset=16\nvalidator='test-sized'\n",
                    "dup"));
    Bytes b2(4096, 0);
    plant(b2, 100, "OUT!", 1, 500);  // structural at 100
    plant(b2, 116, "INN!", 3, 20);   // inner verified at 116 AND shifted verified at 100
    found = scan(test::span_of(b2), s);
    ASSERT_EQ(found.size(), 2u);
    EXPECT_EQ(found[0].offset, 100u);
    EXPECT_EQ(found[0].signature, "shifted");  // verified beats structural at the same offset
    EXPECT_EQ(found[0].confidence, Confidence::Verified);
    ASSERT_EQ(found[0].also_matched.size(), 1u);
    EXPECT_EQ(found[0].also_matched[0].signature, "outer");  // same offset, lower confidence
    EXPECT_EQ(found[1].signature, "inner");  // at 116: equal confidence, not absorbed
}

TEST(Resolve, OrderingIsOffsetThenConfidenceThenSizeThenName) {
    // Without resolution the list is still sorted by the same total order.
    SignatureSet s = set();
    ASSERT_TRUE(
        s.load_toml("[[signature]]\nname='shifted'\nformat='shifted'\ncategory='other'\nmagic='INN!"
                    "'\nmagic_offset=16\nvalidator='test-sized'\n",
                    "dup"));
    Bytes b(4096, 0);
    plant(b, 100, "OUT!", 3, 10);  // verified size 10 at 100
    plant(b, 116, "INN!", 3,
          999);  // inner verified size 999 at 116; shifted verified size 999 at 100
    ScanOptions raw;
    raw.resolve_conflicts = false;
    const auto all = scan(test::span_of(b), s, raw);
    ASSERT_EQ(all.size(), 3u);
    EXPECT_EQ(all[0].signature, "shifted");  // 100, verified, 999
    EXPECT_EQ(all[1].signature, "outer");    // 100, verified, 10
    EXPECT_EQ(all[2].signature, "inner");    // 116
}

TEST(Resolve, SameSignatureHitsInsideCoveredRangeAreSkipped) {
    Bytes buf(8192, 0);
    plant(buf, 0, "INN!", 2, 4000);     // consistent, covers [0, 4000)
    plant(buf, 1000, "INN!", 3, 100);   // same signature inside: not validated, not reported
    plant(buf, 4000, "INN!", 3, 100);   // at the boundary: reported
    plant(buf, 5000, "INN!", 1, 4000);  // structural: does not cover
    plant(buf, 6000, "INN!", 3, 10);    // inside the structural one: still validated and reported
    const auto found = scan(test::span_of(buf), set());
    std::vector<std::uint64_t> offs;
    for (const Finding& f : found) offs.push_back(f.offset);
    EXPECT_EQ(offs, (std::vector<std::uint64_t>{0, 4000, 5000, 6000}));
    EXPECT_TRUE(found[0].also_matched.empty());
}
