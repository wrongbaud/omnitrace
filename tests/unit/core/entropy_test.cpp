// entropy_test.cpp — Shannon entropy, the byte-distribution profile and the
// classes it maps onto. The classification thresholds are conventions, so the
// tests pin them against data whose character is not in doubt: erased flash,
// passwd text, an even byte distribution, and real compressor output.
#include "omnitrace/core/Entropy.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cmath>
#include <memory>
#include <numeric>
#include <random>
#include <string>
#include <vector>

#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::entropy {
namespace {

using Bytes = std::vector<std::uint8_t>;

Bytes repeated(std::size_t n, std::uint8_t b) {
    return Bytes(n, b);
}

// Every byte value equally often: the definition of 8 bits per byte.
Bytes every_value(std::size_t copies) {
    Bytes b;
    b.reserve(copies * 256);
    for (std::size_t c = 0; c < copies; ++c)
        for (int v = 0; v < 256; ++v) b.push_back(static_cast<std::uint8_t>(v));
    return b;
}

Bytes uniform_random(std::size_t n, std::uint64_t seed) {
    std::mt19937_64 rng(seed);
    Bytes b(n);
    for (auto& x : b) x = static_cast<std::uint8_t>(rng());
    return b;
}

Bytes text_like(std::size_t n) {
    static const std::string line =
        "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin\n";
    Bytes b;
    while (b.size() < n)
        for (const char c : line) b.push_back(static_cast<std::uint8_t>(c));
    b.resize(n);
    return b;
}

std::span<const std::uint8_t> view(const Bytes& b) {
    return std::span<const std::uint8_t>(b.data(), b.size());
}

Span span_of(Bytes b, std::shared_ptr<const Source>& keep) {
    keep = std::make_shared<MemorySource>(std::move(b), "e");
    return Span::whole(keep);
}

}  // namespace

TEST(Entropy, ShannonHitsBothEnds) {
    EXPECT_DOUBLE_EQ(shannon({}), 0.0);
    EXPECT_DOUBLE_EQ(shannon(view(repeated(4096, 0xFF))), 0.0);
    EXPECT_DOUBLE_EQ(shannon(view(repeated(4096, 0x00))), 0.0);
    // 256 values once each is exactly 8 bits; two values is exactly 1.
    EXPECT_NEAR(shannon(view(every_value(1))), 8.0, 1e-12);
    EXPECT_NEAR(shannon(view(every_value(16))), 8.0, 1e-12);
    Bytes two(4096, 'a');
    std::fill(two.begin(), two.begin() + 2048, 'b');
    EXPECT_NEAR(shannon(view(two)), 1.0, 1e-12);
}

TEST(Entropy, ClassNamesAndMeaningsExistForEveryClass) {
    for (const Class c : {Class::Unknown, Class::Erased, Class::Sparse, Class::Text, Class::Binary,
                          Class::Packed, Class::Random}) {
        EXPECT_STRNE(class_name(c), "");
        EXPECT_STRNE(class_meaning(c), "");
    }
    EXPECT_STREQ(class_name(Class::Erased), "erased");
    EXPECT_STREQ(class_name(Class::Random), "random");
    // The hedge is the point: `random` must never claim encryption on its own.
    const std::string meaning = class_meaning(Class::Random);
    EXPECT_NE(meaning.find("cannot tell apart"), std::string::npos) << meaning;
}

TEST(Entropy, ErasedFlashAndFillAreRecognised) {
    for (const std::uint8_t fill : {std::uint8_t{0x00}, std::uint8_t{0xFF}, std::uint8_t{0x5A}}) {
        const Profile p = profile(view(repeated(1u << 16, fill)));
        EXPECT_EQ(p.klass, Class::Erased) << static_cast<int>(fill);
        EXPECT_TRUE(p.uniform_fill);
        EXPECT_EQ(p.fill_byte, fill);
        EXPECT_DOUBLE_EQ(p.mean, 0.0);
    }
}

TEST(Entropy, SparseTextAndBinarySeparate) {
    // Mostly zeros with a byte every 64: a sparse table, not erased.
    Bytes sparse(1u << 16, 0x00);
    for (std::size_t i = 0; i < sparse.size(); i += 64) sparse[i] = static_cast<std::uint8_t>(i);
    const Profile s = profile(view(sparse));
    EXPECT_EQ(s.klass, Class::Sparse);
    EXPECT_FALSE(s.uniform_fill);

    const Profile t = profile(view(text_like(1u << 16)));
    EXPECT_EQ(t.klass, Class::Text);
    EXPECT_GT(t.printable, 0.99);

    // A byte distribution with real structure but no printable bias.
    Bytes bin(1u << 16);
    std::mt19937_64 rng(7);
    for (auto& x : bin) x = static_cast<std::uint8_t>(rng() % 48);  // 48 values, ~5.6 bits
    const Profile b = profile(view(bin));
    EXPECT_EQ(b.klass, Class::Binary);
    EXPECT_LT(b.printable, 0.85);
}

TEST(Entropy, UniformBytesAreRandomAndChiSquareIsNearOne) {
    const Profile p = profile(view(uniform_random(1u << 20, 99)));
    EXPECT_EQ(p.klass, Class::Random);
    EXPECT_GT(p.mean, 7.9);
    // The whole discriminator: a uniform sample sits at a reduced chi-square
    // of about 1. 0.5 either side is far outside sampling noise at this size.
    EXPECT_NEAR(p.chi_square, 1.0, 0.5) << p.chi_square;
}

// Structured data is nowhere near uniform, which is what keeps `Random` from
// being handed out to anything that merely has high entropy.
TEST(Entropy, ChiSquareSeparatesStructureFromUniformity) {
    const Profile uniform = profile(view(uniform_random(1u << 20, 5)));
    const Profile text = profile(view(text_like(1u << 20)));
    const Profile erased = profile(view(repeated(1u << 20, 0xFF)));
    EXPECT_LT(uniform.chi_square, 2.0);
    EXPECT_GT(text.chi_square, 100.0);
    EXPECT_GT(erased.chi_square, 100.0);
}

TEST(Entropy, TooFewBytesIsUnknownRatherThanAGuess) {
    Options o;
    o.min_bytes = 256;
    const Profile p = profile(view(uniform_random(64, 1)), o);
    EXPECT_EQ(p.klass, Class::Unknown);
    EXPECT_EQ(p.sampled, 64u);  // still measured, just not classified
    EXPECT_GT(p.mean, 0.0);
    EXPECT_EQ(profile(std::span<const std::uint8_t>{}).klass, Class::Unknown);
}

// A region can be gigabytes. Reads have to stay bounded or profiling an eMMC
// image costs more than analysing it.
TEST(Entropy, ReadsStayInsideTheBudget) {
    std::shared_ptr<const Source> keep;
    const Span s = span_of(uniform_random(4u << 20, 3), keep);

    Options o;
    o.window = 4096;
    o.budget = 64u << 10;  // 16 windows
    const Profile p = profile(s, 0, s.size(), o);
    EXPECT_LE(p.sampled, o.budget);
    EXPECT_EQ(p.windows, 16u);
    EXPECT_EQ(p.klass, Class::Random);  // the sample still classifies correctly

    // A bigger budget reads more and still agrees.
    o.budget = 4u << 20;
    const Profile full = profile(s, 0, s.size(), o);
    EXPECT_GT(full.sampled, p.sampled);
    EXPECT_EQ(full.klass, Class::Random);
    EXPECT_NEAR(full.mean, p.mean, 0.05);
}

// The sampler spreads windows across the whole span, so a region that is text
// at one end and random at the other is not classified from its first bytes.
TEST(Entropy, SamplingSpreadsAcrossTheSpanNotJustTheStart) {
    Bytes b = text_like(2u << 20);
    const Bytes tail = uniform_random(2u << 20, 11);
    b.insert(b.end(), tail.begin(), tail.end());
    std::shared_ptr<const Source> keep;
    const Span s = span_of(b, keep);

    Options o;
    o.window = 4096;
    o.budget = 256u << 10;
    const Profile p = profile(s, 0, s.size(), o);
    // Both halves are represented, so the extremes bracket the mean.
    EXPECT_LT(p.min, 5.0) << "the text half was never sampled";
    EXPECT_GT(p.max, 7.5) << "the random half was never sampled";
    EXPECT_GT(p.mean, p.min);
    EXPECT_LT(p.mean, p.max);
}

TEST(Entropy, SpanAndBufferProfilesAgree) {
    const Bytes b = uniform_random(1u << 18, 21);
    std::shared_ptr<const Source> keep;
    const Span s = span_of(b, keep);
    const Profile from_span = profile(s, 0, s.size());
    const Profile from_buf = profile(view(b));
    EXPECT_EQ(from_span.klass, from_buf.klass);
    EXPECT_NEAR(from_span.mean, from_buf.mean, 1e-9);
    EXPECT_EQ(from_span.sampled, from_buf.sampled);
}

TEST(Entropy, OffsetAndLengthAreHonouredAndClamped) {
    Bytes b = repeated(1u << 16, 0xFF);
    const Bytes rnd = uniform_random(1u << 16, 4);
    b.insert(b.end(), rnd.begin(), rnd.end());
    std::shared_ptr<const Source> keep;
    const Span s = span_of(b, keep);

    EXPECT_EQ(profile(s, 0, 1u << 16).klass, Class::Erased);
    EXPECT_EQ(profile(s, 1u << 16, 1u << 16).klass, Class::Random);
    // A length past the end profiles what is there rather than reading off it.
    const Profile over = profile(s, 1u << 16, 1ull << 40);
    EXPECT_EQ(over.klass, Class::Random);
    EXPECT_LE(over.sampled, 1u << 16);
    // An offset past the end has nothing to say.
    EXPECT_EQ(profile(s, s.size() + 1, 4096).klass, Class::Unknown);
    EXPECT_EQ(profile(s, 0, 0).klass, Class::Unknown);
}

}  // namespace omnitrace::entropy
