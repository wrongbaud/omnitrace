// hash_test.cpp — Hasher / hash_span / hash_file against known vectors.
#include "omnitrace/core/Hash.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "omnitrace/core/Span.h"

namespace omnitrace {
namespace {

// Deterministic pseudo-random bytes (xorshift64*), so every run hashes the
// same buffer and results are comparable across machines.
std::vector<std::uint8_t> pseudo_random(std::size_t n, std::uint64_t seed) {
    std::vector<std::uint8_t> v(n);
    std::uint64_t x = seed;
    for (std::size_t i = 0; i < n; ++i) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        v[i] = static_cast<std::uint8_t>((x * 0x2545F4914F6CDD1Dull) >> 56);
    }
    return v;
}

std::span<const std::uint8_t> bytes_of(const std::string& s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

TEST(Hash, EmptyInputKnownVectors) {
    const Digests d = Hasher::of({});
    EXPECT_EQ(d.md5, "d41d8cd98f00b204e9800998ecf8427e");
    EXPECT_EQ(d.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    EXPECT_EQ(d.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(d.bytes, 0u);
    EXPECT_FALSE(d.empty());
    EXPECT_TRUE(Digests{}.empty());
}

TEST(Hash, AbcKnownVectors) {
    const Digests d = Hasher::of(bytes_of("abc"));
    EXPECT_EQ(d.md5, "900150983cd24fb0d6963f7d28e17f72");
    EXPECT_EQ(d.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
    EXPECT_EQ(d.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(d.bytes, 3u);
    EXPECT_EQ(d.md5.size(), 32u);
    EXPECT_EQ(d.sha1.size(), 40u);
    EXPECT_EQ(d.sha256.size(), 64u);
}

TEST(Hash, MillionAKnownVectors) {
    const std::string a(1'000'000, 'a');
    const Digests d = Hasher::of(bytes_of(a));
    EXPECT_EQ(d.md5, "7707d6ae4e027c70eea2a935c2296f21");
    EXPECT_EQ(d.sha1, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    EXPECT_EQ(d.sha256, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(Hash, IncrementalMatchesSingleShot) {
    const auto buf = pseudo_random(10u << 20, 0x9E3779B97F4A7C15ull);
    const Digests one = Hasher::of(buf);
    Hasher h;
    // Irregular chunk sizes exercise every block boundary in the digests.
    const std::size_t sizes[] = {1, 63, 64, 65, 4095, 4096, 4097, 1u << 20, 3u << 20, 7};
    std::size_t off = 0, k = 0;
    while (off < buf.size()) {
        const std::size_t n =
            std::min(sizes[k++ % (sizeof(sizes) / sizeof(sizes[0]))], buf.size() - off);
        h.update(std::span<const std::uint8_t>(buf.data() + off, n));
        off += n;
    }
    const Digests inc = h.finish();
    EXPECT_EQ(inc.md5, one.md5);
    EXPECT_EQ(inc.sha1, one.sha1);
    EXPECT_EQ(inc.sha256, one.sha256);
    EXPECT_EQ(inc.bytes, buf.size());
    // finish() resets: the same Hasher must now produce the empty digests.
    const Digests again = h.finish();
    EXPECT_EQ(again.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(again.bytes, 0u);
}

TEST(Hash, SpanChunkedMatchesSingleShot) {
    auto buf = pseudo_random((3u << 20) + 123, 42);
    const Digests one = Hasher::of(buf);
    auto src = std::make_shared<MemorySource>(buf, "hash-span");
    const Span whole = Span::whole(src);
    for (std::size_t chunk : {std::size_t{1} << 20, std::size_t{4097}, std::size_t{1},
                              std::size_t{0}, std::size_t{64} << 20}) {
        if (chunk == 1 && buf.size() > 4096)
            continue;  // byte-at-a-time over 3 MiB is slow; covered by sub-span below
        const Digests d = hash_span(whole, chunk);
        EXPECT_EQ(d.sha256, one.sha256) << "chunk " << chunk;
        EXPECT_EQ(d.md5, one.md5) << "chunk " << chunk;
        EXPECT_EQ(d.bytes, buf.size()) << "chunk " << chunk;
    }
    // A sub-span hashes only its window, relative offsets honoured.
    const Span sub = whole.sub(1000, 2000);
    const Digests ds = hash_span(sub, 1);
    EXPECT_EQ(ds.sha256, Hasher::of(std::span<const std::uint8_t>(buf.data() + 1000, 2000)).sha256);
    EXPECT_EQ(ds.bytes, 2000u);
    // Empty span: empty digests, zero bytes.
    const Digests de = hash_span(Span{}, 4096);
    EXPECT_EQ(de.bytes, 0u);
    EXPECT_EQ(de.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

class HashFileTest : public ::testing::Test {
   protected:
    std::filesystem::path dir_;
    void SetUp() override {
        std::error_code ec;
        dir_ = std::filesystem::temp_directory_path(ec) /
               ("omnitrace-hash-test-" +
                std::to_string(::testing::UnitTest::GetInstance()->random_seed()) + "-" +
                std::to_string(static_cast<unsigned>(std::hash<std::string>{}(
                    ::testing::UnitTest::GetInstance()->current_test_info()->name()))));
        std::filesystem::create_directories(dir_, ec);
        ASSERT_FALSE(ec) << ec.message();
    }
    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
    }
};

TEST_F(HashFileTest, StreamsWholeFile) {
    const auto buf = pseudo_random((10u << 20) + 17, 7);  // crosses the 8 MiB read chunk
    const auto path = dir_ / "blob.bin";
    {
        std::ofstream f(path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
    }
    Digests d;
    const Status s = hash_file(path.string(), d);
    ASSERT_TRUE(s) << s.error;
    const Digests expect = Hasher::of(buf);
    EXPECT_EQ(d.md5, expect.md5);
    EXPECT_EQ(d.sha1, expect.sha1);
    EXPECT_EQ(d.sha256, expect.sha256);
    EXPECT_EQ(d.bytes, buf.size());
}

TEST_F(HashFileTest, EmptyFile) {
    const auto path = dir_ / "empty.bin";
    {
        std::ofstream f(path, std::ios::binary);
    }
    Digests d;
    ASSERT_TRUE(hash_file(path.string(), d));
    EXPECT_EQ(d.bytes, 0u);
    EXPECT_EQ(d.md5, "d41d8cd98f00b204e9800998ecf8427e");
}

TEST_F(HashFileTest, MissingFileFails) {
    Digests d;
    const Status s = hash_file((dir_ / "does-not-exist").string(), d);
    EXPECT_FALSE(s);
    EXPECT_EQ(s.error, "hash-file-not-regular");
    EXPECT_TRUE(d.empty());
}

TEST_F(HashFileTest, DirectoryFails) {
    Digests d;
    const Status s = hash_file(dir_.string(), d);
    EXPECT_FALSE(s);
    EXPECT_EQ(s.error, "hash-file-not-regular");
}

}  // namespace
}  // namespace omnitrace
