// source_test.cpp — MemorySource, SubSource and MappedFile.
#include "omnitrace/core/Source.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <random>
#include <string>
#include <vector>

namespace omnitrace {
namespace {

std::vector<std::uint8_t> ramp(std::size_t n) {
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<std::uint8_t>(i & 0xFF);
    return v;
}

std::vector<std::uint8_t> read_all(const Source& s, std::uint64_t off, std::size_t n) {
    std::vector<std::uint8_t> out(n);
    const std::size_t got = s.read(off, out);
    out.resize(got);
    return out;
}

// ---------------------------------------------------------------- MemorySource

TEST(MemorySource, SizeAndId) {
    MemorySource m(ramp(16), "unit");
    EXPECT_EQ(m.size(), 16u);
    EXPECT_EQ(m.id(), "mem:unit");
}

TEST(MemorySource, EmptyBuffer) {
    MemorySource m({}, "empty");
    EXPECT_EQ(m.size(), 0u);
    std::uint8_t b[4];
    EXPECT_EQ(m.read(0, b), 0u);
    EXPECT_TRUE(m.map(0, 0).empty());
    EXPECT_TRUE(m.map(0, 1).empty());
}

TEST(MemorySource, ReadFullAndShort) {
    MemorySource m(ramp(16), "r");
    auto a = read_all(m, 0, 16);
    EXPECT_EQ(a, ramp(16));
    auto b = read_all(m, 12, 16);  // short at EOF
    ASSERT_EQ(b.size(), 4u);
    EXPECT_EQ(b[0], 12u);
    EXPECT_EQ(b[3], 15u);
    EXPECT_TRUE(read_all(m, 16, 4).empty());  // off == size
    EXPECT_TRUE(read_all(m, 17, 4).empty());  // off > size
    EXPECT_TRUE(read_all(m, std::numeric_limits<std::uint64_t>::max(), 4).empty());
    EXPECT_TRUE(read_all(m, std::numeric_limits<std::uint64_t>::max() - 1, 4).empty());
}

TEST(MemorySource, ReadIntoEmptySpan) {
    MemorySource m(ramp(16), "r");
    EXPECT_EQ(m.read(0, std::span<std::uint8_t>{}), 0u);
}

TEST(MemorySource, MapBounds) {
    MemorySource m(ramp(16), "m");
    auto v = m.map(4, 8);
    ASSERT_EQ(v.size(), 8u);
    EXPECT_EQ(v[0], 4u);
    EXPECT_EQ(v[7], 11u);
    EXPECT_EQ(m.map(0, 16).size(), 16u);  // exact fit
    EXPECT_TRUE(m.map(0, 17).empty());    // one past
    EXPECT_TRUE(m.map(16, 1).empty());    // at end
    EXPECT_TRUE(m.map(15, 2).empty());    // straddles end
    EXPECT_TRUE(m.map(std::numeric_limits<std::uint64_t>::max() - 1, 4).empty());
    EXPECT_TRUE(m.map(1, std::numeric_limits<std::size_t>::max()).empty());
}

// ------------------------------------------------------------------- SubSource

TEST(SubSource, IdIsParentAtHexOffsetPlusHexLength) {
    auto parent = std::make_shared<MemorySource>(ramp(256), "p");
    SubSource s(parent, 0x10, 0x20);
    EXPECT_EQ(s.id(), "mem:p@0x10+0x20");
    SubSource z(parent, 0, 0);
    EXPECT_EQ(z.id(), "mem:p@0x0+0x0");
    SubSource big(parent, 0xAB, 0x100 - 0xAB);
    EXPECT_EQ(big.id(), "mem:p@0xab+0x55");
    EXPECT_EQ(s.offset_in_parent(), 0x10u);
    EXPECT_EQ(s.parent().get(), parent.get());
}

TEST(SubSource, NestedIdChains) {
    auto parent = std::make_shared<MemorySource>(ramp(256), "p");
    auto a = std::make_shared<SubSource>(parent, 0x40, 0x80);
    SubSource b(a, 0x8, 0x10);
    EXPECT_EQ(b.id(), "mem:p@0x40+0x80@0x8+0x10");
}

TEST(SubSource, ReadIsRelativeAndClampedToSubRange) {
    auto parent = std::make_shared<MemorySource>(ramp(256), "p");
    SubSource s(parent, 100, 10);
    EXPECT_EQ(s.size(), 10u);
    auto v = read_all(s, 0, 4);
    ASSERT_EQ(v.size(), 4u);
    EXPECT_EQ(v[0], 100u);
    EXPECT_EQ(v[3], 103u);
    // Never reads past the sub-range even though the parent has more bytes.
    auto tail = read_all(s, 8, 100);
    ASSERT_EQ(tail.size(), 2u);
    EXPECT_EQ(tail[0], 108u);
    EXPECT_EQ(tail[1], 109u);
    EXPECT_TRUE(read_all(s, 10, 1).empty());
    EXPECT_TRUE(read_all(s, 11, 1).empty());
    EXPECT_TRUE(read_all(s, std::numeric_limits<std::uint64_t>::max() - 1, 4).empty());
}

TEST(SubSource, MapClampsToSubRange) {
    auto parent = std::make_shared<MemorySource>(ramp(256), "p");
    SubSource s(parent, 100, 10);
    auto m = s.map(2, 8);
    ASSERT_EQ(m.size(), 8u);
    EXPECT_EQ(m[0], 102u);
    EXPECT_EQ(m[7], 109u);
    EXPECT_TRUE(s.map(2, 9).empty());  // would run past the sub-range
    EXPECT_TRUE(s.map(10, 1).empty());
    EXPECT_TRUE(s.map(0, 0).empty());
    EXPECT_TRUE(s.map(std::numeric_limits<std::uint64_t>::max() - 1, 4).empty());
    EXPECT_TRUE(s.map(1, std::numeric_limits<std::size_t>::max()).empty());
}

TEST(SubSource, HostileConstructionClampsToParent) {
    auto parent = std::make_shared<MemorySource>(ramp(64), "p");
    SubSource past(parent, 100, 10);
    EXPECT_EQ(past.size(), 0u);
    EXPECT_EQ(past.offset_in_parent(), 64u);
    EXPECT_TRUE(read_all(past, 0, 1).empty());

    SubSource overlong(parent, 60, std::numeric_limits<std::uint64_t>::max());
    EXPECT_EQ(overlong.size(), 4u);
    auto v = read_all(overlong, 0, 16);
    ASSERT_EQ(v.size(), 4u);
    EXPECT_EQ(v[0], 60u);

    SubSource wrap(parent, std::numeric_limits<std::uint64_t>::max() - 1, 4);
    EXPECT_EQ(wrap.size(), 0u);
    EXPECT_TRUE(wrap.map(0, 1).empty());
}

TEST(SubSource, NullParent) {
    SubSource s(nullptr, 5, 5);
    EXPECT_EQ(s.size(), 0u);
    EXPECT_EQ(s.id(), "@0x0+0x0");
    EXPECT_TRUE(read_all(s, 0, 1).empty());
    EXPECT_TRUE(s.map(0, 1).empty());
}

// ------------------------------------------------------------------ MappedFile

class MappedFileTest : public ::testing::Test {
   protected:
    std::filesystem::path dir_;

    void SetUp() override {
        // gtest's TempDir() honours TEST_TMPDIR; the random suffix keeps
        // concurrent runs (e.g. several presets' ctest) from sharing a dir.
        dir_ = std::filesystem::path(::testing::TempDir()) /
               ("omnitrace-mapped-file-test-" + std::to_string(std::random_device{}()));
        std::error_code ec;
        std::filesystem::create_directories(dir_, ec);
        ASSERT_FALSE(ec) << ec.message();
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(dir_, ec);
    }

    std::string write_file(const std::string& name, const std::vector<std::uint8_t>& bytes) {
        const auto p = dir_ / name;
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        f.close();
        return p.string();
    }
};

TEST_F(MappedFileTest, OpenReadMap) {
    const auto bytes = ramp(4096 + 17);
    const auto path = write_file("ramp.bin", bytes);

    std::shared_ptr<MappedFile> mf;
    Status st = MappedFile::open(path, mf);
    ASSERT_TRUE(st) << st.error;
    ASSERT_NE(mf, nullptr);
    EXPECT_EQ(mf->size(), bytes.size());
    EXPECT_EQ(mf->id(), path);
    EXPECT_EQ(mf->path(), path);

    auto v = mf->map(0, bytes.size());
    ASSERT_EQ(v.size(), bytes.size());
    EXPECT_TRUE(std::equal(v.begin(), v.end(), bytes.begin()));

    auto tail = read_all(*mf, 4096, 64);
    ASSERT_EQ(tail.size(), 17u);
    EXPECT_EQ(tail[0], bytes[4096]);
    EXPECT_EQ(tail[16], bytes[4112]);

    EXPECT_TRUE(mf->map(0, bytes.size() + 1).empty());
    EXPECT_TRUE(mf->map(bytes.size(), 1).empty());
    EXPECT_TRUE(mf->map(std::numeric_limits<std::uint64_t>::max() - 1, 4).empty());
    EXPECT_TRUE(read_all(*mf, bytes.size(), 4).empty());
    EXPECT_TRUE(read_all(*mf, std::numeric_limits<std::uint64_t>::max() - 1, 4).empty());
}

TEST_F(MappedFileTest, MappingOutlivesSharedPtrCopies) {
    const auto bytes = ramp(100);
    const auto path = write_file("copy.bin", bytes);
    std::span<const std::uint8_t> v;
    std::shared_ptr<MappedFile> keep;
    {
        std::shared_ptr<MappedFile> mf;
        ASSERT_TRUE(MappedFile::open(path, mf));
        keep = mf;
        v = mf->map(10, 10);
    }
    ASSERT_EQ(v.size(), 10u);
    EXPECT_EQ(v[0], 10u);
    EXPECT_EQ(v[9], 19u);
}

TEST_F(MappedFileTest, EmptyFileMapsToSizeZero) {
    const auto path = write_file("empty.bin", {});
    std::shared_ptr<MappedFile> mf;
    Status st = MappedFile::open(path, mf);
    ASSERT_TRUE(st) << st.error;
    ASSERT_NE(mf, nullptr);
    EXPECT_EQ(mf->size(), 0u);
    EXPECT_TRUE(mf->map(0, 0).empty());
    EXPECT_TRUE(mf->map(0, 1).empty());
    std::uint8_t b[8];
    EXPECT_EQ(mf->read(0, b), 0u);
}

TEST_F(MappedFileTest, MissingFileFailsWithPathAndReason) {
    const auto path = (dir_ / "does-not-exist.bin").string();
    std::shared_ptr<MappedFile> mf;
    Status st = MappedFile::open(path, mf);
    EXPECT_FALSE(st);
    EXPECT_EQ(mf, nullptr);
    EXPECT_NE(st.error.find(path), std::string::npos) << st.error;
    EXPECT_NE(st.error.find("No such file"), std::string::npos) << st.error;
}

TEST_F(MappedFileTest, DirectoryFails) {
    std::shared_ptr<MappedFile> mf;
    Status st = MappedFile::open(dir_.string(), mf);
    EXPECT_FALSE(st);
    EXPECT_EQ(mf, nullptr);
    EXPECT_NE(st.error.find(dir_.string()), std::string::npos) << st.error;
}

TEST_F(MappedFileTest, SubSourceOverMappedFile) {
    const auto bytes = ramp(512);
    const auto path = write_file("sub.bin", bytes);
    std::shared_ptr<MappedFile> mf;
    ASSERT_TRUE(MappedFile::open(path, mf));
    SubSource s(mf, 0x100, 0x10);
    EXPECT_EQ(s.id(), path + "@0x100+0x10");
    auto m = s.map(0, 0x10);
    ASSERT_EQ(m.size(), 0x10u);
    EXPECT_EQ(m[0], 0u);  // 0x100 & 0xFF
    EXPECT_EQ(m[15], 15u);
    EXPECT_TRUE(s.map(1, 0x10).empty());
}

// A sparse file exercises the "large file maps fine" path without writing
// gigabytes: on 64-bit the mapping is pure address space.
TEST_F(MappedFileTest, LargeSparseFileMaps) {
    if constexpr (sizeof(void*) < 8) GTEST_SKIP() << "32-bit address space";
    const auto p = dir_ / "sparse.bin";
    const std::uint64_t size = 5ull * 1024 * 1024 * 1024;  // 5 GiB
    {
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        f.seekp(static_cast<std::streamoff>(size - 1));
        f.put('\x5A');
        f.close();
    }
    std::error_code ec;
    if (std::filesystem::file_size(p, ec) != size || ec)
        GTEST_SKIP() << "filesystem does not support sparse files";
    std::shared_ptr<MappedFile> mf;
    Status st = MappedFile::open(p.string(), mf);
    if (!st) GTEST_SKIP() << "cannot map 5 GiB here: " << st.error;
    EXPECT_EQ(mf->size(), size);
    auto last = mf->map(size - 1, 1);
    ASSERT_EQ(last.size(), 1u);
    EXPECT_EQ(last[0], 0x5Au);
    auto first = mf->map(0, 1);
    ASSERT_EQ(first.size(), 1u);
    EXPECT_EQ(first[0], 0u);
    EXPECT_TRUE(mf->map(size, 1).empty());
    EXPECT_TRUE(mf->map(size - 1, 2).empty());
}

}  // namespace
}  // namespace omnitrace
