// validators_test.cpp — each validator on a hand-built minimal structure
// (accept), on corrupted / truncated / absurd input (reject or downgrade), and
// on the generated fixtures when they are present.
#include <gtest/gtest.h>

#include <algorithm>

#include "../../../src/discovery/crc32.h"
#include "helpers.h"

using namespace omnitrace;
using namespace omnitrace::discovery;
using test::Bytes;

namespace {

std::vector<Finding> scan_one(const Bytes& buf, const char* signature) {
    return scan(test::span_of(buf), test::only({signature}));
}

bool has_diag(const Finding& f, const char* code) {
    for (const Diagnostic& d : f.diagnostics)
        if (d.code == code) return true;
    return false;
}

std::vector<Finding> scan_file(const std::string& fixture) {
    std::shared_ptr<MappedFile> file;
    const Status st = MappedFile::open(test::fixture_path(fixture), file);
    EXPECT_TRUE(st) << st.error;
    return scan(Span::whole(file), SignatureSet::builtin());
}

// ------------------------------------------------------------- crc32 helper

TEST(Crc32, MatchesZlibOracleForEveryParameterSet) {
    Bytes data(1000);
    for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>(i * 7 + 3);
    const std::span<const std::uint8_t> s(data.data(), data.size());
    EXPECT_EQ(crc32_zlib(s), test::crc_zlib(data, 0, data.size()));
    EXPECT_EQ(crc32_jffs2(s), test::crc_jffs2(data, 0, data.size()));
    EXPECT_EQ(crc32_ubi(s), test::crc_ubi(data, 0, data.size()));
    const Bytes check{'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    EXPECT_EQ(crc32_zlib(std::span<const std::uint8_t>(check.data(), check.size())), 0xCBF43926u);
    EXPECT_EQ(crc32c_ext4(std::span<const std::uint8_t>(check.data(), check.size())) ^ 0xFFFFFFFFu,
              0xE3069283u);
    // Chunked span CRC equals one-shot, across the 64 KiB internal buffer.
    Bytes big(200000);
    for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<std::uint8_t>(i ^ (i >> 8));
    const Span sp = Span::whole(std::make_shared<test::NoMapSource>(big));
    EXPECT_EQ(crc32_span(sp, 10, 150000, 0xFFFFFFFFu, 0xFFFFFFFFu),
              test::crc_zlib(big, 10, 150000));
    EXPECT_FALSE(crc32_span(sp, 10, 200000, 0u, 0u).has_value());
    EXPECT_FALSE(crc32_span(sp, UINT64_MAX - 1, 4, 0u, 0u).has_value());
}

// ---------------------------------------------------------------- squashfs

Bytes squashfs_header(std::uint64_t bytes_used = 200000, bool big = false) {
    Bytes b(4096, 0);
    auto u16 = [&](std::size_t o, std::uint16_t v) {
        big ? test::put_u16be(b, o, v) : test::put_u16le(b, o, v);
    };
    auto u32 = [&](std::size_t o, std::uint32_t v) {
        big ? test::put_u32be(b, o, v) : test::put_u32le(b, o, v);
    };
    auto u64 = [&](std::size_t o, std::uint64_t v) {
        big ? test::put_u64be(b, o, v) : test::put_u64le(b, o, v);
    };
    test::put_bytes(b, 0, big ? "sqsh" : "hsqs");
    u32(4, 20);          // inodes
    u32(8, 1700000000);  // mkfs_time
    u32(12, 131072);     // block_size
    u32(16, 1);          // fragments
    u16(20, 4);          // xz
    u16(22, 17);         // block_log
    u16(24, 0xC0);       // flags
    u16(26, 1);          // no_ids
    u16(28, 4);
    u16(30, 0);
    u64(32, 0);
    u64(40, bytes_used);
    u64(48, bytes_used - 8);    // id table
    u64(56, ~0ull);             // xattr absent
    u64(64, bytes_used - 700);  // inode table
    u64(72, bytes_used - 400);  // dir table
    u64(80, bytes_used - 100);  // fragment table
    u64(88, ~0ull);             // export absent
    return b;
}

TEST(SquashfsValidator, AcceptsMinimalHeader) {
    Bytes b = squashfs_header(3000);
    b.resize(8192);
    const auto f = scan_one(b, "squashfs-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].size, 4096u);  // 3000 rounded up to 4K
    EXPECT_EQ(f[0].attrs.at("compression"), "xz");
    EXPECT_EQ(f[0].attrs.at("block_size"), "131072");
    EXPECT_EQ(f[0].attrs.at("inodes"), "20");
    EXPECT_EQ(f[0].attrs.at("fragments"), "1");
    EXPECT_EQ(f[0].attrs.at("version"), "4.0");
    EXPECT_EQ(f[0].endian, Endian::Little);
}

TEST(SquashfsValidator, BigEndianAndVendorMagics) {
    Bytes b = squashfs_header(3000, true);
    auto f = scan_one(b, "squashfs-be");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].endian, Endian::Big);
    test::put_bytes(b, 0, "qshs");  // vendor magic, order inferred from version
    f = scan_one(b, "squashfs-vendor-qshs");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].endian, Endian::Big);
    Bytes le = squashfs_header(3000, false);
    test::put_bytes(le, 0, "shsq");
    f = scan_one(le, "squashfs-vendor-shsq");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].endian, Endian::Little);
}

TEST(SquashfsValidator, CorruptedHeadersDowngradeOrReject) {
    Bytes b = squashfs_header(3000);
    test::put_u32le(b, 12, 100000);  // not a power of two
    auto f = scan_one(b, "squashfs-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_EQ(f[0].diagnostics[0].code, "squashfs-bad-block-size");

    b = squashfs_header(3000);
    test::put_u16le(b, 20, 9);  // compression id
    f = scan_one(b, "squashfs-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);

    b = squashfs_header(3000);
    test::put_u64le(b, 64, 3000 + 5);  // inode table outside bytes_used
    f = scan_one(b, "squashfs-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].diagnostics[0].code, "squashfs-table-outside");

    b = squashfs_header(1ull << 40);  // absurd bytes_used
    f = scan_one(b, "squashfs-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].size, b.size());
    EXPECT_EQ(f[0].diagnostics[0].code, "squashfs-truncated");

    b = squashfs_header(3000);
    test::put_u16le(b, 28, 3);  // v3: recognised, not parsed
    f = scan_one(b, "squashfs-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_EQ(f[0].diagnostics[0].code, "squashfs-unsupported-version");

    test::put_u16le(b, 28, 0x4141);  // garbage version: reject
    EXPECT_TRUE(scan_one(b, "squashfs-le").empty());

    Bytes tiny{'h', 's', 'q', 's', 1, 2, 3};  // truncated superblock
    f = scan_one(tiny, "squashfs-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_EQ(f[0].diagnostics[0].code, "squashfs-truncated-superblock");
}

TEST(SquashfsValidator, HostileBlockLogNeverShiftsOutOfRange) {
    // block_size is valid but block_log is attacker-controlled: 1u << 32 or
    // more is UB, so the validator must refuse before shifting.
    for (const std::uint16_t bl : {std::uint16_t{32}, std::uint16_t{40}, std::uint16_t{0xFFFF}}) {
        Bytes b = squashfs_header(3000);
        test::put_u16le(b, 22, bl);
        const auto f = scan_one(b, "squashfs-le");
        ASSERT_EQ(f.size(), 1u) << "block_log " << bl;
        EXPECT_EQ(f[0].confidence, Confidence::Magic) << "block_log " << bl;
        EXPECT_TRUE(has_diag(f[0], "squashfs-block-log-mismatch")) << "block_log " << bl;
    }
}

TEST(SquashfsValidator, Fixtures) {
    if (!test::fixture_exists("squashfs-gzip.img")) GTEST_SKIP();
    for (const char* name :
         {"squashfs-gzip.img", "squashfs-xz.img", "squashfs-lz4.img", "squashfs-zstd.img"}) {
        const auto found = scan_file(name);
        const Finding* f = test::find_at(found, 0, "squashfs");
        ASSERT_NE(f, nullptr) << name;
        EXPECT_EQ(f->confidence, Confidence::Consistent) << name;
        EXPECT_EQ(f->attrs.at("inodes"), "20") << name;
        EXPECT_EQ(f->attrs.at("mkfs_time"), "1700000000") << name;
        EXPECT_LE(f->size, std::filesystem::file_size(test::fixture_path(name))) << name;
        EXPECT_GE(f->size + 4096, std::filesystem::file_size(test::fixture_path(name))) << name;
    }
    EXPECT_EQ(test::find_at(scan_file("squashfs-lz4.img"), 0, "squashfs")->attrs.at("compression"),
              "lz4");
}

// ------------------------------------------------------------------- jffs2

void jffs2_node(Bytes& b, std::size_t off, std::uint16_t type, std::uint32_t totlen,
                bool big = false) {
    if (big) {
        test::put_u16be(b, off, 0x1985);
        test::put_u16be(b, off + 2, type);
        test::put_u32be(b, off + 4, totlen);
    } else {
        test::put_u16le(b, off, 0x1985);
        test::put_u16le(b, off + 2, type);
        test::put_u32le(b, off + 4, totlen);
    }
    const std::uint32_t crc = test::crc_jffs2(b, off, 8);
    big ? test::put_u32be(b, off + 8, crc) : test::put_u32le(b, off + 8, crc);
}

TEST(Jffs2Validator, WalksNodesAndErasedGaps) {
    Bytes b(65536 * 3, 0xFF);
    jffs2_node(b, 0, 0x2003, 12);            // cleanmarker
    jffs2_node(b, 12, 0xE002, 70);           // inode, padded to 72
    jffs2_node(b, 84, 0xE001, 30);           // dirent, padded to 32
    jffs2_node(b, 65536, 0x2003, 12);        // next erase block
    jffs2_node(b, 65536 + 12, 0xE002, 100);  // -> ends at 65536+112
    b[131072] = 0x00;                        // something else after the erased tail
    const auto f = scan_one(b, "jffs2-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].offset, 0u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified);
    EXPECT_EQ(f[0].size, 65536u + 112u);
    EXPECT_EQ(f[0].attrs.at("nodes"), "5");
    EXPECT_EQ(f[0].attrs.at("inode_nodes"), "2");
    EXPECT_EQ(f[0].attrs.at("dirent_nodes"), "1");
    EXPECT_EQ(f[0].attrs.at("cleanmarkers"), "2");
    EXPECT_EQ(f[0].attrs.at("erased_gap_bytes"), std::to_string(65536 - 116));
}

TEST(Jffs2Validator, BigEndianAndCorruption) {
    Bytes b(4096, 0xFF);
    jffs2_node(b, 0, 0x2003, 12, true);
    jffs2_node(b, 12, 0xE002, 40, true);
    auto f = scan_one(b, "jffs2-be");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].endian, Endian::Big);
    EXPECT_EQ(f[0].size, 52u);
    {
        const auto wrong = scan_one(b, "jffs2-le");  // wrong byte order: CRC fails
        EXPECT_TRUE(wrong.empty())
            << (wrong.empty() ? "" : wrong[0].evidence + " size " + std::to_string(wrong[0].size));
    }

    b[9] ^= 0x01;                 // corrupt the first header CRC: rejected outright; the
    f = scan_one(b, "jffs2-be");  // intact second node at 12 is a valid start
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].offset, 12u);
    EXPECT_EQ(f[0].attrs.at("nodes"), "1");

    Bytes t(4096, 0xFF);
    jffs2_node(t, 0, 0xE002, 100000);  // totlen past the end
    f = scan_one(t, "jffs2-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].size, t.size());
    EXPECT_EQ(f[0].diagnostics[0].code, "jffs2-truncated");

    Bytes u(4096, 0xFF);
    jffs2_node(u, 102, 0x2003, 12);  // unaligned: alignment=4 rejects it
    EXPECT_TRUE(scan_one(u, "jffs2-le").empty());
    Bytes z(16, 0);
    jffs2_node(z, 0, 0x2003, 4);  // totlen < 12
    EXPECT_TRUE(scan_one(z, "jffs2-le").empty());
}

TEST(Jffs2Validator, Fixtures) {
    if (!test::fixture_exists("jffs2-le.img")) GTEST_SKIP();
    auto found = scan_file("jffs2-le.img");
    const Finding* le = test::find_at(found, 0, "jffs2");
    ASSERT_NE(le, nullptr);
    EXPECT_EQ(le->confidence, Confidence::Verified);
    EXPECT_EQ(le->endian, Endian::Little);
    EXPECT_GT(std::stoul(le->attrs.at("inode_nodes")), 0u);
    std::size_t n = 0;
    for (const Finding& f : found) n += f.format == "jffs2";
    EXPECT_EQ(n, 1u);
    found = scan_file("jffs2-be.img");
    const Finding* be = test::find_at(found, 0, "jffs2");
    ASSERT_NE(be, nullptr);
    EXPECT_EQ(be->endian, Endian::Big);
    EXPECT_EQ(be->confidence, Confidence::Verified);
}

// --------------------------------------------------------------------- ubi

void ubi_ec(Bytes& b, std::size_t off, std::uint32_t vid_off = 2048,
            std::uint32_t data_off = 4096) {
    test::put_bytes(b, off, "UBI#");
    b[off + 4] = 1;
    test::put_u64be(b, off + 8, 3);
    test::put_u32be(b, off + 16, vid_off);
    test::put_u32be(b, off + 20, data_off);
    test::put_u32be(b, off + 24, 0x12345678);
    test::put_u32be(b, off + 60, test::crc_ubi(b, off, 60));
}

TEST(UbiValidator, WalksPebs) {
    const std::size_t peb = 65536;
    Bytes b(peb * 5, 0xFF);
    ubi_ec(b, 0);
    ubi_ec(b, peb);
    ubi_ec(b, 3 * peb);  // PEB 2 erased (interior), PEB 4 erased (trailing)
    test::put_bytes(b, 2048, "UBI!");
    const auto f = scan_one(b, "ubi");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified);
    EXPECT_EQ(f[0].attrs.at("peb_size"), "65536");
    EXPECT_EQ(f[0].attrs.at("pebs"), "4");
    EXPECT_EQ(f[0].attrs.at("erased_pebs"), "1");
    EXPECT_EQ(f[0].attrs.at("trailing_erased_pebs"), "1");
    EXPECT_EQ(f[0].size, 4 * peb);
    EXPECT_EQ(f[0].attrs.at("first_peb_mapped"), "true");
    EXPECT_EQ(f[0].attrs.at("vid_hdr_offset"), "2048");
    EXPECT_EQ(f[0].endian, Endian::Big);
}

TEST(UbiValidator, CorruptedAndHostile) {
    Bytes b(65536, 0xFF);
    ubi_ec(b, 0);
    b[8] ^= 0xFF;  // CRC no longer matches; fields still sane
    auto f = scan_one(b, "ubi");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].diagnostics[0].code, "ubi-ec-crc-mismatch");
    EXPECT_EQ(f[0].size, 0u);

    Bytes g(65536, 0xFF);
    test::put_bytes(g, 0, "UBI#");  // version 0xFF, offsets 0xFFFFFFFF, bad CRC: reject
    EXPECT_TRUE(scan_one(g, "ubi").empty());

    Bytes s(65536, 0xFF);
    ubi_ec(s, 0, 2048, 0xFFFFFF00u);  // data_offset past the span, CRC ok
    f = scan_one(s, "ubi");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified);
    EXPECT_EQ(f[0].diagnostics[0].code, "ubi-ec-fields-insane");

    Bytes one(65536, 0xFF);
    ubi_ec(one, 0);
    f = scan_one(one, "ubi");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].attrs.at("pebs"), "1");
    EXPECT_EQ(f[0].size, 0u);

    Bytes tiny{'U', 'B', 'I', '#', 1};
    f = scan_one(tiny, "ubi");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].diagnostics[0].code, "ubi-truncated-header");
}

TEST(UbiValidator, Fixture) {
    if (!test::fixture_exists("ubi.img")) GTEST_SKIP();
    const auto found = scan_file("ubi.img");
    const Finding* f = test::find_at(found, 0, "ubi");
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->confidence, Confidence::Verified);
    EXPECT_EQ(f->attrs.at("peb_size"), "131072");
    EXPECT_EQ(f->attrs.at("pebs"), "18");
    EXPECT_EQ(f->size, 2359296u);
    std::size_t n = 0;
    for (const Finding& x : found) n += x.format == "ubi";
    EXPECT_EQ(n, 1u);
}

// --------------------------------------------------------------------- ext

Bytes ext_image(std::uint32_t blocks = 1024, std::uint32_t log_bs = 0) {
    const std::uint64_t bs = 1024ull << log_bs;
    Bytes b(static_cast<std::size_t>(bs * blocks), 0);
    const std::size_t sb = 1024;
    const std::uint32_t bpg = 8192, ipg = 128;
    const std::uint32_t first = log_bs == 0 ? 1 : 0;
    const std::uint32_t groups = (blocks - first + bpg - 1) / bpg;
    test::put_u32le(b, sb + 0x00, groups * ipg);
    test::put_u32le(b, sb + 0x04, blocks);
    test::put_u32le(b, sb + 0x14, first);
    test::put_u32le(b, sb + 0x18, log_bs);
    test::put_u32le(b, sb + 0x20, bpg);
    test::put_u32le(b, sb + 0x28, ipg);
    test::put_u32le(b, sb + 0x2C, 1700000000);
    test::put_u32le(b, sb + 0x30, 1700000001);
    test::put_u16le(b, sb + 0x38, 0xEF53);
    test::put_u16le(b, sb + 0x3A, 1);
    test::put_u32le(b, sb + 0x4C, 1);
    test::put_u16le(b, sb + 0x58, 256);
    test::put_u32le(b, sb + 0x5C, 0x4);   // has_journal
    test::put_u32le(b, sb + 0x60, 0x42);  // filetype|extents
    test::put_u32le(b, sb + 0x64, 0x2C2);
    for (std::size_t i = 0; i < 16; ++i) b[sb + 0x68 + i] = static_cast<std::uint8_t>(i * 17);
    test::put_bytes(b, sb + 0x78, "omnitrace");
    test::put_bytes(b, sb + 0x88, "/mnt/test");
    return b;
}

TEST(ExtValidator, AcceptsAndClassifies) {
    const Bytes b = ext_image();
    auto f = scan_one(b, "ext");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].offset, 0u);
    EXPECT_EQ(f[0].format, "ext4");
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].size, b.size());
    EXPECT_EQ(f[0].attrs.at("volume_name"), "omnitrace");
    EXPECT_EQ(f[0].attrs.at("uuid"), "00112233-4455-6677-8899-aabbccddeeff");
    EXPECT_EQ(f[0].attrs.at("last_mount_time"), "1700000000");
    EXPECT_EQ(f[0].attrs.at("block_size"), "1024");
    EXPECT_EQ(f[0].attrs.at("inode_count"), "128");
    EXPECT_EQ(f[0].attrs.at("feature_incompat"), "0x00000042");
    EXPECT_EQ(f[0].attrs.at("last_mounted"), "/mnt/test");

    Bytes e3 = ext_image();
    test::put_u32le(e3, 1024 + 0x60, 0x2);
    test::put_u32le(e3, 1024 + 0x64, 0x3);
    f = scan_one(e3, "ext");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].format, "ext3");
    test::put_u32le(e3, 1024 + 0x5C, 0);
    f = scan_one(e3, "ext");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].format, "ext2");

    // metadata_csum with a good crc32c -> Verified.
    Bytes v = ext_image();
    test::put_u32le(v, 1024 + 0x64, 0x2C2 | 0x400);
    const std::uint32_t csum = crc32c_ext4(std::span<const std::uint8_t>(v.data() + 1024, 0x3FC));
    test::put_u32le(v, 1024 + 0x3FC, csum);
    f = scan_one(v, "ext");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified);
    v[1024 + 0x3FC] ^= 1;
    f = scan_one(v, "ext");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].attrs.at("superblock_checksum"), "mismatch");
}

TEST(ExtValidator, RejectsAndDowngrades) {
    Bytes b = ext_image();
    test::put_u32le(b, 1024 + 0x18, 7);  // log_block_size
    EXPECT_TRUE(scan_one(b, "ext").empty());
    b = ext_image();
    test::put_u32le(b, 1024 + 0x04, 0);  // no blocks
    EXPECT_TRUE(scan_one(b, "ext").empty());
    b = ext_image();
    test::put_u32le(b, 1024 + 0x14, 0);  // first_data_block wrong for 1K
    EXPECT_TRUE(scan_one(b, "ext").empty());
    b = ext_image();
    test::put_u32le(b, 1024 + 0x04, 0xFFFFFFFFu);  // absurd size
    auto f = scan_one(b, "ext");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].size, b.size());
    EXPECT_EQ(f[0].diagnostics[0].code, "ext-truncated");
    b = ext_image();
    test::put_u32le(b, 1024 + 0x00, 999);  // inode count disagrees
    f = scan_one(b, "ext");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].diagnostics[0].code, "ext-inode-count-mismatch");
    // Magic at the very end with no superblock behind it.
    Bytes t(0x43A, 0);
    test::put_u16le(t, 0x438, 0xEF53);
    EXPECT_TRUE(scan_one(t, "ext").empty());
}

TEST(ExtValidator, Fixture) {
    if (!test::fixture_exists("ext4.img")) GTEST_SKIP();
    const auto found = scan_file("ext4.img");
    const Finding* f = test::find_at(found, 0, "ext4");
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->confidence, Confidence::Verified);  // mkfs.ext4 default: metadata_csum
    EXPECT_EQ(f->attrs.at("superblock_checksum"), "ok");
    EXPECT_EQ(f->size, 16777216u);
    EXPECT_EQ(f->attrs.at("volume_name"), "omnitrace");
    EXPECT_EQ(f->attrs.at("block_size"), "4096");
}

// --------------------------------------------------------------------- mbr

void mbr_entry(Bytes& b, std::size_t base, int i, std::uint8_t status, std::uint8_t type,
               std::uint32_t lba, std::uint32_t n) {
    const std::size_t o = base + 446 + static_cast<std::size_t>(i) * 16;
    b[o] = status;
    b[o + 4] = type;
    test::put_u32le(b, o + 8, lba);
    test::put_u32le(b, o + 12, n);
}

TEST(MbrValidator, PrimariesAndEbrChain) {
    Bytes b(512 * 400, 0);
    b[510] = 0x55;
    b[511] = 0xAA;
    test::put_u32le(b, 440, 0xCAFEBABE);
    mbr_entry(b, 0, 0, 0x80, 0x83, 8, 100);
    mbr_entry(b, 0, 1, 0x00, 0x05, 120, 200);  // extended at sector 120
    // EBR 1 at 120: logical at +2 (10 sectors), next EBR at ext+20
    b[120 * 512 + 510] = 0x55;
    b[120 * 512 + 511] = 0xAA;
    mbr_entry(b, 120 * 512, 0, 0, 0x83, 2, 10);
    mbr_entry(b, 120 * 512, 1, 0, 0x05, 20, 30);
    // EBR 2 at 140: logical at +2 (20 sectors), no next
    b[140 * 512 + 510] = 0x55;
    b[140 * 512 + 511] = 0xAA;
    mbr_entry(b, 140 * 512, 0, 0, 0x0C, 2, 20);
    const auto f = scan_one(b, "mbr");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].offset, 0u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].attrs.at("partitions"),
              "p1:4096:51200:0x83:boot;p2:61440:102400:0x05;p3:62464:5120:0x83:logical;p4:72704:"
              "10240:0x0c:logical");
    EXPECT_EQ(f[0].attrs.at("disk_signature"), "0xcafebabe");
    EXPECT_EQ(f[0].size, (120u + 200u) * 512u);
}

TEST(MbrValidator, HostileTables) {
    Bytes vbr(4096, 0);  // boot sector with signature but no table
    vbr[510] = 0x55;
    vbr[511] = 0xAA;
    EXPECT_TRUE(scan_one(vbr, "mbr").empty());

    Bytes b(512 * 64, 0);
    b[510] = 0x55;
    b[511] = 0xAA;
    mbr_entry(b, 0, 0, 0x00, 0x83, 8, 0xFFFFFFF0u);  // ends far past the span
    auto f = scan_one(b, "mbr");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].size, b.size());
    EXPECT_EQ(f[0].diagnostics[0].code, "mbr-partition-truncated");

    mbr_entry(b, 0, 0, 0x00, 0x83, 8, 10);
    mbr_entry(b, 0, 1, 0x00, 0x83, 12, 10);  // overlaps p1
    f = scan_one(b, "mbr");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].diagnostics[0].code, "mbr-partitions-overlap");

    // Self-referencing EBR chain terminates.
    Bytes loop(512 * 64, 0);
    loop[510] = 0x55;
    loop[511] = 0xAA;
    mbr_entry(loop, 0, 0, 0, 0x0F, 10, 40);
    loop[10 * 512 + 510] = 0x55;
    loop[10 * 512 + 511] = 0xAA;
    mbr_entry(loop, 10 * 512, 0, 0, 0x83, 1, 2);
    mbr_entry(loop, 10 * 512, 1, 0, 0x05, 0, 40);  // points back to itself
    f = scan_one(loop, "mbr");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].attrs.at("partition_count"), "2");
}

TEST(MbrValidator, Fixture) {
    if (!test::fixture_exists("mbr-two-partitions.img")) GTEST_SKIP();
    const auto found = scan_file("mbr-two-partitions.img");
    const Finding* f = test::find_at(found, 0, "mbr");
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->confidence, Confidence::Consistent);
    EXPECT_EQ(f->attrs.at("partitions"), "p1:1048576:16777216:0x83:boot;p2:17825792:319488:0x83");
}

// --------------------------------------------------------------------- gpt

Bytes gpt_image(std::uint32_t entries = 128) {
    const std::uint64_t sectors = 4096;
    Bytes b(static_cast<std::size_t>(sectors * 512), 0);
    b[510] = 0x55;
    b[511] = 0xAA;
    mbr_entry(b, 0, 0, 0, 0xEE, 1, static_cast<std::uint32_t>(sectors - 1));
    const std::size_t h = 512;
    test::put_bytes(b, h, "EFI PART");
    test::put_u32le(b, h + 8, 0x00010000);
    test::put_u32le(b, h + 12, 92);
    test::put_u64le(b, h + 24, 1);
    test::put_u64le(b, h + 32, sectors - 1);
    test::put_u64le(b, h + 40, 34);
    test::put_u64le(b, h + 48, sectors - 34);
    for (std::size_t i = 0; i < 16; ++i) b[h + 56 + i] = static_cast<std::uint8_t>(0xA0 + i);
    test::put_u64le(b, h + 72, 2);
    test::put_u32le(b, h + 80, entries);
    test::put_u32le(b, h + 84, 128);
    // Two entries.
    const std::size_t e = 1024;
    const std::uint8_t linux_guid[16] = {0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
                                         0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4};
    for (int p = 0; p < 2; ++p) {
        const std::size_t o = e + static_cast<std::size_t>(p) * 128;
        std::copy(linux_guid, linux_guid + 16, b.begin() + static_cast<std::ptrdiff_t>(o));
        for (std::size_t i = 0; i < 16; ++i)
            b[o + 16 + i] = static_cast<std::uint8_t>(static_cast<std::size_t>(p) * 16 + i);
        test::put_u64le(b, o + 32, p == 0 ? 64 : 2048);
        test::put_u64le(b, o + 40, p == 0 ? 2047 : sectors - 35);
        const char16_t* name = p == 0 ? u"boot" : u"röot:x";
        for (std::size_t i = 0; name[i] != 0; ++i)
            test::put_u16le(b, o + 56 + i * 2, static_cast<std::uint16_t>(name[i]));
    }
    test::put_u32le(b, h + 88, test::crc_zlib(b, e, static_cast<std::size_t>(entries) * 128));
    test::put_u32le(b, h + 16, test::crc_zlib(b, h, 92));
    // Backup header at the last sector.
    const std::size_t bh = static_cast<std::size_t>((sectors - 1) * 512);
    std::copy(b.begin() + 512, b.begin() + 512 + 92, b.begin() + static_cast<std::ptrdiff_t>(bh));
    test::put_u64le(b, bh + 24, sectors - 1);
    test::put_u64le(b, bh + 32, 1);
    test::put_u32le(b, bh + 16, 0);
    test::put_u32le(b, bh + 16, test::crc_zlib(b, bh, 92));
    return b;
}

TEST(GptValidator, VerifiedWithEntriesAndBackup) {
    const Bytes b = gpt_image();
    const auto found = scan(test::span_of(b), test::only({"gpt", "gpt-4k", "mbr"}));
    ASSERT_GE(found.size(), 2u);
    const Finding* g = test::find_at(found, 0, "gpt");
    ASSERT_NE(g, nullptr);
    EXPECT_EQ(g->confidence, Confidence::Verified);
    EXPECT_EQ(g->size, b.size());
    EXPECT_EQ(g->attrs.at("disk_guid"), "a3a2a1a0-a5a4-a7a6-a8a9-aaabacadaeaf");
    EXPECT_EQ(g->attrs.at("partitions"),
              "p1:32768:1015808:0fc63daf-8483-4772-8e79-3d69d8477de4:03020100-0504-0706-0809-"
              "0a0b0c0d0e0f:boot;"
              "p2:1048576:1031168:0fc63daf-8483-4772-8e79-3d69d8477de4:13121110-1514-1716-1819-"
              "1a1b1c1d1e1f:r\xC3\xB6ot_x");
    EXPECT_EQ(g->attrs.at("entry_array_crc"), "ok");
    ASSERT_EQ(g->also_matched.size(), 1u);  // protective MBR at the same offset
    EXPECT_EQ(g->also_matched[0].format, "mbr");
    EXPECT_EQ(g->also_matched[0].attrs.at("protective"), "true");
    const Finding* backup = test::find_at(found, b.size() - 512, "gpt");
    ASSERT_NE(backup, nullptr);
    EXPECT_EQ(backup->attrs.at("backup"), "true");
    EXPECT_EQ(backup->confidence, Confidence::Verified);
}

// Blank the backup header so corruption tests see one finding.
Bytes gpt_no_backup() {
    Bytes b = gpt_image();
    std::fill(b.end() - 512, b.end(), 0);
    return b;
}

TEST(GptValidator, CorruptedAndHostile) {
    Bytes b = gpt_no_backup();
    b[512 + 40] ^= 1;  // header field changed: header CRC fails
    auto f = scan_one(b, "gpt");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].diagnostics[0].code, "gpt-header-crc-mismatch");

    b = gpt_no_backup();
    b[1024 + 32] ^= 1;  // entry changed: array CRC fails
    f = scan_one(b, "gpt");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].attrs.at("entry_array_crc"), "mismatch");

    b = gpt_no_backup();
    test::put_u32le(b, 512 + 80, 0xFFFFFFFFu);  // absurd entry count
    f = scan_one(b, "gpt");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_TRUE(has_diag(f[0], "gpt-entries-outside"));

    b = gpt_no_backup();
    test::put_u64le(b, 512 + 72, UINT64_MAX / 2);  // entry lba overflow
    f = scan_one(b, "gpt");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_TRUE(has_diag(f[0], "gpt-entries-outside"));

    b = gpt_no_backup();
    test::put_u32le(b, 512 + 12, 4);  // header_size
    f = scan_one(b, "gpt");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);

    Bytes tiny(600, 0);
    test::put_bytes(tiny, 512, "EFI PART");
    f = scan_one(tiny, "gpt");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].diagnostics[0].code, "gpt-truncated-header");

    // Truncated disk: the alternate header lies beyond the data.
    b = gpt_image();
    b.resize(1 << 20);
    f = scan_one(b, "gpt");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].size, b.size());
    EXPECT_TRUE(has_diag(f[0], "gpt-truncated"));
}

TEST(GptValidator, Fixture) {
    if (!test::fixture_exists("gpt.img")) GTEST_SKIP();
    const auto found = scan_file("gpt.img");
    const Finding* f = test::find_at(found, 0, "gpt");
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->confidence, Confidence::Verified);
    EXPECT_EQ(f->attrs.at("partition_count"), "2");
    EXPECT_EQ(f->attrs.at("disk_guid"), "6f1a2c3e-0001-4d5e-8f90-0123456789ab");
}

// ------------------------------------------------------------------ uimage

Bytes uimage(std::uint32_t data_size = 1000, std::uint8_t type = 2) {
    Bytes b(64 + data_size + 100, 0);
    for (std::size_t i = 0; i < data_size; ++i) b[64 + i] = static_cast<std::uint8_t>(i * 31);
    test::put_u32be(b, 0, 0x27051956);
    test::put_u32be(b, 8, 1700000000);
    test::put_u32be(b, 12, data_size);
    test::put_u32be(b, 16, 0x80000000);
    test::put_u32be(b, 20, 0x80000000);
    test::put_u32be(b, 24, test::crc_zlib(b, 64, data_size));
    b[28] = 5;
    b[29] = 5;
    b[30] = type;
    b[31] = 3;
    test::put_bytes(b, 32, "MIPS OpenWrt Linux-4.14.63");
    test::put_u32be(b, 4, test::crc_zlib(b, 0, 64));
    return b;
}

TEST(UimageValidator, VerifiedHeaderAndData) {
    const Bytes b = uimage();
    auto f = scan_one(b, "uimage");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified);
    EXPECT_EQ(f[0].size, 1064u);
    EXPECT_EQ(f[0].attrs.at("name"), "MIPS OpenWrt Linux-4.14.63");
    EXPECT_EQ(f[0].attrs.at("os"), "linux");
    EXPECT_EQ(f[0].attrs.at("arch"), "mips");
    EXPECT_EQ(f[0].attrs.at("type"), "kernel");
    EXPECT_EQ(f[0].attrs.at("compression"), "lzma");
    EXPECT_EQ(f[0].attrs.at("data_size"), "1000");
    EXPECT_EQ(f[0].attrs.at("data_crc"), "ok");
    EXPECT_EQ(f[0].category, "kernel");
    EXPECT_EQ(f[0].endian, Endian::Big);
    f = scan_one(uimage(1000, 7), "uimage");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].category, "container");
    EXPECT_EQ(f[0].attrs.at("type"), "filesystem");
}

TEST(UimageValidator, Corrupted) {
    Bytes b = uimage();
    b[40] ^= 1;  // name changed: header CRC fails
    auto f = scan_one(b, "uimage");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_EQ(f[0].size, 0u);
    EXPECT_EQ(f[0].diagnostics[0].code, "uimage-header-crc-mismatch");

    b = uimage();
    b[64 + 10] ^= 1;  // payload changed
    f = scan_one(b, "uimage");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].attrs.at("data_crc"), "mismatch");

    b = uimage();
    b.resize(500);  // payload truncated
    f = scan_one(b, "uimage");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].size, 500u);
    EXPECT_EQ(f[0].diagnostics[0].code, "uimage-truncated");

    Bytes tiny{0x27, 0x05, 0x19, 0x56, 0, 0};
    f = scan_one(tiny, "uimage");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].diagnostics[0].code, "uimage-truncated-header");
}

TEST(UimageValidator, Fixture) {
    if (!test::fixture_exists("uimage-lzma.img")) GTEST_SKIP();
    const auto found = scan_file("uimage-lzma.img");
    const Finding* f = test::find_at(found, 0, "uimage");
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->confidence, Confidence::Verified);
    EXPECT_EQ(f->attrs.at("name"), "omnitrace rootfs");
    EXPECT_EQ(f->attrs.at("compression"), "lzma");
    EXPECT_EQ(f->size, std::filesystem::file_size(test::fixture_path("uimage-lzma.img")));
    EXPECT_EQ(f->attrs.at("data_crc"), "ok");
}

// ------------------------------------------------------- compressed streams

TEST(GzipValidator, HeaderFields) {
    Bytes b{0x1F, 0x8B, 0x08, 0x08, 0x00, 0xE1, 0xF5, 0x05, 0x02, 0x03,
            'k',  'e',  'r',  'n',  'e',  'l',  0,    1,    2,    3};
    auto f = scan_one(b, "gzip");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].attrs.at("mtime"), "100000000");
    EXPECT_EQ(f[0].attrs.at("original_name"), "kernel");
    EXPECT_EQ(f[0].attrs.at("os"), "unix");
    EXPECT_EQ(f[0].attrs.at("header_len"), "17");
    b[3] = 0x80;  // reserved flag bit: reject
    EXPECT_TRUE(scan_one(b, "gzip").empty());
    b[3] = 0x00;
    b[9] = 200;  // bad OS: downgrade
    f = scan_one(b, "gzip");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    // FNAME without terminator runs to the end of the span without overrun.
    Bytes n{0x1F, 0x8B, 0x08, 0x08, 0, 0, 0, 0, 0, 3, 'a', 'b'};
    f = scan_one(n, "gzip");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].attrs.at("original_name"), "ab");
    Bytes t{0x1F, 0x8B, 0x08};
    f = scan_one(t, "gzip");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].diagnostics[0].code, "gzip-truncated-header");
}

TEST(XzValidator, StreamFlagsCrc) {
    Bytes b{0xFD, '7', 'z', 'X', 'Z', 0x00, 0x00, 0x04, 0, 0, 0, 0, 0xAA};
    test::put_u32le(b, 8, test::crc_zlib(b, 6, 2));
    auto f = scan_one(b, "xz");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].attrs.at("check"), "crc64");
    b[8] ^= 1;
    f = scan_one(b, "xz");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_EQ(f[0].diagnostics[0].code, "xz-header-crc-mismatch");
    b[7] = 0x33;  // invalid flags
    f = scan_one(b, "xz");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    Bytes t{0xFD, '7', 'z', 'X', 'Z', 0x00, 0x00};
    f = scan_one(t, "xz");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].diagnostics[0].code, "xz-truncated-header");
}

TEST(Lz4Validator, FrameDescriptor) {
    Bytes b{0x04, 0x22, 0x4D, 0x18, 0x6C, 0x70, 0x10, 0x27, 0, 0, 0, 0, 0, 0, 0x33, 0xAA};
    auto f = scan_one(b, "lz4-frame");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].attrs.at("block_max_size"), "4MiB");
    EXPECT_EQ(f[0].attrs.at("content_size"), "10000");
    EXPECT_EQ(f[0].attrs.at("block_independence"), "true");
    b[4] = 0x2C;  // version 0
    f = scan_one(b, "lz4-frame");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    b[4] = 0x6C;
    b[5] = 0x71;  // reserved BD bit
    f = scan_one(b, "lz4-frame");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    Bytes t{0x04, 0x22, 0x4D, 0x18, 0x64};
    f = scan_one(t, "lz4-frame");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].diagnostics[0].code, "lz4-truncated-header");
}

TEST(ZstdValidator, FrameHeader) {
    // FHD 0xE4: FCS 8 bytes, single segment, checksum; then 8-byte content size.
    Bytes b{0x28, 0xB5, 0x2F, 0xFD, 0xE4, 0x10, 0x27, 0, 0, 0, 0, 0, 0, 0xFF};
    auto f = scan_one(b, "zstd");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].attrs.at("frame_content_size"), "10000");
    EXPECT_EQ(f[0].attrs.at("single_segment"), "true");
    EXPECT_EQ(f[0].attrs.at("content_checksum"), "true");
    EXPECT_EQ(f[0].attrs.at("header_len"), "13");
    Bytes w{0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x58, 0xFF};  // window descriptor only
    f = scan_one(w, "zstd");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].attrs.at("window_size"), "2097152");
    b[4] = 0x08;  // reserved bit
    f = scan_one(b, "zstd");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    Bytes t{0x28, 0xB5, 0x2F, 0xFD};
    f = scan_one(t, "zstd");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].diagnostics[0].code, "zstd-truncated-header");
}

// ----------------------------------------------------------- android sparse

Bytes sparse_image() {
    Bytes b(28 + 12 + 4096 * 2 + 16 + 12 + 16, 0);
    test::put_u32le(b, 0, 0x3AFF26ED);
    test::put_u16le(b, 4, 1);
    test::put_u16le(b, 6, 0);
    test::put_u16le(b, 8, 28);
    test::put_u16le(b, 10, 12);
    test::put_u32le(b, 12, 4096);
    test::put_u32le(b, 16, 2 + 3 + 4);
    test::put_u32le(b, 20, 4);
    std::size_t o = 28;
    test::put_u16le(b, o, 0xCAC1);
    test::put_u32le(b, o + 4, 2);
    test::put_u32le(b, o + 8, 12 + 8192);
    o += 12 + 8192;
    test::put_u16le(b, o, 0xCAC2);
    test::put_u32le(b, o + 4, 3);
    test::put_u32le(b, o + 8, 16);
    o += 16;
    test::put_u16le(b, o, 0xCAC3);
    test::put_u32le(b, o + 4, 4);
    test::put_u32le(b, o + 8, 12);
    o += 12;
    test::put_u16le(b, o, 0xCAC4);
    test::put_u32le(b, o + 4, 0);
    test::put_u32le(b, o + 8, 16);
    o += 16;
    return b;
}

TEST(SparseValidator, WalksChunks) {
    const Bytes b = sparse_image();
    auto f = scan_one(b, "android-sparse");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].size, b.size());
    EXPECT_EQ(f[0].attrs.at("output_size"), "36864");
    EXPECT_EQ(f[0].attrs.at("raw_chunks"), "1");
    EXPECT_EQ(f[0].attrs.at("fill_chunks"), "1");
    EXPECT_EQ(f[0].attrs.at("dont_care_chunks"), "1");
    EXPECT_EQ(f[0].attrs.at("crc_chunks"), "1");
}

TEST(SparseValidator, HostileChunks) {
    Bytes b = sparse_image();
    test::put_u32le(b, 20, 0xFFFFFFFFu);  // absurd chunk count: walk stops at the data end
    auto f = scan_one(b, "android-sparse");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].attrs.at("chunks_walked"), "4");
    b = sparse_image();
    test::put_u32le(b, 28 + 8, 0xFFFFFFF0u);  // raw chunk claims far past the span
    f = scan_one(b, "android-sparse");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    b = sparse_image();
    test::put_u32le(b, 12, 4094);  // block size not a multiple of 4
    f = scan_one(b, "android-sparse");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    b = sparse_image();
    test::put_u16le(b, 4, 2);
    f = scan_one(b, "android-sparse");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].diagnostics[0].code, "sparse-unknown-version");
    b = sparse_image();
    test::put_u32le(b, 16, 5);  // total_blks disagrees
    f = scan_one(b, "android-sparse");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].diagnostics[0].code, "sparse-block-count-mismatch");
}

// --------------------------------------------------- all validators, hostile

TEST(AllValidators, NeverReadOutsideAndSurviveTruncation) {
    // Every builtin signature planted at the end of a buffer so that the
    // structure is cut off at every possible length: no crash, no hang.
    for (const Signature& sig : SignatureSet::builtin().signatures) {
        if (sig.validator.empty()) continue;
        const Validator* v = ValidatorRegistry::instance().find(sig.validator);
        ASSERT_NE(v, nullptr);
        for (std::size_t len = 0; len < 130; ++len) {
            Bytes buf(static_cast<std::size_t>(sig.magic_offset) + len, 0xFF);
            if (len >= sig.magic.size())
                std::copy(sig.magic.begin(), sig.magic.end(),
                          buf.begin() + static_cast<std::ptrdiff_t>(sig.magic_offset));
            const auto r = (*v)(test::span_of(buf), 0, sig);
            if (r) {
                EXPECT_LE(r->offset + r->size, buf.size()) << sig.name;
            }
            (void)(*v)(test::span_of(buf), UINT64_MAX - 3, sig);  // start past the end
            (void)(*v)(Span{}, 0, sig);
        }
    }
}

}  // namespace
