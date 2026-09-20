// qnx6_validator_test.cpp — the QNX6 superblock validator: a hand-built
// minimal instance (both byte orders), hostile variants (bad checksums, a
// missing second superblock, an impossible block size, a huge num_blocks, a
// root pointer past the data area, an unaligned hit) and the corpus slices
// when the evidence image is present (GTEST_SKIP otherwise).
#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <map>

#include "helpers.h"

using namespace omnitrace;
using namespace omnitrace::discovery;
using test::Bytes;

// The validator lives in src/discovery/validators/qnx6.cpp; its static
// registrar only survives static linking when something references the
// object file. builtin.cpp's OMNITRACE_TOUCH_ANCHOR(qnx6) line does that for
// every binary; this test references the anchor directly as well so it does
// not depend on that line being present.
namespace omnitrace::discovery::detail {
void omnitrace_validator_anchor_qnx6();
}
namespace {
const bool kAnchored = (omnitrace::discovery::detail::omnitrace_validator_anchor_qnx6(), true);

std::vector<Finding> scan_one(const Bytes& buf, const char* signature) {
    return scan(test::span_of(buf), test::only({signature}));
}

bool has_diag(const Finding& f, const char* code) {
    for (const Diagnostic& d : f.diagnostics)
        if (d.code == code) return true;
    return false;
}

// CRC-32, polynomial 0x04C11DB7, MSB first, seed 0, no final xor, bit by bit.
std::uint32_t sb_crc(const std::uint8_t* p, std::size_t n) {
    std::uint32_t crc = 0;
    for (std::size_t i = 0; i < n; ++i) {
        crc ^= static_cast<std::uint32_t>(p[i]) << 24;
        for (int k = 0; k < 8; ++k)
            crc = (crc & 0x80000000u) ? (crc << 1) ^ 0x04C11DB7u : (crc << 1);
    }
    return crc;
}

struct Params {
    Endian e = Endian::Little;
    std::uint32_t bs = 4096, nb = 64;
    std::uint64_t serial0 = 10, serial1 = 11;
    bool second = true;
    std::uint32_t root_ptr = 1;          // inode table block
    std::uint32_t num_blocks_field = 0;  // 0: nb
};

void put16(Bytes& b, std::size_t off, std::uint16_t v, Endian e) {
    if (e == Endian::Little)
        test::put_u16le(b, off, v);
    else
        test::put_u16be(b, off, v);
}
void put32(Bytes& b, std::size_t off, std::uint32_t v, Endian e) {
    if (e == Endian::Little)
        test::put_u32le(b, off, v);
    else
        test::put_u32be(b, off, v);
}
void put64(Bytes& b, std::size_t off, std::uint64_t v, Endian e) {
    if (e == Endian::Little)
        test::put_u64le(b, off, v);
    else
        test::put_u64be(b, off, v);
}

Bytes superblock(const Params& p, std::uint64_t serial) {
    Bytes sb(512, 0);
    put32(sb, 0, 0x68191122u, p.e);
    put64(sb, 8, serial, p.e);
    put32(sb, 16, 1600000000u, p.e);
    put32(sb, 20, 1600000001u, p.e);
    put32(sb, 24, 0x302, p.e);
    put16(sb, 28, 4, p.e);
    put16(sb, 30, 3, p.e);
    for (std::size_t i = 0; i < 16; ++i) sb[32 + i] = static_cast<std::uint8_t>(i);
    put32(sb, 48, p.bs, p.e);
    put32(sb, 52, 32, p.e);
    put32(sb, 56, 30, p.e);
    put32(sb, 60, p.num_blocks_field ? p.num_blocks_field : p.nb, p.e);
    put32(sb, 64, p.nb - 3, p.e);
    put32(sb, 68, 1, p.e);
    for (std::size_t r = 0; r < 5; ++r) {
        const std::size_t at = 72 + 80 * r;
        for (std::size_t i = 0; i < 16; ++i) put32(sb, at + 8 + 4 * i, 0xFFFFFFFFu, p.e);
        sb[at + 73] = 1;
    }
    put64(sb, 72, 32 * 128, p.e);  // inode table: 32 records
    put32(sb, 72 + 8, p.root_ptr, p.e);
    put64(sb, 152, 16, p.e);  // bitmap: 16 bytes
    put32(sb, 152 + 8, 0, p.e);
    put32(sb, 4, sb_crc(sb.data() + 8, 504), p.e);
    return sb;
}

// A QNX6 image with two superblocks and a root inode; no directory data.
Bytes image(const Params& p) {
    const std::uint64_t data_start = (0x3000 + p.bs - 1) / p.bs * p.bs;
    const std::uint64_t tail = (0x1000 + p.bs - 1) / p.bs * p.bs;
    Bytes b(static_cast<std::size_t>(data_start + std::uint64_t{p.nb} * p.bs + tail), 0);
    b[0] = 0xEB;
    b[1] = 0x10;
    b[2] = 0x90;
    const Bytes sb0 = superblock(p, p.serial0);
    std::copy(sb0.begin(), sb0.end(), b.begin() + 0x2000);
    if (p.second) {
        const Bytes sb1 = superblock(p, p.serial1);
        std::copy(sb1.begin(), sb1.end(),
                  b.begin() + static_cast<std::ptrdiff_t>(data_start + std::uint64_t{p.nb} * p.bs));
    }
    // root inode (ino 1) in block 1: a directory of size 0
    const std::size_t root = static_cast<std::size_t>(data_start + p.bs);
    put16(b, root + 32, 0040755, p.e);
    return b;
}

const std::string kCorpus = "/home/wrongbaud/projects/omnitrace-v2/corpus/";

std::optional<Span> corpus_slice(const std::string& rel, std::uint64_t off, std::uint64_t len,
                                 std::shared_ptr<MappedFile>& keep) {
    const std::string path = kCorpus + rel;
    if (!std::filesystem::exists(path)) return std::nullopt;
    if (!MappedFile::open(path, keep)) return std::nullopt;
    return Span::whole(keep).sub(off, len);
}

}  // namespace

TEST(Qnx6Validator, MinimalImageIsVerified) {
    for (const Endian e : {Endian::Little, Endian::Big}) {
        Params p;
        p.e = e;
        const Bytes b = image(p);
        const auto f = scan_one(b, e == Endian::Little ? "qnx6-le" : "qnx6-be");
        ASSERT_EQ(f.size(), 1u) << "second superblock must be covered, not a second finding";
        EXPECT_EQ(f[0].offset, 0u);
        EXPECT_EQ(f[0].format, "qnx6");
        EXPECT_EQ(f[0].confidence, Confidence::Verified) << f[0].evidence;
        EXPECT_EQ(f[0].size, b.size());
        EXPECT_EQ(f[0].endian, e);
        EXPECT_EQ(f[0].attrs.at("blocksize"), "4096");
        EXPECT_EQ(f[0].attrs.at("num_blocks"), "64");
        EXPECT_EQ(f[0].attrs.at("num_inodes"), "32");
        EXPECT_EQ(f[0].attrs.at("free_inodes"), "30");
        EXPECT_EQ(f[0].attrs.at("free_blocks"), "61");
        EXPECT_EQ(f[0].attrs.at("serial"), "11");
        EXPECT_EQ(f[0].attrs.at("second_serial"), "11");
        EXPECT_EQ(f[0].attrs.at("current_superblock"), "secondary");
        EXPECT_EQ(f[0].attrs.at("second_superblock_offset"), "0x43000");
        EXPECT_EQ(f[0].attrs.at("data_start"), "0x3000");
        EXPECT_EQ(f[0].attrs.at("endian"), e == Endian::Little ? "little" : "big");
        EXPECT_EQ(f[0].attrs.at("ctime"), "1600000000");
        EXPECT_EQ(f[0].attrs.at("atime"), "1600000001");
        EXPECT_EQ(f[0].attrs.at("flags"), "0x302");
        EXPECT_EQ(f[0].attrs.at("root_levels"), "0");
        EXPECT_EQ(f[0].attrs.at("blocks_per_group"), "1");
        EXPECT_EQ(f[0].attrs.at("version"), "4.3");
        EXPECT_EQ(f[0].attrs.at("volume_id"), "000102030405060708090a0b0c0d0e0f");
        EXPECT_TRUE(f[0].diagnostics.empty()) << f[0].diagnostics[0].message;
    }
}

TEST(Qnx6Validator, LargerBlockSizeMovesTheDataArea) {
    Params p;
    p.bs = 16384;
    p.nb = 8;
    const Bytes b = image(p);
    const auto f = scan_one(b, "qnx6-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified);
    EXPECT_EQ(f[0].attrs.at("data_start"), "0x4000");
    EXPECT_EQ(f[0].attrs.at("second_superblock_offset"), "0x24000");
    EXPECT_EQ(f[0].size, b.size());
}

TEST(Qnx6Validator, HostileVariants) {
    {  // primary checksum bad: consistent, second is current
        Params p;
        Bytes b = image(p);
        b[0x2000 + 20] ^= 1;
        const auto f = scan_one(b, "qnx6-le");
        ASSERT_EQ(f.size(), 1u);
        EXPECT_EQ(f[0].confidence, Confidence::Consistent);
        EXPECT_TRUE(has_diag(f[0], "qnx6-superblock-bad-crc"));
        EXPECT_EQ(f[0].attrs.at("serial"), "11");
    }
    {  // both checksums bad: still consistent, higher serial wins
        Params p;
        p.serial0 = 20;
        Bytes b = image(p);
        b[0x2000 + 20] ^= 1;
        b[0x43000 + 20] ^= 1;
        const auto f = scan_one(b, "qnx6-le");
        ASSERT_EQ(f.size(), 1u);
        EXPECT_EQ(f[0].confidence, Confidence::Consistent);
        EXPECT_EQ(f[0].attrs.at("serial"), "20");
        EXPECT_EQ(f[0].attrs.at("current_superblock"), "primary");
    }
    {  // no second superblock
        Params p;
        p.second = false;
        const Bytes b = image(p);
        const auto f = scan_one(b, "qnx6-le");
        ASSERT_EQ(f.size(), 1u);
        EXPECT_EQ(f[0].confidence, Confidence::Verified);
        EXPECT_TRUE(has_diag(f[0], "qnx6-superblock-single"));
        EXPECT_EQ(f[0].attrs.at("second_superblock_offset"), "none");
        EXPECT_EQ(f[0].attrs.at("serial"), "10");
    }
    {  // equal serials
        Params p;
        p.serial1 = 10;
        const auto f = scan_one(image(p), "qnx6-le");
        ASSERT_EQ(f.size(), 1u);
        EXPECT_TRUE(has_diag(f[0], "qnx6-serial-tie"));
        EXPECT_EQ(f[0].attrs.at("current_superblock"), "primary");
    }
    {  // block size not a power of two: the primary hit is magic tier with no
       // size; the hit on the second superblock recognises the filesystem at
       // offset 0 and describes it from that superblock alone
        Params p;
        Bytes b = image(p);
        test::put_u32le(b, 0x2000 + 48, 3000);
        // Conflict resolution keeps the verified one and absorbs the
        // magic-tier twin at the same offset into also_matched.
        const auto f = scan_one(b, "qnx6-le");
        ASSERT_EQ(f.size(), 1u);
        EXPECT_EQ(f[0].offset, 0u);
        EXPECT_EQ(f[0].confidence, Confidence::Verified) << f[0].evidence;
        EXPECT_EQ(f[0].size, b.size());
        EXPECT_TRUE(has_diag(f[0], "qnx6-bad-superblock"));
        EXPECT_EQ(f[0].attrs.at("serial"), "11");
        EXPECT_EQ(f[0].attrs.at("current_superblock"), "secondary");
        EXPECT_EQ(f[0].attrs.at("second_superblock_offset"), "0x43000");
        ASSERT_EQ(f[0].also_matched.size(), 1u);
        EXPECT_EQ(f[0].also_matched[0].confidence, Confidence::Magic);
        EXPECT_EQ(f[0].also_matched[0].size, 0u);
        EXPECT_TRUE(has_diag(f[0].also_matched[0], "qnx6-bad-superblock"));
        // Without resolution both are visible.
        ScanOptions raw;
        raw.resolve_conflicts = false;
        const auto both = scan(test::span_of(b), test::only({"qnx6-le"}), raw);
        ASSERT_EQ(both.size(), 2u);
        EXPECT_EQ(both[0].confidence, Confidence::Verified);
        EXPECT_EQ(both[1].confidence, Confidence::Magic);
    }
    {  // seven levels in the primary: same shape
        Params p;
        Bytes b = image(p);
        b[0x2000 + 72 + 72] = 7;
        const auto f = scan_one(b, "qnx6-le");
        ASSERT_EQ(f.size(), 1u);
        EXPECT_EQ(f[0].confidence, Confidence::Verified);
        EXPECT_TRUE(has_diag(f[0], "qnx6-bad-superblock"));
        ASSERT_EQ(f[0].also_matched.size(), 1u);
        EXPECT_EQ(f[0].also_matched[0].confidence, Confidence::Magic);
    }
    {  // primary wiped entirely: only the second superblock's hit remains
        Params p;
        Bytes b = image(p);
        std::fill(b.begin() + 0x2000, b.begin() + 0x2200, 0);
        const auto f = scan_one(b, "qnx6-le");
        ASSERT_EQ(f.size(), 1u);
        EXPECT_EQ(f[0].offset, 0u);
        EXPECT_EQ(f[0].confidence, Confidence::Verified) << f[0].evidence;
        EXPECT_EQ(f[0].size, b.size());
        EXPECT_TRUE(has_diag(f[0], "qnx6-bad-superblock"));
        EXPECT_EQ(f[0].attrs.at("serial"), "11");
    }
    {  // huge num_blocks: structural, truncated, clamped to the span. A
       // structural finding claims no coverage, so the second superblock's
       // hit (which cannot be tied to offset 0 with a bogus num_blocks)
       // yields a second, equally truncated finding.
        Params p;
        p.num_blocks_field = 0xFFFFFFFFu;
        const Bytes b = image(p);
        const auto f = scan_one(b, "qnx6-le");
        const Finding* first = test::find_at(f, 0, "qnx6");
        ASSERT_NE(first, nullptr);
        EXPECT_EQ(first->confidence, Confidence::Structural);
        EXPECT_TRUE(has_diag(*first, "qnx6-truncated"));
        EXPECT_EQ(first->size, b.size());
        for (const Finding& x : f) EXPECT_EQ(x.confidence, Confidence::Structural);
    }
    {  // root pointer past the data area: structural
        Params p;
        p.root_ptr = 64;
        const auto f = scan_one(image(p), "qnx6-le");
        ASSERT_EQ(f.size(), 1u);
        EXPECT_EQ(f[0].confidence, Confidence::Structural);
        EXPECT_TRUE(has_diag(f[0], "qnx6-bad-root-pointer"));
    }
    {  // unaligned: 512 bytes of padding in front, the scanner drops the hit
        Params p;
        const Bytes img = image(p);
        Bytes b(512, 0);
        b.insert(b.end(), img.begin(), img.end());
        EXPECT_TRUE(scan_one(b, "qnx6-le").empty());
    }
    {  // truncated inside the superblock area
        Params p;
        const Bytes img = image(p);
        const Bytes b(img.begin(), img.begin() + 0x2100);
        const auto f = scan_one(b, "qnx6-le");
        ASSERT_EQ(f.size(), 1u);
        EXPECT_EQ(f[0].confidence, Confidence::Magic);
        EXPECT_EQ(f[0].size, 0u);
        EXPECT_TRUE(has_diag(f[0], "qnx6-truncated"));
    }
}

TEST(Qnx6Validator, WrongByteOrderSignatureDoesNotMatch) {
    Params p;
    p.e = Endian::Big;
    EXPECT_TRUE(scan_one(image(p), "qnx6-le").empty());
    p.e = Endian::Little;
    EXPECT_TRUE(scan_one(image(p), "qnx6-be").empty());
}

TEST(Qnx6Validator, CorpusDpsMfg) {
    std::shared_ptr<MappedFile> keep;
    const auto slice = corpus_slice("qnx-example/flash/UserData.BIN", 0x800000, 4u << 20, keep);
    if (!slice) GTEST_SKIP() << "corpus image missing";
    const auto f = scan(*slice, test::only({"qnx6-le", "qnx6-be"}));
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].offset, 0u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified) << f[0].evidence;
    EXPECT_EQ(f[0].size, 4u << 20);
    EXPECT_EQ(f[0].attrs.at("blocksize"), "4096");
    EXPECT_EQ(f[0].attrs.at("num_blocks"), "1020");
    EXPECT_EQ(f[0].attrs.at("num_inodes"), "128");
    EXPECT_EQ(f[0].attrs.at("serial"), "16");
    EXPECT_EQ(f[0].attrs.at("second_serial"), "16");
    EXPECT_EQ(f[0].attrs.at("current_superblock"), "secondary");
    EXPECT_EQ(f[0].attrs.at("second_superblock_offset"), "0x3ff000");
    EXPECT_EQ(f[0].attrs.at("free_blocks"), "965");
    EXPECT_TRUE(f[0].diagnostics.empty());
}

TEST(Qnx6Validator, CorpusDpsOsSecondSuperblockDespiteBadBootBlockHint) {
    std::shared_ptr<MappedFile> keep;
    const auto slice = corpus_slice("qnx-example/flash/UserData.BIN", 0x1000000, 24u << 20, keep);
    if (!slice) GTEST_SKIP() << "corpus image missing";
    const auto f = scan(*slice, test::only({"qnx6-le"}));
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified) << f[0].evidence;
    EXPECT_EQ(f[0].size, 24u << 20);
    EXPECT_EQ(f[0].attrs.at("num_blocks"), "6140");
    EXPECT_EQ(f[0].attrs.at("root_levels"), "1");
    EXPECT_EQ(f[0].attrs.at("second_superblock_offset"), "0x17ff000");
    EXPECT_EQ(f[0].attrs.at("serial"), "5186");
    EXPECT_EQ(f[0].attrs.at("second_serial"), "5186");
    EXPECT_TRUE(f[0].diagnostics.empty());
}

TEST(Qnx6Validator, CorpusWholeImageNestedInstancesAreSized) {
    // The first 0x2900000 bytes hold dps_mfg (4 MiB at 0x800000) and dps_os
    // (24 MiB at 0x1000000); each must be one finding covering its second
    // superblock.
    std::shared_ptr<MappedFile> keep;
    const auto slice = corpus_slice("qnx-example/flash/UserData.BIN", 0, 0x2900000, keep);
    if (!slice) GTEST_SKIP() << "corpus image missing";
    const auto f = scan(*slice, test::only({"qnx6-le"}));
    ASSERT_EQ(f.size(), 2u);
    EXPECT_EQ(f[0].offset, 0x800000u);
    EXPECT_EQ(f[0].size, 4u << 20);
    EXPECT_EQ(f[1].offset, 0x1000000u);
    EXPECT_EQ(f[1].size, 24u << 20);
}
