// partition_test.cpp — the partition-table contract (docs/formats/partition-tables.md):
//   1. a table finding covers the table's own bytes, never the disk it describes;
//   2. MBR/GPT candidates must be sector aligned and structurally sane;
//   3. a backup GPT header yields the partition list when the primary is gone;
//   4. conflict resolution never lets a filesystem or container swallow a table;
//   5. the corpus images (skipped when absent) behave as the examiner expects.
#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>

#include "helpers.h"

using namespace omnitrace;
using namespace omnitrace::discovery;
using test::Bytes;

namespace {

constexpr std::uint64_t kSector = 512;
constexpr std::uint64_t kMiB = 1u << 20;

bool has_diag(const Finding& f, const char* code) {
    for (const Diagnostic& d : f.diagnostics)
        if (d.code == code) return true;
    return false;
}

std::string diag_message(const Finding& f, const char* code) {
    for (const Diagnostic& d : f.diagnostics)
        if (d.code == code) return d.message;
    return {};
}

std::size_t count_format(const std::vector<Finding>& v, const char* format) {
    std::size_t n = 0;
    for (const Finding& f : v) n += f.format == format;
    return n;
}

// ---------------------------------------------------------------- builders

void mbr_entry(Bytes& b, std::size_t base, int i, std::uint8_t status, std::uint8_t type,
               std::uint32_t lba, std::uint32_t n) {
    const std::size_t o = base + 446 + static_cast<std::size_t>(i) * 16;
    b[o] = status;
    b[o + 4] = type;
    test::put_u32le(b, o + 8, lba);
    test::put_u32le(b, o + 12, n);
}

void boot_signature(Bytes& b, std::size_t sector) {
    b[sector * kSector + 510] = 0x55;
    b[sector * kSector + 511] = 0xAA;
}

struct GptPart {
    std::uint64_t first, last;
    const char16_t* name;
};

// A `sectors`-sector disk: primary header at `primary_lba` (entries right
// after it, protective MBR right before it), backup header at the last sector
// with its entry array (32 sectors) right before it. 128 entries of 128 bytes.
Bytes gpt_disk(std::uint64_t sectors, const std::vector<GptPart>& parts,
               std::uint64_t primary_lba = 1) {
    Bytes b(static_cast<std::size_t>(sectors * kSector), 0);
    // Protective MBR in the sector before the header (LBA 0 normally; Audio
    // puts it at 12288 beside its header at 12289).
    const std::size_t pm = static_cast<std::size_t>((primary_lba - 1) * kSector);
    b[pm + 510] = 0x55;
    b[pm + 511] = 0xAA;
    mbr_entry(b, pm, 0, 0, 0xEE, static_cast<std::uint32_t>(primary_lba),
              static_cast<std::uint32_t>(sectors - primary_lba));
    const std::size_t h = static_cast<std::size_t>(primary_lba * kSector);
    const std::size_t e = h + kSector;
    const std::size_t array_bytes = 128 * 128;
    test::put_bytes(b, h, "EFI PART");
    test::put_u32le(b, h + 8, 0x00010000);
    test::put_u32le(b, h + 12, 92);
    test::put_u64le(b, h + 24, primary_lba);
    test::put_u64le(b, h + 32, sectors - 1);
    test::put_u64le(b, h + 40, primary_lba + 33);
    test::put_u64le(b, h + 48, sectors - 34);
    for (std::size_t i = 0; i < 16; ++i) b[h + 56 + i] = static_cast<std::uint8_t>(0x10 + i);
    test::put_u64le(b, h + 72, primary_lba + 1);
    test::put_u32le(b, h + 80, 128);
    test::put_u32le(b, h + 84, 128);
    const std::uint8_t linux_guid[16] = {0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47,
                                         0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4};
    for (std::size_t p = 0; p < parts.size(); ++p) {
        const std::size_t o = e + p * 128;
        std::copy(linux_guid, linux_guid + 16, b.begin() + static_cast<std::ptrdiff_t>(o));
        for (std::size_t i = 0; i < 16; ++i) b[o + 16 + i] = static_cast<std::uint8_t>(p + i);
        test::put_u64le(b, o + 32, parts[p].first);
        test::put_u64le(b, o + 40, parts[p].last);
        for (std::size_t i = 0; parts[p].name[i] != 0; ++i)
            test::put_u16le(b, o + 56 + i * 2, static_cast<std::uint16_t>(parts[p].name[i]));
    }
    test::put_u32le(b, h + 88, test::crc_zlib(b, e, array_bytes));
    test::put_u32le(b, h + 16, test::crc_zlib(b, h, 92));
    // Backup.
    const std::size_t bh = static_cast<std::size_t>((sectors - 1) * kSector);
    const std::size_t be = bh - array_bytes;
    std::copy(b.begin() + static_cast<std::ptrdiff_t>(e),
              b.begin() + static_cast<std::ptrdiff_t>(e + array_bytes),
              b.begin() + static_cast<std::ptrdiff_t>(be));
    std::copy(b.begin() + static_cast<std::ptrdiff_t>(h),
              b.begin() + static_cast<std::ptrdiff_t>(h + 92),
              b.begin() + static_cast<std::ptrdiff_t>(bh));
    test::put_u64le(b, bh + 24, sectors - 1);
    test::put_u64le(b, bh + 32, primary_lba);
    test::put_u64le(b, bh + 72, be / kSector);
    test::put_u32le(b, bh + 16, 0);
    test::put_u32le(b, bh + 16, test::crc_zlib(b, bh, 92));
    return b;
}

const std::vector<GptPart> kTwoParts = {{64, 2047, u"boot"}, {2048, 4000, u"rootfs"}};

// Minimal ext4 superblock at `base` + 1024 describing `blocks` 1 KiB blocks
// (the same shape as validators_test.cpp's ext_image).
void put_ext4(Bytes& b, std::size_t base, std::uint32_t blocks) {
    const std::size_t sb = base + 1024;
    const std::uint32_t bpg = 8192, ipg = 128;
    const std::uint32_t groups = (blocks - 1 + bpg - 1) / bpg;
    test::put_u32le(b, sb + 0x00, groups * ipg);
    test::put_u32le(b, sb + 0x04, blocks);
    test::put_u32le(b, sb + 0x14, 1);
    test::put_u32le(b, sb + 0x18, 0);
    test::put_u32le(b, sb + 0x20, bpg);
    test::put_u32le(b, sb + 0x28, ipg);
    test::put_u32le(b, sb + 0x2C, 1700000000);
    test::put_u32le(b, sb + 0x30, 1700000001);
    test::put_u16le(b, sb + 0x38, 0xEF53);
    test::put_u16le(b, sb + 0x3A, 1);
    test::put_u32le(b, sb + 0x4C, 1);
    test::put_u16le(b, sb + 0x58, 256);
    test::put_u32le(b, sb + 0x5C, 0x4);
    test::put_u32le(b, sb + 0x60, 0x42);
    test::put_u32le(b, sb + 0x64, 0x2C2);
    for (std::size_t i = 0; i < 16; ++i) b[sb + 0x68 + i] = static_cast<std::uint8_t>(i * 17);
    test::put_bytes(b, sb + 0x78, "rootfs");
}

// A verified uImage header at 0 whose payload is [64, 64 + data_size).
void put_uimage(Bytes& b, std::uint32_t data_size) {
    test::put_u32be(b, 0, 0x27051956);
    test::put_u32be(b, 8, 1700000000);
    test::put_u32be(b, 12, data_size);
    test::put_u32be(b, 16, 0x80000000);
    test::put_u32be(b, 20, 0x80000000);
    test::put_u32be(b, 24, test::crc_zlib(b, 64, data_size));
    b[28] = 5;
    b[29] = 5;
    b[30] = 2;
    b[31] = 3;
    test::put_bytes(b, 32, "kernel-over-table");
    test::put_u32be(b, 4, test::crc_zlib(b, 0, 64));
}

// Deterministic pseudo-random bytes (xorshift), so "noise" is reproducible.
Bytes noise(std::size_t n, std::uint32_t seed) {
    Bytes b(n);
    std::uint32_t x = seed;
    for (std::size_t i = 0; i < n; ++i) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        b[i] = static_cast<std::uint8_t>(x);
    }
    return b;
}

std::vector<Finding> scan_tables(const Bytes& b) {
    return scan(test::span_of(b), test::only({"mbr", "gpt", "gpt-4k"}));
}

// ------------------------------------------------------------------ corpus

const char* kCorpus = "/home/wrongbaud/projects/omnitrace-v2/corpus";

// [off, off + len) of a corpus file, or nullopt when the file is absent or
// short. Reads only the slice: the images are up to 15 GB.
std::optional<Bytes> corpus_slice(const std::string& rel, std::uint64_t off, std::size_t len) {
    const std::filesystem::path p = std::filesystem::path(kCorpus) / rel;
    std::error_code ec;
    if (!std::filesystem::exists(p, ec)) return std::nullopt;
    std::ifstream in(p, std::ios::binary);
    if (!in) return std::nullopt;
    in.seekg(static_cast<std::streamoff>(off));
    Bytes b(len);
    in.read(reinterpret_cast<char*>(b.data()), static_cast<std::streamsize>(len));
    if (static_cast<std::size_t>(in.gcount()) != len) return std::nullopt;
    return b;
}

}  // namespace

// ------------------------------------------------------------------- MBR

TEST(PartitionTable, MbrPrimariesAndEbrChainAreOneTable) {
    // p1 0x83 [8, 108), p2 0x0C [200, 300), p3 extended [400, 1000) holding
    // three logicals via a chain of three EBRs.
    Bytes b(static_cast<std::size_t>(1100 * kSector), 0);
    boot_signature(b, 0);
    test::put_u32le(b, 440, 0x0BADC0DE);
    mbr_entry(b, 0, 0, 0x80, 0x83, 8, 100);
    mbr_entry(b, 0, 1, 0x00, 0x0C, 200, 100);
    mbr_entry(b, 0, 2, 0x00, 0x05, 400, 600);
    boot_signature(b, 400);
    mbr_entry(b, 400 * kSector, 0, 0x00, 0x83, 1, 99);     // p5 [401, 500)
    mbr_entry(b, 400 * kSector, 1, 0x00, 0x05, 100, 200);  // next EBR at 500
    boot_signature(b, 500);
    mbr_entry(b, 500 * kSector, 0, 0x00, 0x82, 1, 199);  // p6 [501, 700)
    mbr_entry(b, 500 * kSector, 1, 0x00, 0x05, 300, 300);
    boot_signature(b, 700);
    mbr_entry(b, 700 * kSector, 0, 0x00, 0x83, 1, 299);  // p7 [701, 1000)

    const auto found = scan_tables(b);
    ASSERT_EQ(found.size(), 1u) << "EBRs must not be reported as tables of their own";
    const Finding& f = found[0];
    EXPECT_EQ(f.offset, 0u);
    EXPECT_EQ(f.size, kSector);
    EXPECT_EQ(f.category, "partition-table");
    EXPECT_EQ(f.confidence, Confidence::Consistent);
    EXPECT_EQ(f.attrs.at("table"), "mbr-primary");
    EXPECT_EQ(f.attrs.at("partitions"),
              "p1:4096:51200:0x83:boot;p2:102400:51200:0x0c;p3:204800:307200:0x05;"
              "p5:205312:50688:0x83:logical;p6:256512:101888:0x82:logical;"
              "p7:358912:153088:0x83:logical");
    EXPECT_EQ(f.attrs.at("partition_count"), "6");
    EXPECT_EQ(f.attrs.at("disk_size"), std::to_string(1000 * kSector));
    EXPECT_EQ(f.attrs.at("disk_offset"), "0");
    EXPECT_EQ(f.attrs.at("disk_signature"), "0x0badc0de");
    EXPECT_EQ(f.attrs.at("also_covers"), "204800:512;256000:512;358400:512");
    EXPECT_EQ(f.attrs.count("protective"), 0u);
}

TEST(PartitionTable, MbrCandidatesInNoiseAreRejected) {
    // 256 KiB of noise with 0x55AA planted at many unaligned offsets, each
    // followed by whatever bytes the noise has in the entry slots.
    Bytes b = noise(256 * 1024, 0xC0FFEE);
    for (std::size_t off = 511; off + 2 <= b.size(); off += 4099) {
        b[off] = 0x55;
        b[off + 1] = 0xAA;
    }
    EXPECT_TRUE(scan_tables(b).empty());

    // Aligned 0x55AA with garbage entries (status bytes that are not
    // 0x00/0x80, starts beyond the data) is rejected as well.
    Bytes g = noise(64 * 1024, 0xBEEF);
    for (std::size_t s = 0; s < g.size() / kSector; ++s) boot_signature(g, s);
    EXPECT_TRUE(scan_tables(g).empty());

    // An MBR whose only entries are empty (a VBR) is rejected.
    Bytes vbr(8192, 0);
    boot_signature(vbr, 0);
    EXPECT_TRUE(scan_tables(vbr).empty());

    // The same table is accepted the moment it is sector aligned.
    Bytes ok(16 * 1024, 0);
    boot_signature(ok, 4);
    mbr_entry(ok, 4 * kSector, 0, 0x00, 0x83, 8, 16);
    auto found = scan_tables(ok);
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].offset, 4 * kSector);
    EXPECT_EQ(found[0].size, kSector);
    Bytes shifted(ok.begin(), ok.end());
    shifted.insert(shifted.begin(), 3, 0);
    EXPECT_TRUE(scan_tables(shifted).empty());
}

TEST(PartitionTable, ProtectiveMbrIsTagged) {
    const Bytes b = gpt_disk(4096, kTwoParts);
    const auto found = scan(test::span_of(b), test::only({"mbr"}));
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].attrs.at("protective"), "true");
    EXPECT_EQ(found[0].attrs.at("partitions"), "p1:512:2096640:0xee");
    EXPECT_EQ(found[0].size, kSector);
    EXPECT_EQ(found[0].attrs.at("disk_size"), std::to_string(4096 * kSector));
}

// ------------------------------------------------------------------- GPT

TEST(PartitionTable, GptPrimaryAndBackupAreConsistent) {
    const Bytes b = gpt_disk(4096, kTwoParts);
    const auto found = scan_tables(b);
    ASSERT_EQ(found.size(), 2u);
    const Finding& primary = found[0];
    const Finding& backup = found[1];

    EXPECT_EQ(primary.offset, 0u);
    EXPECT_EQ(primary.size, 0x4400u);  // LBA 0 + header + 128 * 128 entries
    EXPECT_EQ(primary.confidence, Confidence::Verified);
    EXPECT_EQ(primary.attrs.at("table"), "gpt-primary");
    EXPECT_EQ(primary.attrs.at("header_lba"), "1");
    EXPECT_EQ(primary.attrs.at("entries_lba"), "2");
    EXPECT_EQ(primary.attrs.at("alternate_lba"), "4095");
    EXPECT_EQ(primary.attrs.at("disk_guid"), "13121110-1514-1716-1819-1a1b1c1d1e1f");
    EXPECT_EQ(primary.attrs.at("disk_offset"), "0");
    EXPECT_EQ(primary.attrs.at("disk_size"), std::to_string(4096 * kSector));
    EXPECT_EQ(primary.attrs.at("entry_array_crc"), "ok");
    EXPECT_EQ(primary.attrs.at("backup"), "valid");
    EXPECT_EQ(primary.attrs.at("partition_count"), "2");
    EXPECT_EQ(primary.attrs.at("partitions"),
              "p1:32768:1015808:0fc63daf-8483-4772-8e79-3d69d8477de4:03020100-0504-0706-0809-"
              "0a0b0c0d0e0f:boot;"
              "p2:1048576:999936:0fc63daf-8483-4772-8e79-3d69d8477de4:04030201-0605-0807-090a-"
              "0b0c0d0e0f10:rootfs");
    ASSERT_EQ(primary.also_matched.size(), 1u);
    EXPECT_EQ(primary.also_matched[0].format, "mbr");
    EXPECT_NE(primary.evidence.find("entry array CRC ok"), std::string::npos);

    EXPECT_EQ(backup.offset, b.size() - 33 * kSector);
    EXPECT_EQ(backup.size, 33 * kSector);  // 32 sectors of entries + the header
    EXPECT_EQ(backup.confidence, Confidence::Verified);
    EXPECT_EQ(backup.attrs.at("table"), "gpt-backup");
    EXPECT_EQ(backup.attrs.at("header_lba"), "4095");
    EXPECT_EQ(backup.attrs.at("entries_lba"), "4063");
    EXPECT_EQ(backup.attrs.at("alternate_lba"), "1");
    EXPECT_EQ(backup.attrs.at("primary"), "valid");
    EXPECT_EQ(backup.attrs.at("disk_offset"), "0");
    EXPECT_EQ(backup.attrs.at("disk_size"), std::to_string(4096 * kSector));
    EXPECT_EQ(backup.attrs.at("partitions"), primary.attrs.at("partitions"));
    EXPECT_TRUE(has_diag(backup, "gpt-backup"));
    EXPECT_EQ(diag_message(backup, "gpt-backup"), "backup header, matches primary");
    EXPECT_FALSE(has_diag(backup, "gpt-primary-missing"));
}

TEST(PartitionTable, GptDestroyedPrimaryIsRecoveredFromBackup) {
    Bytes b = gpt_disk(4096, kTwoParts);
    // Wipe LBA 1 and the primary entry array with noise, as a bad erase would.
    const Bytes junk = noise(0x4200, 0xDEAD);
    std::copy(junk.begin(), junk.end(), b.begin() + 512);
    const auto found = scan_tables(b);
    // The protective MBR at LBA 0 survived and is a table of its own now
    // that no GPT sits at the same offset; the backup is the other one.
    ASSERT_EQ(found.size(), 2u);
    EXPECT_EQ(found[0].format, "mbr");
    EXPECT_EQ(found[0].attrs.at("protective"), "true");
    const Finding& backup = found[1];
    EXPECT_EQ(backup.attrs.at("table"), "gpt-backup");
    EXPECT_EQ(backup.offset, b.size() - 33 * kSector);
    EXPECT_EQ(backup.size, 33 * kSector);
    EXPECT_EQ(backup.confidence, Confidence::Verified);
    EXPECT_EQ(backup.attrs.at("partition_count"), "2");
    EXPECT_EQ(backup.attrs.at("partitions"),
              "p1:32768:1015808:0fc63daf-8483-4772-8e79-3d69d8477de4:03020100-0504-0706-0809-"
              "0a0b0c0d0e0f:boot;"
              "p2:1048576:999936:0fc63daf-8483-4772-8e79-3d69d8477de4:04030201-0605-0807-090a-"
              "0b0c0d0e0f10:rootfs");
    EXPECT_EQ(backup.attrs.at("primary"), "invalid");
    EXPECT_EQ(backup.attrs.at("entry_array_crc"), "ok");
    EXPECT_TRUE(has_diag(backup, "gpt-primary-missing"));
    EXPECT_EQ(diag_message(backup, "gpt-primary-missing"),
              "primary GPT header at LBA 1 is invalid; partition list recovered from the backup "
              "header at LBA 4095");
    EXPECT_FALSE(has_diag(backup, "gpt-backup"));
}

TEST(PartitionTable, GptBackupThatDisagreesWithPrimaryIsFlagged) {
    Bytes b = gpt_disk(4096, kTwoParts);
    // Repartitioned primary whose backup was never rewritten: different array.
    const std::size_t bh = b.size() - 512;
    const std::size_t be = bh - 128 * 128;
    test::put_u64le(b, be + 40, 3000);  // p1 last_lba changed in the backup array only
    test::put_u32le(b, bh + 88, test::crc_zlib(b, be, 128 * 128));
    test::put_u32le(b, bh + 16, 0);
    test::put_u32le(b, bh + 16, test::crc_zlib(b, bh, 92));
    const auto found = scan_tables(b);
    ASSERT_EQ(found.size(), 2u);
    EXPECT_EQ(found[0].attrs.at("backup"), "mismatch");
    EXPECT_TRUE(has_diag(found[0], "gpt-backup-mismatch"));
    EXPECT_EQ(found[1].attrs.at("primary"), "mismatch");
    EXPECT_TRUE(has_diag(found[1], "gpt-backup-mismatch"));
    EXPECT_NE(found[0].attrs.at("partitions"), found[1].attrs.at("partitions"));
}

TEST(PartitionTable, GptPrimaryAtVendorLbaKeepsDiskOrigin) {
    // audio-style: primary header at LBA 12289 rather than 1, my_lba honest.
    // 16 MiB so the relocated protective MBR's entry still starts inside the
    // data when read relative to its own sector (see Known gaps in the doc).
    const Bytes b = gpt_disk(32768, kTwoParts, 12289);
    const auto found = scan_tables(b);
    ASSERT_EQ(found.size(), 2u);
    const Finding& primary = found[0];
    EXPECT_EQ(primary.attrs.at("table"), "gpt-primary");
    EXPECT_EQ(primary.offset, 12288 * kSector);  // the sector before the header
    EXPECT_EQ(primary.size, 0x4400u);
    EXPECT_EQ(primary.attrs.at("header_lba"), "12289");
    EXPECT_EQ(primary.attrs.at("disk_offset"), "0");
    EXPECT_EQ(primary.attrs.at("disk_size"), std::to_string(32768 * kSector));
    EXPECT_EQ(primary.attrs.at("backup"), "valid");
    EXPECT_EQ(primary.confidence, Confidence::Verified);
    ASSERT_EQ(primary.also_matched.size(), 1u);  // protective MBR at 12288
    EXPECT_EQ(primary.also_matched[0].attrs.at("protective"), "true");
    EXPECT_EQ(found[1].attrs.at("table"), "gpt-backup");
    EXPECT_EQ(found[1].attrs.at("primary"), "valid");
    EXPECT_EQ(found[1].attrs.at("disk_offset"), "0");
}

TEST(PartitionTable, GptCarvedBackupSliceStillYieldsPartitions) {
    // Only the last 33 sectors of the disk: LBA 0 and the primary are gone.
    const Bytes disk = gpt_disk(4096, kTwoParts);
    const Bytes slice(disk.end() - 33 * 512, disk.end());
    const auto found = scan_tables(slice);
    ASSERT_EQ(found.size(), 1u);
    const Finding& backup = found[0];
    EXPECT_EQ(backup.attrs.at("table"), "gpt-backup");
    EXPECT_EQ(backup.offset, 0u);
    EXPECT_EQ(backup.size, slice.size());
    EXPECT_EQ(backup.attrs.at("partition_count"), "2");
    EXPECT_EQ(backup.attrs.count("disk_offset"), 0u);  // LBA 0 is before the data
    EXPECT_TRUE(has_diag(backup, "gpt-origin-outside"));
    EXPECT_EQ(backup.attrs.at("primary"), "outside");
    EXPECT_TRUE(has_diag(backup, "gpt-primary-missing"));
    EXPECT_NE(diag_message(backup, "gpt-primary-missing").find("outside the data"),
              std::string::npos);
    EXPECT_EQ(backup.confidence, Confidence::Verified);
}

// A GPT header whose leading "EFI " has been cleared, with the CRC computed
// over the cleared bytes. Seen on an automotive Android unit VCUNH unit's 116 GiB user LUN; the four
// tests below are the whole rule, and each one fails if a different half of it
// is removed.
Bytes gpt_disk_cleared_sig(bool recompute_crc) {
    Bytes b = gpt_disk(4096, kTwoParts);
    for (std::size_t i = 0; i < 4; ++i) b[kSector + i] = 0;
    if (recompute_crc) {
        test::put_u32le(b, kSector + 16, 0);
        test::put_u32le(b, kSector + 16, test::crc_zlib(b, kSector, 92));
    }
    return b;
}

TEST(PartitionTable, GptClearedSignatureIsReadWhenTheCrcCoversIt) {
    const Bytes b = gpt_disk_cleared_sig(/*recompute_crc=*/true);
    const auto found = scan(test::span_of(b),
                            test::only({"gpt", "gpt-4k", "gpt-cleared-sig", "gpt-cleared-sig-4k"}));
    ASSERT_GE(found.size(), 1u);
    const Finding& primary = found[0];
    EXPECT_EQ(primary.signature, "gpt-cleared-sig");
    EXPECT_EQ(primary.attrs.at("table"), "gpt-primary");
    EXPECT_EQ(primary.confidence, Confidence::Verified);
    EXPECT_EQ(primary.attrs.at("partition_count"), "2");
    EXPECT_EQ(primary.attrs.at("signature_bytes"), "0000000050415254");
    EXPECT_TRUE(has_diag(primary, "gpt-signature-nonstandard"));
}

TEST(PartitionTable, GptClearedSignatureWithoutTheCrcIsNotAFindingAtAll) {
    // The point of the gate: without "EFI PART" the CRC is the only evidence,
    // so a failed one yields nothing rather than the usual magic-tier hit. A
    // magic-tier finding here would put 8 coincidental bytes in the manifest
    // and, worse, give the region an extent.
    const Bytes b = gpt_disk_cleared_sig(/*recompute_crc=*/false);
    const auto found = scan(test::span_of(b),
                            test::only({"gpt", "gpt-4k", "gpt-cleared-sig", "gpt-cleared-sig-4k"}));
    for (const Finding& f : found) EXPECT_NE(f.signature, "gpt-cleared-sig");
}

TEST(PartitionTable, GptBackupDoesNotCallAClearedPrimaryMissing) {
    // The backup names LBA 1 as its alternate. Before the signature bytes were
    // widened it found no magic there and reported the primary destroyed --
    // which would have an examiner hunting for a table that is intact.
    const Bytes b = gpt_disk_cleared_sig(/*recompute_crc=*/true);
    const auto found = scan(test::span_of(b),
                            test::only({"gpt", "gpt-4k", "gpt-cleared-sig", "gpt-cleared-sig-4k"}));
    ASSERT_EQ(found.size(), 2u);
    const Finding& backup = found[1];
    ASSERT_EQ(backup.attrs.at("table"), "gpt-backup");
    EXPECT_EQ(backup.attrs.at("alternate"), "valid");
    EXPECT_EQ(backup.attrs.at("primary"), "valid");
    EXPECT_FALSE(has_diag(backup, "gpt-primary-missing"));
    EXPECT_TRUE(has_diag(backup, "gpt-backup"));
}

TEST(PartitionTable, GptSpecSignatureWithABadCrcStillReportsItself) {
    // The gate applies only to the cleared form. An "EFI PART" header that
    // fails its CRC is damaged evidence an examiner still wants to see, and it
    // keeps the behaviour it always had.
    Bytes b = gpt_disk(4096, kTwoParts);
    test::put_u32le(b, kSector + 16, 0xDEADBEEF);
    const auto found = scan(test::span_of(b),
                            test::only({"gpt", "gpt-4k", "gpt-cleared-sig", "gpt-cleared-sig-4k"}));
    ASSERT_GE(found.size(), 1u);
    EXPECT_EQ(found[0].signature, "gpt");
    EXPECT_TRUE(has_diag(found[0], "gpt-header-crc-mismatch"));
    EXPECT_FALSE(has_diag(found[0], "gpt-signature-nonstandard"));
    EXPECT_GE(found[0].confidence, Confidence::Structural);
}

TEST(PartitionTable, GptHostileHeadersNeverClaimTheDisk) {
    Bytes b = gpt_disk(4096, kTwoParts);
    // Entry array pointer into the far future: the header stays a 2-sector
    // finding with a diagnostic, nothing else changes.
    test::put_u64le(b, 512 + 72, 1ull << 60);
    auto found = scan(test::span_of(b), test::only({"gpt"}));
    ASSERT_GE(found.size(), 1u);
    EXPECT_EQ(found[0].offset, 0u);
    EXPECT_EQ(found[0].size, 2 * kSector);
    EXPECT_TRUE(has_diag(found[0], "gpt-entries-outside"));
    EXPECT_EQ(found[0].attrs.count("partitions"), 0u);

    // my_lba == alternate_lba cannot be a header: magic-only finding.
    b = gpt_disk(4096, kTwoParts);
    test::put_u64le(b, 512 + 32, 1);
    found = scan(test::span_of(b), test::only({"gpt"}));
    ASSERT_GE(found.size(), 1u);
    EXPECT_EQ(found[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(found[0], "gpt-bad-my-lba"));

    // Entries with a type GUID but no extent are skipped, not partitions.
    b = gpt_disk(4096, kTwoParts);
    const std::size_t e2 = 1024 + 2 * 128;
    b[e2] = 0xAF;  // non-zero type GUID, LBAs 0..0
    test::put_u32le(b, 512 + 88, test::crc_zlib(b, 1024, 128 * 128));
    test::put_u32le(b, 512 + 16, 0);
    test::put_u32le(b, 512 + 16, test::crc_zlib(b, 512, 92));
    found = scan(test::span_of(b), test::only({"gpt"}));
    ASSERT_GE(found.size(), 1u);
    EXPECT_EQ(found[0].attrs.at("partition_count"), "2");
    EXPECT_TRUE(has_diag(found[0], "gpt-entry-invalid"));
}

// ------------------------------------------------------- conflict resolution

TEST(PartitionTable, TableAndFilesystemInsidePartitionBothStayTopLevel) {
    // GPT at 0 describing p2 at 1 MiB; an ext4 of 1000 1-KiB blocks at 1 MiB.
    Bytes b = gpt_disk(4096, kTwoParts);
    put_ext4(b, static_cast<std::size_t>(kMiB), 1000);
    const auto found = scan(test::span_of(b), test::only({"mbr", "gpt", "ext"}));
    const Finding* gpt = test::find_at(found, 0, "gpt");
    const Finding* ext = test::find_at(found, kMiB);
    ASSERT_NE(gpt, nullptr);
    ASSERT_NE(ext, nullptr);
    EXPECT_EQ(ext->format, "ext4");
    EXPECT_EQ(gpt->size, 0x4400u);
    EXPECT_TRUE(gpt->also_matched.size() == 1 && gpt->also_matched[0].format == "mbr");
    EXPECT_TRUE(ext->also_matched.empty());
    EXPECT_EQ(found.size(), 3u);  // gpt, ext4, backup gpt
}

TEST(PartitionTable, TableIsNeverAbsorbedByAContainerAtTheSameOffset) {
    // A verified uImage whose header occupies bytes 0..63 of LBA 0 and whose
    // payload runs over the whole GPT: without the rule the GPT (same offset,
    // same confidence, smaller) would vanish into also_matched.
    Bytes b = gpt_disk(4096, kTwoParts);
    put_uimage(b, 0x8000);
    const auto found = scan(test::span_of(b), test::only({"mbr", "gpt", "uimage"}));
    const Finding* img = test::find_at(found, 0, "uimage");
    const Finding* gpt = test::find_at(found, 0, "gpt");
    ASSERT_NE(img, nullptr);
    ASSERT_NE(gpt, nullptr);
    EXPECT_EQ(img->confidence, Confidence::Verified);
    EXPECT_EQ(gpt->confidence, Confidence::Verified);
    EXPECT_TRUE(img->also_matched.empty());
    ASSERT_EQ(gpt->also_matched.size(), 1u);  // the protective MBR, a table too
    EXPECT_EQ(gpt->also_matched[0].format, "mbr");
    EXPECT_EQ(found.size(), 3u);  // uimage, gpt, backup gpt

    // A higher-confidence container that strictly contains the backup table
    // does not absorb it either.
    Bytes c(static_cast<std::size_t>(64 * kSector), 0);
    boot_signature(c, 8);
    mbr_entry(c, 8 * kSector, 0, 0x00, 0x83, 10, 4);
    put_uimage(c, static_cast<std::uint32_t>(c.size() - 64 - 100));
    const auto nested = scan(test::span_of(c), test::only({"mbr", "uimage"}));
    ASSERT_EQ(nested.size(), 2u);
    EXPECT_EQ(nested[0].format, "uimage");
    EXPECT_EQ(nested[1].format, "mbr");
    EXPECT_TRUE(nested[0].also_matched.empty());
}

TEST(PartitionTable, OrderingIsDeterministic) {
    Bytes b = gpt_disk(4096, kTwoParts);
    put_ext4(b, static_cast<std::size_t>(kMiB), 1000);
    put_uimage(b, 0x8000);
    const auto a = scan(test::span_of(b), SignatureSet::builtin());
    const auto c = scan(test::span_of(b), SignatureSet::builtin());
    ASSERT_EQ(a.size(), c.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        EXPECT_EQ(a[i].offset, c[i].offset);
        EXPECT_EQ(a[i].signature, c[i].signature);
        EXPECT_EQ(a[i].attrs, c[i].attrs);
    }
    for (std::size_t i = 1; i < a.size(); ++i) EXPECT_LE(a[i - 1].offset, a[i].offset);
}

// ---------------------------------------------------------------- corpus

TEST(PartitionCorpus, HyundaiKiaGptFirstMiB) {
    const auto slice = corpus_slice("auto-ivi-example/flash/UserData.BIN", 0, kMiB);
    if (!slice) GTEST_SKIP() << "corpus image missing";
    const auto found = scan(test::span_of(*slice), SignatureSet::builtin());
    const Finding* gpt = test::find_at(found, 0, "gpt");
    ASSERT_NE(gpt, nullptr);
    EXPECT_EQ(gpt->size, 0x4400u);
    EXPECT_EQ(gpt->attrs.at("table"), "gpt-primary");
    EXPECT_EQ(gpt->attrs.at("partition_count"), "18");
    EXPECT_EQ(gpt->attrs.at("disk_size"), "3841982464");
    EXPECT_EQ(gpt->attrs.at("disk_offset"), "0");
    EXPECT_EQ(gpt->attrs.at("entry_array_crc"), "ok");
    EXPECT_EQ(gpt->confidence, Confidence::Verified);
    EXPECT_EQ(gpt->attrs.at("backup"), "outside");
    EXPECT_TRUE(has_diag(*gpt, "gpt-disk-truncated"));
    EXPECT_NE(gpt->attrs.at("partitions").find(":dtb;"), std::string::npos);
    EXPECT_NE(gpt->attrs.at("partitions").find(":log_ext"), std::string::npos);
    ASSERT_EQ(gpt->also_matched.size(), 1u);
    EXPECT_EQ(gpt->also_matched[0].format, "mbr");
    EXPECT_EQ(gpt->also_matched[0].attrs.at("protective"), "true");
    // The findings inside the disk are not swallowed by the table, and no
    // other table is invented.
    EXPECT_GT(found.size(), 1u);
    EXPECT_EQ(count_format(found, "gpt"), 1u);
    EXPECT_EQ(count_format(found, "mbr"), 0u);
}

TEST(PartitionCorpus, SonosBackupGptFromCarvedSlice) {
    // Entry array (LBA 7339999, 32 sectors) + backup header (LBA 7340031).
    const auto slice = corpus_slice("audio-example/flash/UserData.BIN", 7339999ull * 512, 0x4200);
    if (!slice) GTEST_SKIP() << "corpus image missing";
    const auto found = scan(test::span_of(*slice), SignatureSet::builtin());
    const Finding* gpt = test::find_at(found, 0, "gpt");
    ASSERT_NE(gpt, nullptr);
    EXPECT_EQ(gpt->attrs.at("table"), "gpt-backup");
    EXPECT_EQ(gpt->size, 0x4200u);
    EXPECT_EQ(gpt->attrs.at("header_lba"), "7340031");
    EXPECT_EQ(gpt->attrs.at("entries_lba"), "7339999");
    EXPECT_EQ(gpt->attrs.at("alternate_lba"), "12289");
    EXPECT_EQ(gpt->attrs.at("partition_count"), "10");
    EXPECT_EQ(gpt->attrs.at("entry_array_crc"), "ok");
    EXPECT_EQ(gpt->confidence, Confidence::Verified);
    EXPECT_EQ(gpt->attrs.at("primary"), "outside");
    EXPECT_TRUE(has_diag(*gpt, "gpt-primary-missing"));
    EXPECT_TRUE(has_diag(*gpt, "gpt-entry-invalid"));  // the stale 11th slot
    const std::string& parts = gpt->attrs.at("partitions");
    for (const char* name : {":micdata", ":mdp", ":ddp", ":wifical", ":kern0", ":rootfs0", ":kern1",
                             ":rootfs1", ":jffs", ":hwv_scratch"})
        EXPECT_NE(parts.find(name), std::string::npos) << name;
    EXPECT_EQ(gpt->attrs.at("disk_size"), "3758096384");
}

TEST(PartitionCorpus, SonosPrimaryGptAtVendorLba) {
    // audio keeps its primary GPT at LBA 12289 (0x600200), protective MBR at
    // LBA 12288; LBA 1 is not a GPT header at all.
    const auto slice = corpus_slice("audio-example/flash/UserData.BIN", 0, 0x610000);
    if (!slice) GTEST_SKIP() << "corpus image missing";
    const auto found = scan(test::span_of(*slice), test::only({"mbr", "gpt", "gpt-4k"}));
    const Finding* gpt = test::find_at(found, 0x600000, "gpt");
    ASSERT_NE(gpt, nullptr);
    EXPECT_EQ(gpt->attrs.at("table"), "gpt-primary");
    EXPECT_EQ(gpt->size, 0x4400u);
    EXPECT_EQ(gpt->attrs.at("header_lba"), "12289");
    EXPECT_EQ(gpt->attrs.at("disk_offset"), "0");
    EXPECT_EQ(gpt->attrs.at("partition_count"), "10");
    EXPECT_EQ(gpt->attrs.at("disk_size"), "3758096384");
    EXPECT_EQ(gpt->confidence, Confidence::Verified);
    // The protective MBR at LBA 12288 addresses LBA 12289 disk-absolute; in
    // this short slice that lies past the data, so it is rejected rather
    // than reported with a wrong offset. Nothing at LBA 1 is a GPT.
    EXPECT_TRUE(gpt->also_matched.empty());
    EXPECT_EQ(test::find_at(found, 0, "gpt"), nullptr);
    EXPECT_EQ(found.size(), 1u);
}

TEST(PartitionCorpus, NissanNoiseYieldsNoMbr) {
    // 2 MiB around the unaligned 0x55AA hits that used to produce six false
    // MBRs (one at 0x83107fe3 claiming 5.6 GB).
    const auto slice =
        corpus_slice("auto-emmc-example/flash/auto-emmc.bin", 0x83000000ull, 2 * kMiB);
    if (!slice) GTEST_SKIP() << "corpus image missing";
    const auto found = scan(test::span_of(*slice), test::only({"mbr", "gpt", "gpt-4k"}));
    EXPECT_EQ(found.size(), 0u);
    for (const Finding& f : found) ADD_FAILURE() << f.format << " at " << f.offset;
}
