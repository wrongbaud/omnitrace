// qnx6.cpp — QNX6 (Power-Safe, fs-qnx6) superblock validator.
//
// Layout (docs/formats/qnx6.md): the partition starts with a 0x2000-byte boot
// block, the primary superblock (512 bytes, magic 0x68191122) sits at 0x2000
// and the superblock area is 0x3000 bytes; data blocks follow at
// round_up(0x3000, blocksize). A second superblock lives right after the last
// data block (data_start + num_blocks * blocksize) and the two alternate on
// every commit: the one with the higher serial is the current snapshot, the
// other describes the previous one. The checksum is CRC-32 (polynomial
// 0x04C11DB7, MSB first, seed 0, no final xor) over bytes 8..511 of the
// superblock; the Linux driver (fs/qnx6/inode.c, read for understanding) and
// NFI qnxmount agree, and the corpus verifies it.
//
// Tiers: magic when the header is corrupt (with `qnx6-bad-superblock`);
// structural once blocksize, counts and levels are sane; consistent when the
// extent fits the Span and every root pointer lands inside the data area;
// verified when the primary superblock's CRC verifies. The size claimed is
// data_start + num_blocks * blocksize + the trailing superblock area, so the
// second superblock is inside the finding and the scanner's same-signature
// coverage rule hides its magic. Unaligned hits are rejected (real
// superblocks sit on a 4 KiB boundary; the signature carries alignment 4096).
#include <array>

#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint32_t kMagic = 0x68191122u;
constexpr std::uint64_t kBootblockSize = 0x2000;   // primary superblock offset
constexpr std::uint64_t kSuperblockSize = 0x1000;  // area each superblock occupies
constexpr std::uint64_t kSuperblockArea = 0x3000;  // boot block + primary superblock
constexpr std::uint64_t kSuperblockBytes = 512;    // bytes covered by the CRC (+8)
constexpr std::uint32_t kHole = 0xFFFFFFFFu;       // unused block pointer
constexpr unsigned kMaxLevels = 5;                 // QNX6_PTR_MAX_LEVELS
constexpr std::uint64_t kInodeSize = 128;
constexpr std::uint64_t kMinBlocksize = 512;
constexpr std::uint64_t kMaxBlocksize = 65536;
constexpr std::array<std::uint8_t, 4> kBootMagic = {0xEB, 0x10, 0x90, 0x00};

// CRC-32, polynomial 0x04C11DB7, MSB first, seed 0, no final xor (the
// kernel's crc32_be(0, ...)).
struct CrcBeTable {
    std::array<std::uint32_t, 256> t{};
    constexpr CrcBeTable() {
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i << 24;
            for (int k = 0; k < 8; ++k) c = (c & 0x80000000u) ? (c << 1) ^ 0x04C11DB7u : (c << 1);
            t[i] = c;
        }
    }
};
constexpr CrcBeTable kCrcBe{};

std::uint32_t crc32_be(std::span<const std::uint8_t> data) {
    std::uint32_t crc = 0;
    for (const std::uint8_t b : data) crc = kCrcBe.t[((crc >> 24) ^ b) & 0xFFu] ^ (crc << 8);
    return crc;
}

struct RootNode {
    std::uint64_t size = 0;
    std::array<std::uint32_t, 16> ptr{};
    std::uint8_t levels = 0;
    std::uint8_t mode = 0;
};

struct Super {
    std::uint64_t off = 0;  // Span-relative offset of the 512-byte superblock
    std::uint32_t crc = 0;
    std::uint64_t serial = 0;
    std::uint32_t ctime = 0, atime = 0, flags = 0;
    std::uint16_t version1 = 0, version2 = 0;
    std::array<std::uint8_t, 16> volumeid{};
    std::uint32_t blocksize = 0, num_inodes = 0, free_inodes = 0, num_blocks = 0, free_blocks = 0,
                  allocgroup = 0;
    RootNode inodes, bitmap, longfile, iclaim, iextra;
    bool crc_ok = false;
};

RootNode root_node(const std::array<std::uint8_t, 512>& raw, std::size_t at, Endian e) {
    RootNode r;
    r.size = load_int<std::uint64_t>(raw.data() + at, e);
    for (std::size_t i = 0; i < 16; ++i)
        r.ptr[i] = load_int<std::uint32_t>(raw.data() + at + 8 + 4 * i, e);
    r.levels = raw[at + 72];
    r.mode = raw[at + 73];
    return r;
}

// The superblock at `off`, if the magic matches in byte order `e`.
std::optional<Super> parse_super(const Span& span, std::uint64_t off, Endian e) {
    std::array<std::uint8_t, 512> raw{};
    if (span.read(off, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size())
        return std::nullopt;
    if (load_int<std::uint32_t>(raw.data(), e) != kMagic) return std::nullopt;
    Super s;
    s.off = off;
    s.crc = load_int<std::uint32_t>(raw.data() + 4, e);
    s.serial = load_int<std::uint64_t>(raw.data() + 8, e);
    s.ctime = load_int<std::uint32_t>(raw.data() + 16, e);
    s.atime = load_int<std::uint32_t>(raw.data() + 20, e);
    s.flags = load_int<std::uint32_t>(raw.data() + 24, e);
    s.version1 = load_int<std::uint16_t>(raw.data() + 28, e);
    s.version2 = load_int<std::uint16_t>(raw.data() + 30, e);
    std::copy(raw.begin() + 32, raw.begin() + 48, s.volumeid.begin());
    s.blocksize = load_int<std::uint32_t>(raw.data() + 48, e);
    s.num_inodes = load_int<std::uint32_t>(raw.data() + 52, e);
    s.free_inodes = load_int<std::uint32_t>(raw.data() + 56, e);
    s.num_blocks = load_int<std::uint32_t>(raw.data() + 60, e);
    s.free_blocks = load_int<std::uint32_t>(raw.data() + 64, e);
    s.allocgroup = load_int<std::uint32_t>(raw.data() + 68, e);
    s.inodes = root_node(raw, 72, e);
    s.bitmap = root_node(raw, 152, e);
    s.longfile = root_node(raw, 232, e);
    s.iclaim = root_node(raw, 312, e);
    s.iextra = root_node(raw, 392, e);
    s.crc_ok =
        crc32_be(std::span<const std::uint8_t>(raw.data() + 8, kSuperblockBytes - 8)) == s.crc;
    return s;
}

std::uint64_t round_up(std::uint64_t v, std::uint64_t to) {
    return to == 0 ? v : (v + to - 1) / to * to;
}

// First data block: the 0x3000-byte superblock area rounded up to a block.
std::uint64_t data_start_for(std::uint64_t blocksize) {
    return round_up(kSuperblockArea, blocksize);
}

bool root_pointers_inside(const RootNode& r, std::uint32_t num_blocks) {
    for (const std::uint32_t p : r.ptr)
        if (p != kHole && p >= num_blocks) return false;
    return true;
}

// Why a superblock cannot be used for geometry, or empty.
std::string super_problem(const Super& p) {
    if (!is_pow2(p.blocksize) || p.blocksize < kMinBlocksize || p.blocksize > kMaxBlocksize)
        return "blocksize " + dec(p.blocksize) + " is not a power of two in 512..65536";
    if (p.num_blocks == 0) return "num_blocks is 0";
    if (p.num_inodes == 0) return "num_inodes is 0";
    if (p.inodes.levels > kMaxLevels || p.bitmap.levels > kMaxLevels ||
        p.longfile.levels > kMaxLevels)
        return "a root node has " +
               dec(std::max({p.inodes.levels, p.bitmap.levels, p.longfile.levels})) +
               " levels of indirection (max 5)";
    if (p.inodes.size < kInodeSize)
        return "inode table size " + dec(p.inodes.size) + " cannot hold the root inode";
    return {};
}

// Extent of the data area a superblock describes: data_start + num_blocks *
// blocksize (the second superblock sits right after it).
std::uint64_t data_end_for(const Super& s) {
    return sat_add(data_start_for(s.blocksize), sat_mul(s.num_blocks, s.blocksize));
}

std::optional<Finding> validate_qnx6(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    if (start % 4096 != 0) return std::nullopt;  // real superblocks sit on a 4 KiB boundary
    const Endian e = sig.endian.value_or(Endian::Little);
    if (span.at<std::uint32_t>(start + kBootblockSize, e) != kMagic) return std::nullopt;
    const auto here = parse_super(span, start + kBootblockSize, e);
    if (!here) {
        Finding f = make_finding(sig, start, Confidence::Magic);
        f.endian = e;
        diag(f, Severity::Warning, "qnx6-truncated",
             "fewer than 512 bytes available for the superblock at +0x2000");
        f.evidence = "magic at +0x2000; superblock truncated";
        return f;
    }

    // The hit is normally the primary superblock of a filesystem starting at
    // `start`. It can also be the *second* superblock of a filesystem whose
    // primary is corrupt or wiped (an intact primary produces a finding that
    // covers this hit before it is ever seen): recognised when a boot block or
    // a superblock magic sits where that filesystem would begin.
    std::uint64_t fs_start = start;
    std::optional<Super> primary = here;
    std::optional<Super> secondary;
    bool from_second = false;
    if (super_problem(*here).empty()) {
        const std::uint64_t fs_len = data_end_for(*here);
        if (start + kBootblockSize >= fs_len) {
            const std::uint64_t p0 = start + kBootblockSize - fs_len;
            const auto prim = parse_super(span, p0 + kBootblockSize, e);
            if (p0 % 4096 == 0 && (prim || span.matches_at(p0, kBootMagic))) {
                if (prim && super_problem(*prim).empty() && prim->crc_ok)
                    return std::nullopt;  // the primary's own finding covers this hit
                fs_start = p0;
                primary = prim;
                secondary = here;
                from_second = true;
            }
        }
    }

    Finding f = make_finding(sig, fs_start, Confidence::Magic);
    f.endian = e;
    const std::string primary_problem = primary ? super_problem(*primary) : "no magic at +0x2000";
    if (!primary_problem.empty()) {
        diag(f, Severity::Warning, "qnx6-bad-superblock",
             "primary superblock unusable: " + primary_problem);
        if (!from_second) {
            f.evidence = "magic at +0x2000; superblock corrupt: " + primary_problem;
            return f;
        }
    }
    // Geometry comes from the primary when it is sound, else from the second.
    const Super& g = primary_problem.empty() ? *primary : *secondary;
    f.confidence = Confidence::Structural;

    const std::uint64_t data_start = data_start_for(g.blocksize);
    const std::uint64_t second_off = data_end_for(g);
    const std::uint64_t total = sat_add(second_off, round_up(kSuperblockSize, g.blocksize));

    f.attrs["blocksize"] = dec(g.blocksize);
    f.attrs["num_blocks"] = dec(g.num_blocks);
    f.attrs["num_inodes"] = dec(g.num_inodes);
    f.attrs["data_start"] = hex(data_start);
    f.attrs["endian"] = endian_name(e);

    bool truncated = false;
    f.size = clamp_size(span, fs_start, total, truncated);
    if (truncated) {
        diag(f, Severity::Warning, "qnx6-truncated",
             "num_blocks " + dec(g.num_blocks) + " x blocksize " + dec(g.blocksize) + " claims " +
                 dec(total) + " bytes, past the available data");
    }

    // Consistency: the three root trees point inside the data area.
    if (!root_pointers_inside(g.inodes, g.num_blocks) ||
        !root_pointers_inside(g.bitmap, g.num_blocks) ||
        !root_pointers_inside(g.longfile, g.num_blocks)) {
        diag(f, Severity::Warning, "qnx6-bad-root-pointer",
             "a root node pointer lies beyond num_blocks (" + dec(g.num_blocks) + ")");
    } else if (!truncated) {
        f.confidence = Confidence::Consistent;
    }

    // The second superblock: at its computed place, else where the boot
    // block's hint says (the hint is garbage on some images), else absent.
    if (!secondary && !truncated) secondary = parse_super(span, fs_start + second_off, e);
    if (!secondary && span.matches_at(fs_start, kBootMagic)) {
        for (const Endian he : {Endian::Little, Endian::Big}) {
            const auto sblk1 = span.at<std::uint32_t>(fs_start + 12, he);
            if (!sblk1) break;
            const std::uint64_t hint = sat_mul(*sblk1, 512);
            if (hint != kBootblockSize && hint < f.size) {
                secondary = parse_super(span, fs_start + hint, e);
                if (secondary) break;
            }
        }
    }
    if (secondary && !super_problem(*secondary).empty()) {
        diag(f, Severity::Warning, "qnx6-bad-superblock",
             "second superblock at " + hex(secondary->off - fs_start) +
                 " unusable: " + super_problem(*secondary));
        secondary.reset();
    }
    if (!primary_problem.empty()) primary.reset();

    if (primary && !primary->crc_ok)
        diag(f, Severity::Warning, "qnx6-superblock-bad-crc",
             "primary superblock checksum " + hex(primary->crc) + " does not verify");
    if (secondary && !secondary->crc_ok)
        diag(f, Severity::Warning, "qnx6-superblock-bad-crc",
             "second superblock at " + hex(secondary->off - fs_start) + " checksum " +
                 hex(secondary->crc) + " does not verify");
    if (!secondary) {
        diag(f, Severity::Info, "qnx6-superblock-single",
             "no second superblock at " + hex(second_off) + "; only one snapshot is available");
        f.attrs["second_superblock_offset"] = "none";
    } else {
        f.attrs["second_superblock_offset"] = hex(secondary->off - fs_start);
        f.attrs["second_serial"] = dec(secondary->serial);
        if (primary && secondary->serial == primary->serial)
            diag(f, Severity::Info, "qnx6-serial-tie",
                 "both superblocks carry serial " + dec(primary->serial) + "; the primary is used");
    }

    // Current snapshot: the checksum-valid one wins, then the higher serial,
    // then the primary (the kernel's rule).
    const Super* cur = primary ? &*primary : &*secondary;
    if (primary && secondary) {
        const Super& p = *primary;
        const Super& s = *secondary;
        if ((s.crc_ok && !p.crc_ok) || (s.crc_ok == p.crc_ok && s.serial > p.serial)) cur = &s;
    }
    f.attrs["current_superblock"] =
        cur == (primary ? &*primary : nullptr) ? "primary" : "secondary";
    f.attrs["serial"] = dec(cur->serial);
    f.attrs["ctime"] = dec(cur->ctime);
    f.attrs["atime"] = dec(cur->atime);
    f.attrs["flags"] = hex(cur->flags);
    f.attrs["version"] = dec(cur->version1) + "." + dec(cur->version2);
    f.attrs["volume_id"] = hex_bytes(cur->volumeid);
    f.attrs["free_inodes"] = dec(cur->free_inodes);
    f.attrs["free_blocks"] = dec(cur->free_blocks);
    f.attrs["blocks_per_group"] = dec(cur->allocgroup);
    f.attrs["root_levels"] = dec(cur->inodes.levels);
    f.attrs["inode_table_size"] = dec(cur->inodes.size);
    f.attrs["longfile_size"] = dec(cur->longfile.size);

    // Verified needs the checksum of the superblock the geometry came from.
    if (g.crc_ok && f.confidence == Confidence::Consistent) f.confidence = Confidence::Verified;

    f.evidence =
        (from_second
             ? "second superblock hit at +" + hex(start + kBootblockSize - fs_start) +
                   "; primary at +0x2000 " +
                   (primary ? "crc " + std::string(primary->crc_ok ? "ok" : "bad") : "unusable")
             : "superblock at +0x2000 (crc " + std::string(primary->crc_ok ? "ok" : "bad") + ")") +
        ", blocksize " + dec(g.blocksize) + ", " + dec(g.num_blocks) + " blocks, " +
        dec(g.num_inodes) + " inodes, serial " + dec(cur->serial) +
        (secondary ? ", second superblock at +" + hex(secondary->off - fs_start) + " serial " +
                         dec(secondary->serial) + (secondary->crc_ok ? " (crc ok)" : " (crc bad)")
                   : ", no second superblock");
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("qnx6", validate_qnx6);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(qnx6)
