// ubifs.cpp — UBIFS superblock node validator.
//
// Every UBIFS node starts with the 24-byte common header (little-endian):
//    0 magic 0x06101831   4 crc u32   8 sqnum u64   16 len u32   20 node_type u8
//   21 group_type u8   22 pad[2]
// crc is crc32 (init 0xFFFFFFFF, no final xor) over bytes 8..len. The
// superblock node (type 6, len 4096) sits at the start of LEB 0:
//   24 pad[2]  26 key_hash u8  27 key_fmt u8  28 flags u32  32 min_io_size u32
//   36 leb_size u32  40 leb_cnt u32  44 max_leb_cnt u32  48 max_bud_bytes u64
//   56 log_lebs u32  60 lpt_lebs u32  64 orph_lebs u32  68 jhead_cnt u32
//   72 fanout u32  76 lsave_cnt u32  80 fmt_version u32  84 default_compr u16
//   88 rp_uid u32  92 rp_gid u32  96 rp_size u64  104 time_gran u32
//  108 uuid[16]  124 ro_compat_version u32  128 hmac[64]  192 hmac_wkm[64]
//  256 hash_algo u16  258 hash_mst[64]
// Reference: Linux fs/ubifs/ubifs-media.h
#include <array>

#include "../crc32.h"
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint8_t kSbNode = 6;
constexpr std::uint32_t kSbNodeSize = 4096;
constexpr std::uint32_t kMaxFmtVersion = 5;

std::string compr_name(std::uint16_t v) {
    static const char* names[] = {"none", "lzo", "zlib", "zstd"};
    return v < sizeof(names) / sizeof(names[0]) ? names[v] : "unknown(" + dec(v) + ")";
}

std::optional<Finding> validate_ubifs(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    std::array<std::uint8_t, 272> raw{};
    if (span.read(start, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size())
        return std::nullopt;
    auto u32 = [&](std::size_t o) {
        return load_int<std::uint32_t>(raw.data() + o, Endian::Little);
    };
    auto u16 = [&](std::size_t o) {
        return load_int<std::uint16_t>(raw.data() + o, Endian::Little);
    };
    const std::uint32_t crc = u32(4);
    const std::uint64_t sqnum = load_int<std::uint64_t>(raw.data() + 8, Endian::Little);
    const std::uint32_t len = u32(16);
    const std::uint8_t node_type = raw[20];
    // The node magic is shared by every UBIFS node; only the superblock node
    // anchors a filesystem. Other node types are the body of a filesystem
    // whose superblock is (or was) elsewhere.
    if (node_type != kSbNode || len != kSbNodeSize) return std::nullopt;
    const std::uint8_t key_hash = raw[26], key_fmt = raw[27];
    const std::uint32_t flags = u32(28), min_io_size = u32(32), leb_size = u32(36),
                        leb_cnt = u32(40), max_leb_cnt = u32(44), log_lebs = u32(56),
                        lpt_lebs = u32(60), orph_lebs = u32(64), jhead_cnt = u32(68),
                        fanout = u32(72), lsave_cnt = u32(76), fmt_version = u32(80);
    const std::uint16_t default_compr = u16(84);
    const std::uint32_t ro_compat = u32(124);
    const std::uint64_t rp_size = load_int<std::uint64_t>(raw.data() + 96, Endian::Little);

    // Alignment: a superblock starts a LEB, which starts at a min_io_size
    // (or at least sector) boundary. Elsewhere it is a copy inside other data.
    const bool aligned = (min_io_size != 0 && start % min_io_size == 0) || start % 512 == 0;
    if (!aligned) return std::nullopt;

    Finding f = make_finding(sig, start, Confidence::Magic);
    f.endian = Endian::Little;
    const bool sane = is_pow2(min_io_size) && leb_size >= min_io_size &&
                      leb_size % min_io_size == 0 && leb_cnt >= 1 && leb_cnt <= max_leb_cnt &&
                      fmt_version >= 1 && fmt_version <= kMaxFmtVersion && key_hash <= 1 &&
                      key_fmt == 0 && fanout >= 3 && default_compr <= 3;
    if (!sane) {
        diag(f, Severity::Warning, "ubifs-bad-superblock",
             "superblock fields out of range (min_io " + dec(min_io_size) + ", leb_size " +
                 dec(leb_size) + ", leb_cnt " + dec(leb_cnt) + "/" + dec(max_leb_cnt) +
                 ", fmt_version " + dec(fmt_version) + ")");
        return f;
    }
    f.confidence = Confidence::Structural;
    f.attrs["fmt_version"] = dec(fmt_version);
    f.attrs["ro_compat_version"] = dec(ro_compat);
    f.attrs["min_io_size"] = dec(min_io_size);
    f.attrs["leb_size"] = dec(leb_size);
    f.attrs["leb_cnt"] = dec(leb_cnt);
    f.attrs["max_leb_cnt"] = dec(max_leb_cnt);
    f.attrs["log_lebs"] = dec(log_lebs);
    f.attrs["lpt_lebs"] = dec(lpt_lebs);
    f.attrs["orph_lebs"] = dec(orph_lebs);
    f.attrs["jhead_cnt"] = dec(jhead_cnt);
    f.attrs["fanout"] = dec(fanout);
    f.attrs["lsave_cnt"] = dec(lsave_cnt);
    f.attrs["key_hash"] = key_hash == 0 ? "r5" : "test";
    f.attrs["flags"] = hex_fixed(flags, 8);
    f.attrs["default_compr"] = compr_name(default_compr);
    f.attrs["rp_size"] = dec(rp_size);
    f.attrs["sqnum"] = dec(sqnum);
    f.attrs["uuid"] = uuid_raw(std::span<const std::uint8_t>(raw.data() + 108, 16));
    if (fmt_version >= 5) f.attrs["hash_algo"] = dec(u16(256));

    // LEB budget: superblock (1) + master area (2) + log + LPT + orphans must fit.
    const std::uint64_t reserved = 3ull + log_lebs + lpt_lebs + orph_lebs;
    const bool consistent =
        log_lebs >= 2 && lpt_lebs >= 2 && orph_lebs >= 1 && jhead_cnt >= 1 && reserved < leb_cnt;
    if (!consistent)
        diag(f, Severity::Warning, "ubifs-bad-leb-layout",
             "log/lpt/orphan LEB counts do not fit into leb_cnt " + dec(leb_cnt));

    const std::uint64_t claimed = static_cast<std::uint64_t>(leb_size) * leb_cnt;
    bool truncated = false;
    f.size = clamp_size(span, start, claimed, truncated);
    if (truncated)
        diag(f, Severity::Info, "ubifs-truncated",
             "leb_size * leb_cnt (" + dec(claimed) +
                 " bytes) extends past the available data; inside a UBI volume the LEBs "
                 "are not contiguous anyway");

    const auto computed = crc32_span(span, start + 8, kSbNodeSize - 8, 0xFFFFFFFFu, 0u);
    if (computed && *computed == crc) {
        f.attrs["crc_check"] = "ok";
        if (consistent) f.confidence = Confidence::Verified;
    } else {
        f.attrs["crc_check"] = computed ? "mismatch" : "unchecked";
        if (computed)
            diag(f, Severity::Warning, "ubifs-crc-mismatch",
                 "superblock node CRC32 does not match");
        if (consistent) f.confidence = Confidence::Consistent;
    }
    f.evidence = "UBIFS fmt " + dec(fmt_version) + ", LEB " + dec(leb_size) + " x " + dec(leb_cnt) +
                 ", min_io " + dec(min_io_size) + ", " + compr_name(default_compr) + ", crc " +
                 f.attrs["crc_check"];
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("ubifs", validate_ubifs);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(ubifs)
