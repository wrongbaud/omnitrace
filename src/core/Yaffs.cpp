// Yaffs.cpp — the YAFFS2 chunk grid. See the header for the format.
//
// Reference: yaffs2 `yaffs_guts.h`, `yaffs_packedtags2.c` and `yaffs_ecc.c`,
// read for understanding; nothing copied. Checked byte for byte against
// mkyaffs2 output in both spare layouts before this file was written.
#include "omnitrace/core/Yaffs.h"

#include <algorithm>
#include <array>

#include "omnitrace/core/Endian.h"

namespace omnitrace::yaffs {

namespace {

// `struct yaffs_obj_hdr` field offsets. type and parent_obj_id lead, then a
// u16 the format no longer uses, the name, and -- after two bytes of
// alignment padding -- everything else.
constexpr std::uint64_t kOffType = 0, kOffParent = 4, kOffName = 10;
constexpr std::uint64_t kNameMax = 256;  // YAFFS_MAX_NAME_LENGTH + 1
constexpr std::uint64_t kOffMode = 268, kOffUid = 272, kOffGid = 276;
constexpr std::uint64_t kOffAtime = 280, kOffMtime = 284, kOffCtime = 288;
constexpr std::uint64_t kOffSizeLow = 292, kOffEquiv = 296, kOffAlias = 300;
constexpr std::uint64_t kAliasMax = 160;  // YAFFS_MAX_ALIAS_LENGTH + 1
constexpr std::uint64_t kOffRdev = 460, kOffSizeHigh = 496, kOffShadows = 504,
                        kOffIsShrink = 508;
// The value YAFFS2 writes into a field it is not using.
constexpr std::uint32_t kUnset = 0xFFFFFFFFu;

// The parity of each bit of a byte, arranged the way yaffs_ecc.c does:
// bit 0 the byte's own parity, bits 2..7 the six column parities.
constexpr std::array<std::uint8_t, 256> build_column_parity_table() {
    std::array<std::uint8_t, 256> t{};
    for (unsigned v = 0; v < 256; ++v) {
        unsigned b[8];
        for (unsigned k = 0; k < 8; ++k) b[k] = (v >> k) & 1u;
        const unsigned p = b[0] ^ b[1] ^ b[2] ^ b[3] ^ b[4] ^ b[5] ^ b[6] ^ b[7];
        const unsigned cp0 = b[0] ^ b[2] ^ b[4] ^ b[6];
        const unsigned cp1 = b[1] ^ b[3] ^ b[5] ^ b[7];
        const unsigned cp2 = b[0] ^ b[1] ^ b[4] ^ b[5];
        const unsigned cp3 = b[2] ^ b[3] ^ b[6] ^ b[7];
        const unsigned cp4 = b[0] ^ b[1] ^ b[2] ^ b[3];
        const unsigned cp5 = b[4] ^ b[5] ^ b[6] ^ b[7];
        t[v] = static_cast<std::uint8_t>(p | (cp0 << 2) | (cp1 << 3) | (cp2 << 4) | (cp3 << 5) |
                                         (cp4 << 6) | (cp5 << 7));
    }
    return t;
}
constexpr std::array<std::uint8_t, 256> kColumnParity = build_column_parity_table();

// Page and spare sizes YAFFS2 is used with, largest first so a big grid is
// not mistaken for a small one that happens to line up. The spare of a NAND
// page is a thirty-second of it, except on the parts that give more room for
// the controller's own ECC.
//
// Small-page NAND (512 + 16) is absent on purpose: twenty-eight bytes of
// packed tags do not fit in a sixteen-byte spare, so those parts use the
// yaffs1 tag format or in-band tags, neither of which this reads.
struct Candidate {
    std::uint32_t page, spare;
};
constexpr std::array<Candidate, 8> kCandidates{{
    {16384, 1280}, {16384, 512}, {8192, 448}, {8192, 256},
    {4096, 224},   {4096, 128},  {2048, 128}, {2048, 64},
}};

std::uint32_t u32_at(const std::array<std::uint8_t, kPackedTagsSize>& b, std::size_t off) {
    return load_int<std::uint32_t>(b.data() + off, Endian::Little);
}

}  // namespace

Ecc ecc_of(std::span<const std::uint8_t> data) {
    std::uint8_t col = 0;
    std::uint32_t line = 0, line_prime = 0;
    for (std::size_t i = 0; i < data.size(); ++i) {
        const std::uint8_t b = kColumnParity[data[i]];
        col ^= b;
        if ((b & 0x01u) != 0) {  // the byte has an odd number of bits set
            line ^= static_cast<std::uint32_t>(i);
            line_prime ^= ~static_cast<std::uint32_t>(i);
        }
    }
    Ecc e;
    // Only six of the eight column parities are kept, and they are shifted
    // down before they are stored.
    e.col_parity = static_cast<std::uint8_t>((col >> 2) & 0x3Fu);
    e.line_parity = line;
    e.line_parity_prime = line_prime;
    return e;
}

bool read_tags(const Span& span, const Geometry& geo, std::uint64_t at, Tags& out) {
    out = Tags{};
    if (!geo.valid()) return false;
    std::array<std::uint8_t, kPackedTagsSize> raw{};
    const std::uint64_t tags_at = at + geo.page + geo.tags_offset;
    if (span.read(tags_at, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size())
        return false;

    out.erased = std::all_of(raw.begin(), raw.begin() + static_cast<std::ptrdiff_t>(kTagsSize),
                             [](std::uint8_t b) { return b == 0xFF; });
    out.seq = u32_at(raw, 0);
    out.obj_id = u32_at(raw, 4);
    out.chunk_id = u32_at(raw, 8);
    out.n_bytes = u32_at(raw, 12);
    if (out.erased) return true;

    const Ecc want{static_cast<std::uint8_t>(raw[16] & 0x3Fu), u32_at(raw, 20), u32_at(raw, 24)};
    out.ecc_ok = ecc_of(std::span<const std::uint8_t>(raw.data(), kTagsSize)) == want;

    if ((out.chunk_id & kExtraHeaderInfoFlag) != 0) {
        // A header chunk that also carries the object's summary: the parent
        // goes in chunk_id and the type in the top of obj_id, so both fields
        // have to be unpacked before they mean anything.
        out.extra = true;
        out.is_header = true;
        out.parent_id = out.chunk_id & ~kAllExtraFlags;
        out.is_shrink = (out.chunk_id & kExtraShrinkFlag) != 0;
        out.type = static_cast<ObjType>((out.obj_id >> kExtraObjectTypeShift) & 0x0Fu);
        out.obj_id &= ~(0x0Fu << kExtraObjectTypeShift);
        out.chunk_id = 0;
    } else {
        out.is_header = out.chunk_id == 0;
    }
    return true;
}

bool read_header(const Span& span, const Geometry& geo, std::uint64_t at, ObjHeader& out) {
    out = ObjHeader{};
    if (!geo.valid() || geo.page < kObjHeaderSize) return false;
    const auto page = span.bytes(at, static_cast<std::size_t>(kObjHeaderSize));
    if (!page) return false;
    auto u32 = [&](std::uint64_t off) {
        return load_int<std::uint32_t>(page->data() + off, Endian::Little);
    };
    auto str = [&](std::uint64_t off, std::uint64_t max) {
        const std::uint8_t* p = page->data() + off;
        std::uint64_t n = 0;
        while (n < max && p[n] != 0) ++n;
        return std::string(reinterpret_cast<const char*>(p), static_cast<std::size_t>(n));
    };

    const std::uint32_t type = u32(kOffType);
    if (type == 0 || type > static_cast<std::uint32_t>(ObjType::Special)) return false;
    out.type = static_cast<ObjType>(type);
    out.parent_id = u32(kOffParent);
    out.name = str(kOffName, kNameMax);
    out.mode = u32(kOffMode);
    out.uid = u32(kOffUid);
    out.gid = u32(kOffGid);
    out.atime = u32(kOffAtime);
    out.mtime = u32(kOffMtime);
    out.ctime = u32(kOffCtime);
    out.equiv_id = static_cast<std::int32_t>(u32(kOffEquiv));
    out.alias = str(kOffAlias, kAliasMax);
    out.rdev = u32(kOffRdev);
    out.shadows_obj = static_cast<std::int32_t>(u32(kOffShadows));
    out.is_shrink = u32(kOffIsShrink) != kUnset && u32(kOffIsShrink) != 0;

    if (out.type == ObjType::File) {
        // The high word is only written when the file needs it; unused, it is
        // all ones, not zero.
        const std::uint32_t lo = u32(kOffSizeLow);
        const std::uint32_t hi = u32(kOffSizeHigh);
        out.size = hi == kUnset ? lo : (static_cast<std::uint64_t>(hi) << 32) | lo;
    }
    return true;
}

bool detect_geometry(const Span& span, std::uint64_t at, std::uint64_t probe_chunks,
                     Geometry& out, bool require_header) {
    Geometry best;
    std::uint64_t best_score = 0;
    for (const Candidate& c : kCandidates) {
        for (const std::uint32_t tags_off : {std::uint32_t{0}, std::uint32_t{2}}) {
            Geometry geo;
            geo.page = c.page;
            geo.spare = c.spare;
            geo.tags_offset = tags_off;
            if (!geo.valid()) continue;
            // The chunk the magic landed in has to be a header chunk whose
            // tags check out. Everything else follows from that.
            Tags t;
            if (!read_tags(span, geo, at, t) || t.erased || !t.ecc_ok) continue;
            if (require_header && !t.is_header) continue;

            std::uint64_t score = 1;
            for (std::uint64_t i = 1; i < probe_chunks; ++i) {
                const std::uint64_t next = at + i * geo.chunk_size();
                Tags n;
                if (!read_tags(span, geo, next, n)) break;
                if (n.erased) continue;  // an unwritten chunk says nothing either way
                if (!n.ecc_ok) break;
                ++score;
            }
            if (score > best_score) {
                best_score = score;
                best = geo;
            }
        }
    }
    // One chunk proves nothing: sixteen bytes and a checksum can line up by
    // chance in data that is not a grid at all.
    if (best_score < 2) return false;
    out = best;
    return true;
}

}  // namespace omnitrace::yaffs
