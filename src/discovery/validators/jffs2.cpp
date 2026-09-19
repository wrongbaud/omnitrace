// jffs2.cpp — JFFS2 node-header validator and size estimator.
//
// Every node starts with { u16 magic 0x1985, u16 nodetype, u32 totlen,
// u32 hdr_crc } in the filesystem's byte order; hdr_crc is crc32 (init 0,
// no xor-out) over the first 8 bytes. Nodes are 4-byte aligned. Erased space
// inside a partition is 0xFF.
//
// Obsolete nodes: on NOR flash JFFS2 obsoletes a node in place by clearing
// the JFFS2_NODE_ACCURATE bit (0x2000) of nodetype. The stored hdr_crc was
// computed with the bit set, so the kernel's scanner (fs/jffs2/scan.c) checks
// the CRC over the header with the bit re-set. Without that rule every
// obsolete node looks like a gap and one filesystem becomes many findings.
//
// Coalescing: after the last contiguous node the walk looks ahead across
// padding, erased space and dirty (garbage) blocks for the next CRC-valid
// header, up to `max_gap` bytes (Signature::extra, default 128 KiB); the
// finding covers the whole run of nodes. The erase-block size is inferred
// from the spacing of cleanmarker nodes, which sit at erase-block starts.
// Reference: Linux fs/jffs2/, include/uapi/linux/jffs2.h
#include <array>
#include <numeric>

#include "../crc32.h"
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint16_t kMagic = 0x1985;
// Node types carry feature bits (0xC000 incompat, 0x2000 "accurate"); JFFS2
// obsoletes a node in place by clearing the accurate bit, so classify on the
// type with that bit masked off and count the obsolete ones separately.
constexpr std::uint16_t kAccurate = 0x2000;
constexpr std::uint16_t kTypeMask = static_cast<std::uint16_t>(~kAccurate & 0xFFFF);
constexpr std::uint16_t kDirent = 0xC001;
constexpr std::uint16_t kInode = 0xC002;
constexpr std::uint16_t kCleanmarker = 0x0003;
constexpr std::uint16_t kPadding = 0x0004;
constexpr std::uint16_t kSummary = 0x0006;
constexpr std::uint16_t kXattr = 0xC008;
constexpr std::uint16_t kXref = 0xC009;

// Default look-ahead window when the signature does not set max_gap.
constexpr std::uint64_t kDefaultMaxGap = 128u * 1024u;

// Erase-block sizes for which erased-block counting is tracked during the
// walk (4 KiB .. 2 MiB, powers of two). The inferred size is looked up here.
constexpr unsigned kMinEraseShift = 12;
constexpr unsigned kMaxEraseShift = 21;
constexpr std::size_t kEraseCandidates = kMaxEraseShift - kMinEraseShift + 1;

struct Header {
    std::uint16_t nodetype = 0;
    std::uint32_t totlen = 0;
};

// Parse and CRC-check the node header held in `raw` (12 bytes).
std::optional<Header> parse_header(const std::array<std::uint8_t, 12>& raw, Endian e) {
    if (load_int<std::uint16_t>(raw.data(), e) != kMagic) return std::nullopt;
    const std::uint32_t stored = load_int<std::uint32_t>(raw.data() + 8, e);
    std::uint32_t computed = crc32_jffs2(std::span<const std::uint8_t>(raw.data(), 8));
    Header h;
    h.nodetype = load_int<std::uint16_t>(raw.data() + 2, e);
    if (computed != stored) {
        if ((h.nodetype & kAccurate) != 0) return std::nullopt;
        // Obsoleted in place: re-check with the accurate bit set.
        std::array<std::uint8_t, 8> fixed{};
        std::copy(raw.begin(), raw.begin() + 8, fixed.begin());
        const std::uint16_t t = static_cast<std::uint16_t>(h.nodetype | kAccurate);
        if (e == Endian::Little) {
            fixed[2] = static_cast<std::uint8_t>(t & 0xFF);
            fixed[3] = static_cast<std::uint8_t>(t >> 8);
        } else {
            fixed[2] = static_cast<std::uint8_t>(t >> 8);
            fixed[3] = static_cast<std::uint8_t>(t & 0xFF);
        }
        computed = crc32_jffs2(std::span<const std::uint8_t>(fixed.data(), fixed.size()));
        if (computed != stored) return std::nullopt;
    }
    h.totlen = load_int<std::uint32_t>(raw.data() + 4, e);
    if (h.totlen < 12) return std::nullopt;
    return h;
}

std::optional<Header> node_at(const Span& span, std::uint64_t off, Endian e) {
    std::array<std::uint8_t, 12> raw{};
    if (span.read(off, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size())
        return std::nullopt;
    return parse_header(raw, e);
}

struct Gap {
    std::uint64_t next = 0;  // offset of the next valid node header
    bool erased = true;      // every byte in [pos, next) was 0xFF
};

// Look for the next CRC-valid node header at a 4-aligned offset in
// [pos, pos + window). nullopt if none. Also reports whether the skipped
// bytes were all 0xFF (erased) or contained other data (dirty/padding).
std::optional<Gap> find_next_node(const Span& span, std::uint64_t pos, std::uint64_t window,
                                  Endian e) {
    const std::uint64_t limit = std::min(remaining(span, pos), window);
    const std::uint8_t m0 = e == Endian::Little ? 0x85 : 0x19;
    const std::uint8_t m1 = e == Endian::Little ? 0x19 : 0x85;
    std::array<std::uint8_t, 4096 + 12> buf{};
    bool erased = true;
    std::uint64_t done = 0;
    while (done < limit) {
        // Read a chunk plus 12 bytes of slack so a header at the chunk edge
        // is checked without a second read.
        const std::size_t want = static_cast<std::size_t>(
            std::min<std::uint64_t>(buf.size(), remaining(span, pos + done)));
        const std::size_t n = span.read(pos + done, std::span<std::uint8_t>(buf.data(), want));
        if (n == 0) break;
        const std::size_t usable = std::min<std::size_t>(n, 4096);
        for (std::size_t i = 0; i < usable && done + i < limit; i += 4) {
            if (buf[i] == m0 && i + 12 <= n && buf[i + 1] == m1) {
                std::array<std::uint8_t, 12> raw{};
                std::copy(buf.begin() + static_cast<std::ptrdiff_t>(i),
                          buf.begin() + static_cast<std::ptrdiff_t>(i + 12), raw.begin());
                if (parse_header(raw, e)) return Gap{pos + done + i, erased};
            }
            if (erased) {
                for (std::size_t k = i; k < i + 4 && k < n; ++k)
                    if (buf[k] != 0xFF) {
                        erased = false;
                        break;
                    }
            }
        }
        if (usable < 4096) break;
        done += usable;
    }
    return std::nullopt;
}

// Number of whole erase blocks of size `e` (aligned relative to `base`) inside
// [a, b).
std::uint64_t whole_blocks(std::uint64_t base, std::uint64_t a, std::uint64_t b, std::uint64_t e) {
    if (b <= a) return 0;
    const std::uint64_t first = (a - base + e - 1) / e;  // first block index fully >= a
    const std::uint64_t last = (b - base) / e;           // blocks fully < b
    return last > first ? last - first : 0;
}

std::optional<Finding> validate_jffs2(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    const Endian e = sig.endian.value_or(Endian::Little);
    const auto first = node_at(span, start, e);
    if (!first) return std::nullopt;  // 2-byte magic: without the CRC it is noise
    const std::uint64_t max_gap = extra_u64(sig, "max_gap").value_or(kDefaultMaxGap);

    Finding f = make_finding(sig, start, Confidence::Verified);
    f.endian = e;
    std::uint64_t pos = start;
    std::uint64_t end = start;
    std::uint64_t nodes = 0, inodes = 0, dirents = 0, cleanmarkers = 0, padding = 0, summaries = 0,
                  xattrs = 0, unknown = 0, obsolete = 0;
    bool truncated = false;
    std::uint64_t erased_gap_bytes = 0, dirty_gap_bytes = 0, gaps = 0;
    std::uint64_t cleanmarker_gcd = 0;  // gcd of cleanmarker offsets relative to start
    std::array<std::uint64_t, kEraseCandidates> erased_blocks{};
    // Offset of the cleanmarker that ends exactly at `pos`, if the last node
    // was one: a cleanmarker followed by erased space is an erased block.
    std::optional<std::uint64_t> cleanmarker_ending_here;

    while (true) {
        const auto h = node_at(span, pos, e);
        if (!h) {
            const auto gap = find_next_node(span, pos, max_gap, e);
            if (!gap) break;  // trailing erased run (or unrelated data): not part of the size
            ++gaps;
            if (gap->erased) {
                erased_gap_bytes += gap->next - pos;
                const std::uint64_t a = cleanmarker_ending_here.value_or(pos);
                for (std::size_t i = 0; i < kEraseCandidates; ++i)
                    erased_blocks[i] +=
                        whole_blocks(start, a, gap->next, std::uint64_t{1} << (kMinEraseShift + i));
            } else {
                dirty_gap_bytes += gap->next - pos;
            }
            pos = gap->next;
            cleanmarker_ending_here.reset();
            continue;
        }
        ++nodes;
        if ((h->nodetype & kAccurate) == 0) ++obsolete;
        const std::uint16_t type = static_cast<std::uint16_t>(h->nodetype & kTypeMask);
        switch (type) {
            case kInode:
                ++inodes;
                break;
            case kDirent:
                ++dirents;
                break;
            case kCleanmarker:
                ++cleanmarkers;
                cleanmarker_gcd = std::gcd(cleanmarker_gcd, pos - start);
                break;
            case kPadding:
                ++padding;
                break;
            case kSummary:
                ++summaries;
                break;
            case kXattr:
            case kXref:
                ++xattrs;
                break;
            default:
                ++unknown;
                break;
        }
        const std::uint64_t len =
            (static_cast<std::uint64_t>(h->totlen) + 3u) & ~static_cast<std::uint64_t>(3u);
        if (len > remaining(span, pos)) {
            truncated = true;
            end = span.size();
            break;
        }
        cleanmarker_ending_here =
            type == kCleanmarker ? std::optional<std::uint64_t>(pos) : std::nullopt;
        pos += len;
        end = pos;
    }

    f.size = end - start;
    f.attrs["nodes"] = dec(nodes);
    f.attrs["inode_nodes"] = dec(inodes);
    f.attrs["dirent_nodes"] = dec(dirents);
    f.attrs["cleanmarkers"] = dec(cleanmarkers);
    f.attrs["padding_nodes"] = dec(padding);
    f.attrs["summary_nodes"] = dec(summaries);
    f.attrs["xattr_nodes"] = dec(xattrs);
    f.attrs["unknown_nodes"] = dec(unknown);
    f.attrs["obsolete_nodes"] = dec(obsolete);
    f.attrs["first_nodetype"] = hex_fixed(first->nodetype, 4);
    f.attrs["erased_gap_bytes"] = dec(erased_gap_bytes);
    f.attrs["dirty_gap_bytes"] = dec(dirty_gap_bytes);
    f.attrs["gaps"] = dec(gaps);

    if (truncated)
        diag(f, Severity::Warning, "jffs2-truncated", "last node extends past the end of the data");
    // Erase size: the largest power of two dividing every cleanmarker offset.
    std::uint64_t erase_size = 0;
    if (cleanmarker_gcd != 0) erase_size = cleanmarker_gcd & (~cleanmarker_gcd + 1);
    if (erase_size != 0) {
        f.attrs["erase_size"] = dec(erase_size);
        f.attrs["erase_size_source"] = "cleanmarker spacing";
        f.attrs["aligned_size"] = dec((f.size + erase_size - 1) / erase_size * erase_size);
        unsigned shift = 0;
        while ((std::uint64_t{1} << shift) < erase_size) ++shift;
        if (shift >= kMinEraseShift && shift <= kMaxEraseShift)
            f.attrs["erased_blocks"] = dec(erased_blocks[shift - kMinEraseShift]);
        else
            f.attrs["erased_blocks"] = "unknown";
    } else {
        f.attrs["erase_size"] = "unknown";
        f.attrs["erased_blocks"] = "unknown";
        if (cleanmarkers < 2)
            diag(f, Severity::Info, "jffs2-no-erase-size",
                 "fewer than two cleanmarkers at distinct offsets: erase-block size not inferred");
    }
    if (unknown != 0)
        diag(f, Severity::Info, "jffs2-unknown-nodetype",
             dec(unknown) + " node(s) with a nodetype this scanner does not know");
    if (dirty_gap_bytes != 0)
        diag(f, Severity::Info, "jffs2-dirty-gaps",
             dec(dirty_gap_bytes) + " byte(s) of non-node, non-erased data between nodes");
    f.evidence = "node header CRC ok; walked " + dec(nodes) + " nodes (" + dec(inodes) +
                 " inode, " + dec(dirents) + " dirent, " + dec(cleanmarkers) + " cleanmarker, " +
                 dec(obsolete) + " obsolete)";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("jffs2", validate_jffs2);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(jffs2)
