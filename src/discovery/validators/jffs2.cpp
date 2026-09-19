// jffs2.cpp — JFFS2 node-header validator and size estimator.
//
// Every node starts with { u16 magic 0x1985, u16 nodetype, u32 totlen,
// u32 hdr_crc } in the filesystem's byte order; hdr_crc is crc32 (init 0,
// no xor-out) over the first 8 bytes. Nodes are 4-byte aligned. Erased space
// inside a partition is 0xFF. Reference: Linux fs/jffs2/, include/uapi/linux/jffs2.h
#include <array>

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

struct Header {
    std::uint16_t nodetype = 0;
    std::uint32_t totlen = 0;
};

// Parse and CRC-check the node header at `off`. nullopt if not a valid node.
std::optional<Header> node_at(const Span& span, std::uint64_t off, Endian e) {
    std::array<std::uint8_t, 12> raw{};
    if (span.read(off, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size())
        return std::nullopt;
    if (load_int<std::uint16_t>(raw.data(), e) != kMagic) return std::nullopt;
    const std::uint32_t stored = load_int<std::uint32_t>(raw.data() + 8, e);
    if (crc32_jffs2(std::span<const std::uint8_t>(raw.data(), 8)) != stored) return std::nullopt;
    Header h;
    h.nodetype = load_int<std::uint16_t>(raw.data() + 2, e);
    h.totlen = load_int<std::uint32_t>(raw.data() + 4, e);
    if (h.totlen < 12) return std::nullopt;
    return h;
}

// First offset >= off that is not 0xFF, or span.size().
std::uint64_t skip_erased(const Span& span, std::uint64_t off) {
    std::array<std::uint8_t, 4096> buf{};
    while (off < span.size()) {
        const std::size_t n = span.read(off, std::span<std::uint8_t>(buf.data(), buf.size()));
        if (n == 0) return span.size();
        for (std::size_t i = 0; i < n; ++i)
            if (buf[i] != 0xFF) return off + i;
        off += n;
    }
    return span.size();
}

std::optional<Finding> validate_jffs2(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    const Endian e = sig.endian.value_or(Endian::Little);
    const auto first = node_at(span, start, e);
    if (!first) return std::nullopt;  // 2-byte magic: without the CRC it is noise

    Finding f = make_finding(sig, start, Confidence::Verified);
    f.endian = e;
    std::uint64_t pos = start;
    std::uint64_t end = start;
    std::uint64_t nodes = 0, inodes = 0, dirents = 0, cleanmarkers = 0, padding = 0, summaries = 0,
                  xattrs = 0, unknown = 0, obsolete = 0;
    bool truncated = false;
    std::uint64_t erased_gap_bytes = 0;

    while (true) {
        const auto h = node_at(span, pos, e);
        if (!h) {
            // Erased space: skip it; the filesystem continues if a node follows.
            const std::uint64_t next = skip_erased(span, pos);
            if (next == pos) break;  // something else entirely
            const std::uint64_t aligned = (next + 3u) & ~static_cast<std::uint64_t>(3u);
            if (aligned < span.size() && node_at(span, aligned, e)) {
                erased_gap_bytes += aligned - pos;
                pos = aligned;
                continue;
            }
            break;  // trailing erased run (or unrelated data): not part of the size
        }
        ++nodes;
        if ((h->nodetype & kAccurate) == 0) ++obsolete;
        switch (static_cast<std::uint16_t>(h->nodetype & kTypeMask)) {
            case kInode:
                ++inodes;
                break;
            case kDirent:
                ++dirents;
                break;
            case kCleanmarker:
                ++cleanmarkers;
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
    if (truncated)
        diag(f, Severity::Warning, "jffs2-truncated", "last node extends past the end of the data");
    if (unknown != 0)
        diag(f, Severity::Info, "jffs2-unknown-nodetype",
             dec(unknown) + " node(s) with a nodetype this scanner does not know");
    f.evidence = "node header CRC ok; walked " + dec(nodes) + " nodes (" + dec(inodes) +
                 " inode, " + dec(dirents) + " dirent, " + dec(cleanmarkers) + " cleanmarker)";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("jffs2", validate_jffs2);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(jffs2)
