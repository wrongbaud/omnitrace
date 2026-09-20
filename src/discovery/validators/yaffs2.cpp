// yaffs2.cpp — YAFFS2 validator.
//
// YAFFS2 has no superblock and no magic. An image is a flat grid of chunks,
// each one a NAND page followed by its spare (out-of-band) area:
//
//   [ page: 2048 bytes ][ spare: 64 bytes ]  [ page ][ spare ] ...
//
// The spare holds `struct yaffs_packed_tags2`: sixteen bytes of tags
// (seq_number, obj_id, chunk_id, n_bytes, all little-endian) followed by a
// twelve-byte `yaffs_ecc_other` over those sixteen. `chunk_id == 0` marks an
// object header, whose page is a `yaffs_obj_hdr`; anything else is data block
// `chunk_id - 1` of object `obj_id`.
//
// So what identifies a YAFFS2 image is the grid, not a constant. The
// signature anchors on the one byte pattern every non-trivial image has --
// the object header of a directory whose parent is the root (type 3, parent
// 1) -- and this validator does the real work: find the page and spare sizes
// and where in the spare the tags sit, by testing candidate geometries until
// one makes every chunk's tags verify against their own ECC. That ECC is what
// makes the test safe: sixteen bytes of tags plus a checksum over them, in
// every chunk, is not something other data reproduces by accident.
//
// Reference: yaffs2 `yaffs_guts.h` (struct yaffs_obj_hdr), `yaffs_packedtags2.c`
// and `yaffs_ecc.c`, read for understanding; nothing copied. Checked against
// mkyaffs2 output in both spare layouts (docs/formats/yaffs2.md).
#include "anchors.h"
#include "common.h"
#include "omnitrace/core/Yaffs.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;
using yaffs::Geometry;
using yaffs::Tags;

// Chunks the geometry probe looks at before it decides, and the cap on the
// walk that follows. A 16 GiB eMMC of 2 KiB pages is 8 million chunks, so the
// cap is what keeps a bogus hit from reading the whole device.
constexpr std::uint64_t kProbeChunks = 16;
constexpr std::uint64_t kMaxChunks = 1u << 22;
// Fewer chunks than this is not an image; it is a coincidence.
constexpr std::uint64_t kMinChunks = 4;

std::optional<Finding> validate_yaffs2(const Span& span, std::uint64_t start,
                                       const Signature& sig) {
    if (start >= span.size()) return std::nullopt;

    // The magic matched an object header page. Which chunk grid it sits in is
    // what has to be worked out, and a grid that makes the tag ECCs verify is
    // the answer -- a wrong page size, spare size or tag offset reads the
    // tags out of alignment and the checksum says so at once.
    Geometry geo;
    if (!detect_geometry(span, start, extra_u64(sig, "probe_chunks").value_or(kProbeChunks), geo))
        return std::nullopt;

    // Back up to the image's first chunk: the magic hits at the first
    // top-level directory, which is chunk 0 in a freshly made image but need
    // not be in a dump off a device.
    const std::uint64_t chunk = geo.chunk_size();
    std::uint64_t first = start;
    while (first >= chunk) {
        Tags t;
        if (!read_tags(span, geo, first - chunk, t) || t.erased || !t.ecc_ok) break;
        first -= chunk;
    }

    Finding f = make_finding(sig, first, Confidence::Structural);
    f.endian = Endian::Little;
    f.attrs["page_size"] = dec(geo.page);
    f.attrs["spare_size"] = dec(geo.spare);
    f.attrs["tags_offset"] = dec(geo.tags_offset);
    f.attrs["spare_layout"] = geo.tags_offset == 0 ? "yaffs" : "linux-mtd";

    // Walk the grid: every chunk either verifies or is erased. The first that
    // does neither ends the image.
    const std::uint64_t cap = extra_u64(sig, "max_chunks").value_or(kMaxChunks);
    std::uint64_t used = 0, erased = 0, trailing_erased = 0, headers = 0, bad_ecc = 0;
    std::uint64_t last_used_end = 0;
    std::uint64_t seq_min = UINT64_MAX, seq_max = 0;
    std::uint64_t at = first, n = 0;
    for (; n < cap && at + chunk <= span.size(); ++n, at += chunk) {
        Tags t;
        if (!read_tags(span, geo, at, t)) break;
        if (t.erased) {
            ++erased;
            ++trailing_erased;
            continue;
        }
        if (!t.ecc_ok) {
            // A chunk whose tags do not check out is either the end of the
            // image or a damaged block. One is tolerated inside a run that
            // otherwise verifies; two in a row end the walk.
            ++bad_ecc;
            if (bad_ecc > 1) break;
            continue;
        }
        bad_ecc = 0;
        ++used;
        trailing_erased = 0;
        last_used_end = at + chunk - first;
        if (t.is_header) ++headers;
        seq_min = std::min(seq_min, static_cast<std::uint64_t>(t.seq));
        seq_max = std::max(seq_max, static_cast<std::uint64_t>(t.seq));
    }
    if (used < kMinChunks) return std::nullopt;  // a handful of chunks is not an image

    f.size = last_used_end;
    f.attrs["chunks"] = dec(used + erased - trailing_erased);
    f.attrs["used_chunks"] = dec(used);
    f.attrs["object_headers"] = dec(headers);
    if (erased - trailing_erased != 0) f.attrs["erased_chunks"] = dec(erased - trailing_erased);
    if (trailing_erased != 0) f.attrs["trailing_erased_chunks"] = dec(trailing_erased);
    f.attrs["seq_min"] = dec(seq_min);
    f.attrs["seq_max"] = dec(seq_max);

    if (n >= cap)
        diag(f, Severity::Info, "yaffs2-limit-chunks",
             "the walk stopped after max_chunks (" + dec(cap) + "); the image may be longer");
    if (headers == 0) {
        diag(f, Severity::Warning, "yaffs2-no-headers",
             "no chunk carries an object header, so there is no tree to read");
        return f;
    }
    // Every chunk that was walked verified its own tag checksum, and there
    // are object headers among them. Nothing else is going to make this any
    // more certain: YAFFS2 has no superblock to cross-check against.
    f.confidence = Confidence::Verified;
    f.evidence = "chunk grid of " + dec(geo.page) + "+" + dec(geo.spare) + " bytes (tags at spare+" +
                 dec(geo.tags_offset) + "); " + dec(used) + " chunk(s) with verified tag ECC, " +
                 dec(headers) + " object header(s)";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("yaffs2", validate_yaffs2);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(yaffs2)
