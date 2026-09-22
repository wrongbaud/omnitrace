// super.cpp — Android logical-partition ("super") validator.
//
// The layout and the table parsing live in `omnitrace::lp` (core/Lp.h),
// because the container reader assembles the same partitions out of the same
// bytes. This file decides only what a hit is worth and how far it runs.
//
// The geometry magic is four bytes at a fixed offset, so a scan of an eMMC
// image finds it in unrelated data. What separates a super from that is the
// three SHA-256 checksums liblp stores over the geometry, the metadata header
// and the tables. The last is the partition map itself, and it is what lifts a
// finding to Verified: a matching SHA-256 over the map does not happen by
// accident, and a map that cannot be trusted must not become extents on disk
// -- the same argument as the GPT header CRC and the tar member checksum.
//
// Extent: the super's own size, which the block-device table states. Without
// it there is nothing to size the structure by (the logical partitions inside
// say nothing about where the container ends), so the finding carries
// `extent: unknown` and no reader is asked to open it.
#include "omnitrace/core/Lp.h"

#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

std::optional<Finding> validate_super(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);

    const auto geom = lp::read_geometry(span, start);
    if (!geom) {
        diag(f, Severity::Info, "super-bad-geometry",
             "the geometry magic is there but its fields are not a super's (slot count, metadata "
             "size or logical block size out of range)");
        f.attrs["extent"] = "unknown";
        return f;
    }
    f.attrs["metadata_max_size"] = dec(geom->metadata_max_size);
    f.attrs["metadata_slots"] = dec(geom->metadata_slot_count);
    f.attrs["logical_block_size"] = dec(geom->logical_block_size);
    f.confidence = Confidence::Structural;

    const auto meta = lp::read_metadata(span, start, *geom);
    if (!meta) {
        diag(f, Severity::Warning, "super-bad-metadata",
             "the geometry parses but metadata slot 0 does not: no header magic at " +
                 hex(span.absolute(start + lp::kMetadataOffset)) +
                 ", or a table runs outside the slot");
        f.attrs["extent"] = "unknown";
        return f;
    }
    f.attrs["version"] = dec(meta->major_version) + "." + dec(meta->minor_version);
    f.attrs["partition_count"] = dec(meta->partitions.size());
    f.attrs["extent_count"] = dec(meta->extents.size());
    f.attrs["group_count"] = dec(meta->group_count);
    f.confidence = Confidence::Consistent;

    // What the map says is inside, for an examiner reading the manifest
    // without opening the reader's output.
    std::string list;
    std::uint64_t logical_total = 0;
    for (const lp::Partition& p : meta->partitions) {
        const std::uint64_t bytes = meta->partition_size(p);
        logical_total = sat_add(logical_total, bytes);
        if (!list.empty()) list += ";";
        list += list_safe(p.name) + ":" + dec(bytes) + ":" + dec(p.num_extents);
    }
    f.attrs["partitions"] = list;
    f.attrs["logical_bytes"] = dec(logical_total);

    const lp::Checksums sums = lp::verify(span, start, *meta);
    f.attrs["geometry_checksum"] = sums.geometry ? "ok" : "mismatch";
    f.attrs["header_checksum"] = sums.header ? "ok" : "mismatch";
    f.attrs["tables_checksum"] = sums.tables ? "ok" : "mismatch";
    if (!sums.tables)
        diag(f, Severity::Warning, "super-tables-checksum-mismatch",
             "the partition map does not match the SHA-256 the header stores over it, so the "
             "extents it describes are not trustworthy and no partition was claimed");

    // Only a verified map may hand extents to a reader. Everything above is a
    // description; this is the line where it becomes bytes on disk.
    const std::uint64_t device = meta->device_size();
    if (sums.tables && device != 0) {
        f.confidence = Confidence::Verified;
        bool truncated = false;
        f.size = clamp_size(span, start, device, truncated);
        f.attrs["device_size"] = dec(device);
        if (truncated)
            diag(f, Severity::Warning, "super-truncated",
                 "the block-device table describes " + dec(device) + " bytes but only " +
                     dec(span.size() - start) + " are available");
    } else {
        // A map that did not verify, or one whose block-device table does not
        // state a size, leaves the structure unsized rather than guessing from
        // the logical partitions: they describe where their bytes are, not
        // where the container stops.
        f.attrs["extent"] = "unknown";
        if (sums.tables)
            diag(f, Severity::Info, "super-no-device-size",
                 "the block-device table does not state the super's size, so the structure has "
                 "no extent and claims no bytes");
    }

    f.evidence = "super v" + f.attrs["version"] + ", " + dec(meta->partitions.size()) +
                 " logical partition(s) over " + dec(meta->extents.size()) + " extent(s), " +
                 (sums.tables ? "map checksum ok" : "map checksum mismatch");
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("android_super", validate_super);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(super)
