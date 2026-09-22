// SuperReader.cpp — Android logical partitions (super). See SuperReader.h.
#include "SuperReader.h"

#include <algorithm>
#include <vector>

#include "omnitrace/core/Text.h"

namespace omnitrace::container {

namespace {

constexpr std::size_t kCopyChunk = 1U << 20;

constexpr const char* kCodeSinkError = "container-sink-error";
constexpr const char* kCodeBadExtent = "super-extent-outside";
constexpr const char* kCodeEmptyPartition = "super-partition-empty";
constexpr const char* kCodeUnnamed = "super-partition-unnamed";

// A logical partition with no extents is a real thing -- a slot reserved but
// not populated -- and writing a zero-byte file for it says more than dropping
// it would. It is named so an examiner sees the slot exists.
std::string entry_name(const lp::Partition& p, std::size_t index) {
    if (p.name.empty()) return "partition_" + std::to_string(index);
    return safe_filename_component(p.name);
}

}  // namespace

Status SuperReader::open(const Span& span) {
    opened_ = false;
    const auto meta = lp::read(span, 0);
    if (!meta) return Status::fail("container-bad-magic: no usable liblp geometry or metadata");

    // The same rule the validator applies. Without it a four-byte magic in
    // unrelated data would hand this reader a partition map read out of noise,
    // and every extent in it would become a file.
    const lp::Checksums sums = lp::verify(span, 0, *meta);
    if (!sums.tables)
        return Status::fail(
            "super-tables-checksum-mismatch: the partition map does not match the SHA-256 stored "
            "over it");

    span_ = span;
    meta_ = *meta;
    opened_ = true;
    return Status::success();
}

ContainerInfo SuperReader::info() const {
    ContainerInfo i;
    i.format = "android-super";
    i.size = meta_.device_size();
    i.attrs["version"] =
        std::to_string(meta_.major_version) + "." + std::to_string(meta_.minor_version);
    i.attrs["partitions"] = std::to_string(meta_.partitions.size());
    i.attrs["extents"] = std::to_string(meta_.extents.size());
    i.attrs["logical_block_size"] = std::to_string(meta_.geometry.logical_block_size);
    i.attrs["metadata_slots"] = std::to_string(meta_.geometry.metadata_slot_count);
    return i;
}

Status SuperReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    if (!opened_) return Status::fail("container-not-open: walk before a successful open");

    std::vector<std::uint8_t> buf(kCopyChunk);

    for (std::size_t pi = 0; pi < meta_.partitions.size(); ++pi) {
        const lp::Partition& p = meta_.partitions[pi];
        const auto extents = meta_.partition_extents(p);
        if (!extents) continue;  // read_metadata already rejected these

        const std::string name = entry_name(p, pi);
        if (p.name.empty())
            out.diagnostics.push_back({Severity::Warning, kCodeUnnamed,
                                       "logical partition " + std::to_string(pi) +
                                           " has no usable name; emitted as '" + name + "'"});

        FileMeta meta;
        meta.path = name;
        meta.kind = EntryKind::Regular;
        meta.mode = 0644;
        meta.size = meta_.partition_size(p);
        meta.extra["extents"] = std::to_string(extents->size());
        meta.extra["attributes"] = std::to_string(p.attributes);

        if (extents->empty())
            out.diagnostics.push_back({Severity::Info, kCodeEmptyPartition,
                                       "'" + name +
                                           "' has no extents: the slot exists but holds "
                                           "nothing"});

        EntryResult r;
        if (Status st = sink.begin_file(meta); !st) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeSinkError, "'" + name + "': " + st.error});
            continue;
        }

        bool stopped = false;
        for (const lp::Extent& e : *extents) {
            const std::uint64_t bytes = e.num_sectors * lp::kSectorSize;
            if (stopped) break;

            if (e.target == lp::Target::Zero) {
                // Stored nowhere: the device would read zeros here, so that is
                // what the extracted image gets.
                if (!opts.extract_data) continue;
                std::fill(buf.begin(), buf.end(), static_cast<std::uint8_t>(0));
                std::uint64_t done = 0;
                while (done < bytes) {
                    const std::size_t n =
                        static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), bytes - done));
                    if (Status st = sink.write(std::span<const std::uint8_t>(buf.data(), n)); !st) {
                        out.diagnostics.push_back(
                            {Severity::Warning, kCodeSinkError, "'" + name + "': " + st.error});
                        stopped = true;
                        break;
                    }
                    done += n;
                }
                continue;
            }

            // Linear: bytes at target_data sectors into the super. A map that
            // points past the end is a damaged map, not a short read -- say
            // which partition and stop it, rather than emitting silence.
            const std::uint64_t at = e.target_data * lp::kSectorSize;
            if (at > span_.size() || bytes > span_.size() - at) {
                out.diagnostics.push_back(
                    {Severity::Warning, kCodeBadExtent,
                     "'" + name + "': an extent at sector " + std::to_string(e.target_data) +
                         " for " + std::to_string(bytes) +
                         " bytes runs past the end of the super; the entry is short"});
                out.truncated = true;
                break;
            }
            if (!opts.extract_data) continue;
            std::uint64_t done = 0;
            while (done < bytes) {
                const std::size_t want =
                    static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), bytes - done));
                const std::size_t got =
                    span_.read(at + done, std::span<std::uint8_t>(buf.data(), want));
                if (got == 0) {
                    out.diagnostics.push_back({Severity::Warning, kCodeBadExtent,
                                               "'" + name + "': the super could not be read at " +
                                                   std::to_string(at + done)});
                    out.truncated = true;
                    stopped = true;
                    break;
                }
                if (Status st = sink.write(std::span<const std::uint8_t>(buf.data(), got)); !st) {
                    out.diagnostics.push_back(
                        {Severity::Warning, kCodeSinkError, "'" + name + "': " + st.error});
                    stopped = true;
                    break;
                }
                done += got;
            }
        }

        if (Status st = sink.end_file(r); !st) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeSinkError, "'" + name + "': " + st.error});
            continue;
        }
        ++out.entries;
        ++out.files;
        out.bytes += r.digests.bytes;
        out.entries_out.push_back(std::move(r));
    }
    return Status::success();
}

OMNITRACE_REGISTER_CONTAINER("android-super", SuperReader);

}  // namespace omnitrace::container

namespace omnitrace::container::detail {
void omnitrace_container_anchor_super() {}
}  // namespace omnitrace::container::detail
