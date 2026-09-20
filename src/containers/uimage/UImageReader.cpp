// UImageReader.cpp — U-Boot legacy image (uImage).
//
// 64-byte big-endian header, then ih_size bytes of payload. The header is
// parsed and CRC-checked by src/discovery/validators/uimage.cpp; this reader
// repeats the parse because a reader is handed a Span, never a Finding, and
// then emits the payload.
//
// Two payload shapes. Normally the payload is one blob, emitted as "payload".
// The multi-file (ih_type 4) and script (6) types instead begin with a
// NUL-terminated table of big-endian u32 sizes, then the images back to back,
// each padded to a 4-byte boundary; those become "image0", "image1", ...
//
// The payload is emitted as stored, compressed. ih_comp says how it is packed,
// but decompressing here would duplicate what the stream readers already do:
// the analysis pass re-scans every extracted file, so the payload is found and
// decoded by StreamReader one level down. That covers every ih_comp value
// except lzo, whose file format has no signature yet.
// Reference: U-Boot include/image.h, common/image.c (image_multi_*).
#include "UImageReader.h"

#include <algorithm>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "../common.h"
#include "omnitrace/core/Endian.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::container {

namespace {

constexpr std::uint64_t kHeaderSize = 64;
constexpr std::uint32_t kMagic = 0x27051956U;
constexpr std::uint8_t kTypeMulti = 4;
constexpr std::uint8_t kTypeScript = 6;

// Stable codes; literal so scripts/gen_docs.py can catalogue them.
constexpr const char* kCodeShortSection = "container-section-truncated";
constexpr const char* kCodeBadTable = "uimage-bad-multi-table";
constexpr const char* kCodeSinkError = "container-sink-error";

const char* comp_name(std::uint8_t v) {
    static const char* names[] = {"none", "gzip", "bzip2", "lzma", "lzo", "lz4", "zstd"};
    return v < sizeof(names) / sizeof(names[0]) ? names[v] : "unknown";
}

const char* type_name(std::uint8_t v) {
    switch (v) {
        case 2:
            return "kernel";
        case 3:
            return "ramdisk";
        case 4:
            return "multi";
        case 5:
            return "firmware";
        case 6:
            return "script";
        case 7:
            return "filesystem";
        case 8:
            return "flat_dt";
        default:
            return "other";
    }
}

std::uint64_t align4(std::uint64_t v) {
    return v > UINT64_MAX - 3 ? v : (v + 3) & ~std::uint64_t{3};
}

}  // namespace

Status UImageReader::open(const Span& span) {
    opened_ = false;
    const auto magic = span.at<std::uint32_t>(0, Endian::Big);
    if (!magic || *magic != kMagic) return Status::fail("container-bad-magic: no uImage magic");
    const auto size = span.at<std::uint32_t>(12, Endian::Big);
    const auto type = span.u8(30);
    const auto comp = span.u8(31);
    if (!size || !comp) return Status::fail("container-empty: fewer than 64 header bytes");
    data_size_ = *size;
    type_ = *type;
    comp_ = *comp;
    if (const auto n = span.cstring(32, 32)) name_ = sanitize_utf8(*n);
    span_ = span;
    opened_ = true;
    return Status::success();
}

ContainerInfo UImageReader::info() const {
    ContainerInfo i;
    i.format = "uimage";
    i.compression = comp_name(comp_);
    i.size = kHeaderSize + data_size_;
    i.attrs["type"] = type_name(type_);
    i.attrs["data_size"] = std::to_string(data_size_);
    if (!name_.empty()) i.attrs["image_name"] = name_;
    return i;
}

// The multi-file table: big-endian u32 sizes ending with a 0 entry.
std::vector<std::uint64_t> UImageReader::multi_sizes(WalkResult& out) const {
    std::vector<std::uint64_t> sizes;
    std::uint64_t pos = kHeaderSize;
    const std::uint64_t limit = kHeaderSize + data_size_;
    for (;;) {
        if (pos + 4 > limit) {
            out.diagnostics.push_back({Severity::Warning, kCodeBadTable,
                                       "the multi-file size table is not terminated inside the "
                                       "payload; nothing after it is emitted"});
            return {};
        }
        const auto v = span_.at<std::uint32_t>(pos, Endian::Big);
        if (!v) return {};
        pos += 4;
        if (*v == 0) break;
        sizes.push_back(*v);
        if (sizes.size() > kMaxMultiEntries) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeBadTable,
                 "the multi-file size table has more than " + std::to_string(kMaxMultiEntries) +
                     " entries; treated as corrupt"});
            return {};
        }
    }
    return sizes;
}

Status UImageReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    if (!opened_) return Status::fail("container-not-open: walk before a successful open");

    // The payload is bounded by the header's claim and by what the Span has.
    const std::uint64_t avail = span_.size() > kHeaderSize ? span_.size() - kHeaderSize : 0;
    const std::uint64_t payload = std::min<std::uint64_t>(data_size_, avail);
    if (payload < data_size_) {
        out.diagnostics.push_back(
            {Severity::Warning, kCodeShortSection,
             "ih_size claims " + std::to_string(data_size_) + " bytes but only " +
                 std::to_string(payload) + " are present; the payload ends there"});
        out.truncated = true;
    }

    auto emit = [&](const std::string& path, std::uint64_t off, std::uint64_t len) {
        FileMeta meta;
        meta.path = path;
        meta.kind = EntryKind::Regular;
        meta.mode = 0644;
        meta.size = len;
        EntryResult r;
        bool short_read = false;
        const Status st = emit_span_file(sink, opts, meta, span_, off, len, r, short_read);
        if (!st) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error});
            return;
        }
        if (short_read) {
            out.diagnostics.push_back({Severity::Warning, kCodeShortSection,
                                       "'" + path + "' ends before the header's length"});
            r.truncated = true;
            out.truncated = true;
        }
        count_entry(out, r);
        out.entries_out.push_back(std::move(r));
    };

    if (type_ != kTypeMulti && type_ != kTypeScript) {
        emit("payload", kHeaderSize, payload);
        return Status::success();
    }

    const std::vector<std::uint64_t> sizes = multi_sizes(out);
    if (sizes.empty()) {
        // No usable table: the payload is still evidence, so emit it whole
        // rather than losing it to a malformed header.
        emit("payload", kHeaderSize, payload);
        return Status::success();
    }
    std::uint64_t pos = kHeaderSize + (sizes.size() + 1) * 4;
    for (std::size_t i = 0; i < sizes.size(); ++i) {
        const std::uint64_t end = kHeaderSize + payload;
        if (pos >= end) {
            out.diagnostics.push_back({Severity::Warning, kCodeShortSection,
                                       "image " + std::to_string(i) +
                                           " starts past the end of the payload"});
            out.truncated = true;
            break;
        }
        emit("image" + std::to_string(i), pos, std::min(sizes[i], end - pos));
        pos = align4(pos + sizes[i]);
    }
    return Status::success();
}

OMNITRACE_REGISTER_CONTAINER("uimage", UImageReader);

namespace detail {
void omnitrace_container_anchor_uimage() {}
}  // namespace detail

}  // namespace omnitrace::container
