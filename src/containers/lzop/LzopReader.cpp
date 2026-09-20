// LzopReader.cpp — lzop (`.lzo`) files.
//
// The header and block layout is parsed by omnitrace::lzop
// (include/omnitrace/core/Lzop.h), which src/discovery/validators/lzop.cpp
// shares; this decodes what it points at.
//
// Blocks are decoded one at a time and written straight through, so a
// gigabyte payload costs one block buffer -- lzop's default block is 256 KiB
// and its largest is 64 MiB. A block whose compressed length equals its
// uncompressed length was stored verbatim and is copied rather than decoded,
// which is what lzop does with data that does not compress.
//
// Every block carries a checksum of its uncompressed bytes. Unlike the
// wrapper formats, this reader therefore knows whether what it produced is
// what was compressed, and says so on the entry.
//
// Reference: lzop 1.04 (`src/lzop.c`), read for understanding; nothing
// copied. Output checked byte for byte against `lzop -d`.
#include "LzopReader.h"

#include <algorithm>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "../common.h"
#include "omnitrace/core/Compression.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::container {

namespace {

// Stable codes; literal so scripts/gen_docs.py can catalogue them.
constexpr const char* kCodeChecksum = "lzop-checksum-mismatch";
constexpr const char* kCodeUnsupported = "lzop-unsupported-method";
constexpr const char* kCodeBadBlock = "lzop-bad-block";
constexpr const char* kCodeLimitFileBytes = "container-limit-file-bytes";
constexpr const char* kCodeSinkError = "container-sink-error";

std::string dec(std::uint64_t v) {
    return std::to_string(v);
}

}  // namespace

bool LzopReader::survey() {
    members_.clear();
    blocks_ = payload_bytes_ = 0;
    std::uint64_t at = 0;
    lzop::Header h;
    while (members_.size() < kMaxMembers && lzop::read_header(span_, at, h)) {
        const std::uint64_t magic_at = at;
        at = h.first_block;
        bool done = false;
        while (blocks_ < kMaxBlocks) {
            lzop::Block b;
            std::uint64_t next = 0;
            const lzop::BlockResult r = lzop::read_block(span_, h, at, b, next);
            if (r == lzop::BlockResult::Bad) return !members_.empty();
            at = next;
            if (r == lzop::BlockResult::End) {
                done = true;
                break;
            }
            ++blocks_;
            payload_bytes_ += b.uncompressed;
        }
        if (!done) return !members_.empty();
        members_.push_back(magic_at);
        consumed_ = at;
    }
    return !members_.empty();
}

Status LzopReader::open(const Span& span) {
    span_ = span;
    opened_ = false;
    consumed_ = 0;
    bad_checksums_ = 0;
    if (span.empty()) return Status::fail("container-empty: no bytes at the container's start");
    if (!lzop::read_header(span, 0, first_))
        return Status::fail("container-bad-magic: no lzop magic and header at offset 0");
    if (!survey())
        return Status::fail("container-truncated: no lzop member's blocks reach a terminator");
    opened_ = true;
    return Status::success();
}

ContainerInfo LzopReader::info() const {
    ContainerInfo i;
    i.format = "lzop";
    i.size = consumed_;
    i.compression = lzop::method_name(first_.method);
    i.attrs["version"] = std::to_string(first_.version >> 8) + "." +
                         std::to_string(first_.version & 0xFF);
    i.attrs["method"] = lzop::method_name(first_.method);
    i.attrs["level"] = dec(first_.level);
    i.attrs["members"] = dec(members_.size());
    i.attrs["blocks"] = dec(blocks_);
    i.attrs["payload_bytes"] = dec(payload_bytes_);
    if (!first_.name.empty()) i.attrs["original_name"] = sanitize_utf8(first_.name);
    if (bad_checksums_ != 0) i.attrs["bad_checksums"] = dec(bad_checksums_);
    return i;
}

Status LzopReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    if (!opened_) return Status::fail("container-not-open: walk before a successful open");

    std::vector<std::uint8_t> in, decoded;
    for (std::size_t m = 0; m < members_.size(); ++m) {
        lzop::Header h;
        if (!lzop::read_header(span_, members_[m], h)) break;

        FileMeta meta;
        // One member is "payload", like the other single-payload wrappers;
        // several are numbered. The name in the header is evidence and must
        // not decide where the Sink writes, so it stays metadata.
        meta.path = members_.size() == 1 ? "payload" : "payload" + dec(m);
        meta.kind = EntryKind::Regular;
        meta.mode = (h.mode & 0777u) != 0 ? (h.mode & 07777u) : 0644u;
        if (h.mtime != 0) meta.mtime = static_cast<std::int64_t>(h.mtime);
        if (!h.name.empty()) meta.extra["original_name"] = sanitize_utf8(h.name);
        meta.extra["method"] = lzop::method_name(h.method);
        if (!h.checksum_ok) meta.extra["header_checksum"] = "mismatch";

        if (!h.decodable()) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeUnsupported,
                 "'" + meta.path + "': compression method " + dec(h.method) + " (" +
                     lzop::method_name(h.method) +
                     ") is not one this build decodes; no payload emitted"});
            continue;
        }

        // The size is only known once the blocks have been walked, and the
        // survey in open() already did that for the file as a whole; per
        // member it is cheap to repeat and keeps the two in step.
        std::uint64_t total = 0;
        {
            std::uint64_t at = h.first_block;
            for (;;) {
                lzop::Block b;
                std::uint64_t next = 0;
                const lzop::BlockResult r = lzop::read_block(span_, h, at, b, next);
                if (r != lzop::BlockResult::Ok) break;
                total += b.uncompressed;
                at = next;
            }
        }
        meta.size = total;

        if (const Status st = sink.begin_file(meta); !st) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + st.error});
            continue;
        }

        std::uint64_t written = 0, bad = 0, checked = 0;
        bool truncated = false, stopped = false;
        std::uint64_t at = h.first_block;
        while (!stopped) {
            lzop::Block b;
            std::uint64_t next = 0;
            const lzop::BlockResult r = lzop::read_block(span_, h, at, b, next);
            if (r == lzop::BlockResult::End) break;
            if (r == lzop::BlockResult::Bad) {
                out.diagnostics.push_back({Severity::Warning, kCodeBadBlock,
                                           "'" + meta.path + "': the block at offset " + dec(at) +
                                               " is malformed; the payload ends there"});
                truncated = true;
                break;
            }
            at = next;
            if (!opts.extract_data) {
                written += b.uncompressed;
                continue;
            }

            const auto raw = span_.bytes(b.at, b.compressed);
            if (!raw) {
                out.diagnostics.push_back({Severity::Warning, kCodeBadBlock,
                                           "'" + meta.path + "': a block's " + dec(b.compressed) +
                                               " bytes could not be read; the payload ends there"});
                truncated = true;
                break;
            }
            const std::uint8_t* bytes = nullptr;
            std::size_t len = 0;
            if (b.stored()) {
                bytes = raw->data();
                len = raw->size();
            } else {
                const Status st = compress::decompress_exact(
                    compress::Codec::Lzo1x, std::span<const std::uint8_t>(raw->data(), raw->size()),
                    decoded, b.uncompressed);
                if (!st) {
                    out.diagnostics.push_back(
                        {Severity::Warning, kCodeBadBlock,
                         "'" + meta.path + "': an LZO1X block did not decode (" + st.error +
                             "); the payload ends there"});
                    truncated = true;
                    break;
                }
                bytes = decoded.data();
                len = decoded.size();
            }

            // What lzop wrote down about these very bytes. This is the one
            // wrapper format that can be checked against itself.
            const std::span<const std::uint8_t> view(bytes, len);
            if (b.has_data_adler || b.has_data_crc) ++checked;
            if ((b.has_data_adler && lzop::adler32_of(view) != b.data_adler) ||
                (b.has_data_crc && lzop::crc32_of(view) != b.data_crc)) {
                ++bad;
                if (bad == 1) {
                    out.diagnostics.push_back(
                        {Severity::Warning, kCodeChecksum,
                         "'" + meta.path +
                             "': a block does not match the checksum lzop stored for it; the "
                             "bytes are emitted as decoded"});
                }
            }

            std::size_t take = len;
            if (written + take > opts.limits.max_file_bytes) {
                take = static_cast<std::size_t>(opts.limits.max_file_bytes - written);
                out.diagnostics.push_back(
                    {Severity::Warning, kCodeLimitFileBytes,
                     "'" + meta.path + "' exceeds max_file_bytes (" +
                         dec(opts.limits.max_file_bytes) + "); data cut there"});
                truncated = true;
                stopped = true;
            }
            if (Status st = sink.write(std::span<const std::uint8_t>(bytes, take)); !st) {
                out.diagnostics.push_back(
                    {Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + st.error});
                truncated = true;
                break;
            }
            written += take;
        }
        bad_checksums_ += bad;

        EntryResult r;
        if (const Status st = sink.end_file(r); !st) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + st.error});
            if (r.meta.path.empty()) continue;
        }
        // lzop -F writes no per-block checksum, so there is a third answer
        // besides ok and mismatch: nothing was there to check against.
        r.meta.extra["checksum"] = bad != 0     ? "mismatch"
                                  : checked != 0 ? "ok"
                                                 : "none";
        if (truncated) r.truncated = true;
        count_entry(out, r);
        out.entries_out.push_back(std::move(r));
    }
    return Status::success();
}

OMNITRACE_REGISTER_CONTAINER("lzop", LzopReader);

namespace detail {
void omnitrace_container_anchor_lzop() {}
}  // namespace detail

}  // namespace omnitrace::container
