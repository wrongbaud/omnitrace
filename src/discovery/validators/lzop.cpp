// lzop.cpp — lzop (`.lzo`) validator.
//
// The format is parsed by omnitrace::lzop (include/omnitrace/core/Lzop.h),
// which container::LzopReader shares. This decides what a region is and how
// long it is.
//
// Sizing is cheap here, unlike the other compressed formats: lzop writes each
// block's compressed length in the stream, so the extent is a walk of the
// block headers with the data skipped -- no decompression on a magic hit
// (docs/ARCHITECTURE.md on sizing validators). The nine-byte magic is strong
// enough that the header checksum then settles it.
#include "anchors.h"
#include "common.h"
#include "omnitrace/core/Lzop.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

// Blocks and members one hit may walk. A 4 GiB payload at lzop's 256 KiB
// default is 16384 blocks; the caps leave room and still terminate on data
// that only looks like a stream.
constexpr std::uint64_t kMaxBlocks = 1u << 20;
constexpr std::uint64_t kMaxMembers = 4096;

std::optional<Finding> validate_lzop(const Span& span, std::uint64_t start,
                                     const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    lzop::Header h;
    if (!lzop::read_header(span, start, h)) return std::nullopt;

    Finding f = make_finding(sig, start, Confidence::Magic);
    f.endian = Endian::Big;
    f.attrs["version"] = hex_fixed(h.version, 4);
    f.attrs["lib_version"] = hex_fixed(h.lib_version, 4);
    f.attrs["method"] = lzop::method_name(h.method);
    f.attrs["level"] = dec(h.level);
    f.attrs["flags"] = hex(h.flags);
    if (!h.name.empty()) f.attrs["original_name"] = list_safe(h.name);
    if (h.mode != 0) f.attrs["mode"] = hex(h.mode);
    if (h.mtime != 0) f.attrs["mtime"] = dec(h.mtime);
    f.attrs["header_checksum"] = h.checksum_ok ? "ok" : "mismatch";
    if (!h.checksum_ok) {
        // Nine bytes of magic plus a header that does not check out is more
        // likely a damaged stream than a coincidence, so it is still
        // reported -- but nothing here can be trusted to size it.
        diag(f, Severity::Warning, "lzop-header-checksum-mismatch",
             "the header does not match its own checksum; the fields are reported as stored");
        f.evidence = "lzop header, checksum mismatch";
        return f;
    }
    if (!h.decodable())
        diag(f, Severity::Warning, "lzop-unsupported-method",
             "compression method " + dec(h.method) + " (" + lzop::method_name(h.method) +
                 ") is not one this build decodes; the payload is not extracted");

    // Members laid end to end: each is a header and its blocks, and the file
    // ends when the next member's magic is not there.
    std::uint64_t at = h.first_block, members = 0, blocks = 0, uncompressed = 0, stored = 0;
    std::uint64_t end = 0;
    bool clean = true;
    lzop::Header member = h;
    while (members < kMaxMembers) {
        bool member_done = false;
        while (blocks < kMaxBlocks) {
            lzop::Block b;
            std::uint64_t next = 0;
            const lzop::BlockResult r = lzop::read_block(span, member, at, b, next);
            if (r == lzop::BlockResult::Bad) {
                clean = false;
                break;
            }
            at = next;
            if (r == lzop::BlockResult::End) {
                member_done = true;
                break;
            }
            ++blocks;
            uncompressed += b.uncompressed;
            if (b.stored()) ++stored;
        }
        if (!member_done) break;
        ++members;
        end = at;
        if (!lzop::read_header(span, at, member)) break;  // no further member
        at = member.first_block;
    }

    f.attrs["members"] = dec(members);
    f.attrs["blocks"] = dec(blocks);
    f.attrs["stored_blocks"] = dec(stored);
    f.attrs["payload_bytes"] = dec(uncompressed);
    if (members == 0 || !clean) {
        // The header is good but the blocks are not walkable, so the extent
        // is unknown and no reader may be handed this (docs/ARCHITECTURE.md).
        f.attrs["extent"] = "unknown";
        diag(f, Severity::Warning, "lzop-block-walk-failed",
             "the block headers could not be followed to the end of a member after " +
                 dec(blocks) + " block(s)");
        f.confidence = Confidence::Structural;
        f.evidence = "lzop header verified, block walk incomplete";
        return f;
    }
    if (blocks >= kMaxBlocks || members >= kMaxMembers)
        diag(f, Severity::Info, "lzop-limit-blocks",
             "the walk stopped at its block or member cap; the stream may be longer");

    f.size = end - start;
    f.confidence = Confidence::Consistent;
    f.evidence = "lzop " + std::string(lzop::method_name(h.method)) + ", header checksum ok, " +
                 dec(members) + " member(s), " + dec(blocks) + " block(s), " + dec(uncompressed) +
                 " byte(s) of payload" +
                 (h.name.empty() ? std::string{} : ", \"" + list_safe(h.name) + "\"");
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("lzop", validate_lzop);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(lzop)
