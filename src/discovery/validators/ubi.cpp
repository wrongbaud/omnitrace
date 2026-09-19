// ubi.cpp — UBI erase-counter (EC) header validator and PEB walker.
//
// EC header (64 bytes, big-endian) at the start of every physical erase block:
//   0 magic "UBI#"   4 version u8   5 pad[3]   8 ec u64   16 vid_hdr_offset u32
//  20 data_offset u32   24 image_seq u32   28 pad[32]   60 hdr_crc u32
// hdr_crc = crc32 with init 0xFFFFFFFF and no final xor over bytes 0..59.
// The PEB size is not recorded; it is derived from the distance to the next
// valid EC header. Reference: Linux drivers/mtd/ubi/ubi-media.h
#include <array>

#include "../crc32.h"
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::array<std::uint8_t, 4> kEcMagic{'U', 'B', 'I', '#'};
constexpr std::array<std::uint8_t, 4> kVidMagic{'U', 'B', 'I', '!'};

bool ec_header_valid(const Span& span, std::uint64_t off) {
    std::array<std::uint8_t, 64> raw{};
    if (span.read(off, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size()) return false;
    if (!std::equal(kEcMagic.begin(), kEcMagic.end(), raw.begin())) return false;
    const std::uint32_t stored = load_int<std::uint32_t>(raw.data() + 60, Endian::Big);
    return crc32_ubi(std::span<const std::uint8_t>(raw.data(), 60)) == stored;
}

bool erased_header(const Span& span, std::uint64_t off) {
    std::array<std::uint8_t, 64> raw{};
    if (span.read(off, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size()) return false;
    return all_bytes(std::span<const std::uint8_t>(raw.data(), raw.size()), 0xFF);
}

std::optional<Finding> validate_ubi(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    std::array<std::uint8_t, 64> raw{};
    Finding f = make_finding(sig, start, Confidence::Magic);
    f.endian = Endian::Big;
    if (span.read(start, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size()) {
        diag(f, Severity::Warning, "ubi-truncated-header",
             "fewer than 64 bytes available for the EC header");
        return f;
    }
    const std::uint8_t version = raw[4];
    const std::uint64_t ec = load_int<std::uint64_t>(raw.data() + 8, Endian::Big);
    const std::uint32_t vid_hdr_offset = load_int<std::uint32_t>(raw.data() + 16, Endian::Big);
    const std::uint32_t data_offset = load_int<std::uint32_t>(raw.data() + 20, Endian::Big);
    const std::uint32_t image_seq = load_int<std::uint32_t>(raw.data() + 24, Endian::Big);
    const std::uint32_t stored = load_int<std::uint32_t>(raw.data() + 60, Endian::Big);
    const bool crc_ok = crc32_ubi(std::span<const std::uint8_t>(raw.data(), 60)) == stored;

    // Sanity: version 1 is the only one that exists; the VID header follows the
    // EC header and data follows the VID header, all inside the block.
    const bool sane = version == 1 && vid_hdr_offset >= 64 && data_offset >= vid_hdr_offset + 64 &&
                      data_offset <= remaining(span, start);
    if (!crc_ok && !sane) return std::nullopt;  // 4-byte magic with garbage behind it

    f.attrs["version"] = dec(version);
    f.attrs["erase_counter"] = dec(ec);
    f.attrs["vid_hdr_offset"] = dec(vid_hdr_offset);
    f.attrs["data_offset"] = dec(data_offset);
    f.attrs["image_seq"] = hex_fixed(image_seq, 8);
    if (!crc_ok) {
        diag(f, Severity::Warning, "ubi-ec-crc-mismatch",
             "EC header CRC mismatch (stored " + hex_fixed(stored, 8) + ")");
        f.confidence = Confidence::Structural;
        return f;  // size unknown: a corrupt first block cannot anchor a walk
    }
    f.confidence = Confidence::Verified;
    if (!sane) {
        diag(f, Severity::Warning, "ubi-ec-fields-insane",
             "EC header CRC ok but version/offsets are out of range (version " + dec(version) +
                 ", vid_hdr_offset " + dec(vid_hdr_offset) + ", data_offset " + dec(data_offset) +
                 ")");
        return f;
    }
    // VID header magic is a cheap extra cross-check (an unmapped PEB has 0xFF there).
    std::array<std::uint8_t, 4> vid{};
    if (span.read(start + vid_hdr_offset, std::span<std::uint8_t>(vid.data(), vid.size())) ==
        vid.size()) {
        if (std::equal(kVidMagic.begin(), kVidMagic.end(), vid.begin()))
            f.attrs["first_peb_mapped"] = "true";
        else if (all_bytes(std::span<const std::uint8_t>(vid.data(), vid.size()), 0xFF))
            f.attrs["first_peb_mapped"] = "false";
    }

    // Derive the PEB size: the next valid EC header, probed at multiples of
    // vid_hdr_offset (the min I/O unit), which every PEB size is a multiple of.
    const std::uint64_t step = vid_hdr_offset;
    std::uint64_t peb_size = 0;
    for (std::uint64_t cand = start + data_offset; cand + 64 <= span.size(); cand += step) {
        if (!span.matches_at(cand, std::span<const std::uint8_t>(kEcMagic.data(), kEcMagic.size())))
            continue;
        if (ec_header_valid(span, cand)) {
            peb_size = cand - start;
            break;
        }
    }
    if (peb_size == 0) {
        diag(f, Severity::Info, "ubi-single-peb",
             "no second EC header found; PEB size and image size unknown");
        f.attrs["pebs"] = "1";
        f.evidence = "EC header CRC ok; single PEB";
        return f;
    }
    // Walk PEBs: valid headers count; erased blocks inside the run are kept,
    // trailing erased blocks are not.
    std::uint64_t pebs = 1, erased = 0, last_valid_end = start + peb_size;
    for (std::uint64_t off = start + peb_size; off + 64 <= span.size(); off += peb_size) {
        if (ec_header_valid(span, off)) {
            ++pebs;
            last_valid_end = off + peb_size > span.size() ? span.size() : off + peb_size;
        } else if (erased_header(span, off)) {
            ++erased;
        } else {
            break;
        }
    }
    // Recount erased blocks that lie before the last valid one.
    std::uint64_t interior_erased = 0;
    for (std::uint64_t off = start + peb_size; off + 64 <= last_valid_end; off += peb_size)
        if (!ec_header_valid(span, off)) ++interior_erased;
    f.size = last_valid_end - start;
    f.attrs["peb_size"] = dec(peb_size);
    f.attrs["pebs"] = dec(pebs + interior_erased);
    f.attrs["erased_pebs"] = dec(interior_erased);
    if (erased > interior_erased) f.attrs["trailing_erased_pebs"] = dec(erased - interior_erased);
    f.evidence = "EC header CRC ok; " + dec(pebs) + " PEBs of " + dec(peb_size) + " bytes";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("ubi", validate_ubi);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(ubi)
