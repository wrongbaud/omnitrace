// gpt.cpp — GUID Partition Table validator.
//
// Header at LBA 1 (little-endian): 0 "EFI PART", 8 revision, 12 header_size,
// 16 header_crc32 (over header_size bytes with this field zeroed), 24 my_lba,
// 32 alternate_lba, 40 first_usable, 48 last_usable, 56 disk_guid[16],
// 72 partition_entry_lba, 80 num_entries, 84 entry_size, 88 entry_array_crc32.
// Entry: 0 type_guid[16], 16 unique_guid[16], 32 first_lba, 40 last_lba,
// 48 attributes, 56 name[36] UTF-16LE. The sector size is the signature's
// magic_offset (512 or 4096). Reference: UEFI Specification §5.3.
#include <array>

#include "../crc32.h"
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

std::string utf16le_to_utf8(std::span<const std::uint8_t> raw) {
    std::string out;
    for (std::size_t i = 0; i + 1 < raw.size(); i += 2) {
        const std::uint32_t cu = static_cast<std::uint32_t>(raw[i] | (raw[i + 1] << 8));
        if (cu == 0) break;
        std::uint32_t cp = cu;
        if (cu >= 0xD800 && cu <= 0xDBFF && i + 3 < raw.size()) {
            const std::uint32_t lo = static_cast<std::uint32_t>(raw[i + 2] | (raw[i + 3] << 8));
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((cu - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            } else {
                cp = 0xFFFD;
            }
        } else if (cu >= 0xD800 && cu <= 0xDFFF) {
            cp = 0xFFFD;
        }
        if (cp < 0x80)
            out.push_back(static_cast<char>(cp));
        else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    return out;
}

std::optional<Finding> validate_gpt(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    const std::uint64_t sector = sig.magic_offset == 0 ? 512 : sig.magic_offset;
    const std::uint64_t hdr = start + sig.magic_offset;
    const Endian e = Endian::Little;
    Finding f = make_finding(sig, start, Confidence::Magic);

    const auto revision = span.at<std::uint32_t>(hdr + 8, e);
    const auto header_size = span.at<std::uint32_t>(hdr + 12, e);
    const auto header_crc = span.at<std::uint32_t>(hdr + 16, e);
    const auto my_lba = span.at<std::uint64_t>(hdr + 24, e);
    const auto alternate_lba = span.at<std::uint64_t>(hdr + 32, e);
    const auto first_usable = span.at<std::uint64_t>(hdr + 40, e);
    const auto last_usable = span.at<std::uint64_t>(hdr + 48, e);
    const auto disk_guid = span.bytes(hdr + 56, 16);
    const auto entry_lba = span.at<std::uint64_t>(hdr + 72, e);
    const auto num_entries = span.at<std::uint32_t>(hdr + 80, e);
    const auto entry_size = span.at<std::uint32_t>(hdr + 84, e);
    const auto array_crc = span.at<std::uint32_t>(hdr + 88, e);
    if (!array_crc) {
        diag(f, Severity::Warning, "gpt-truncated-header",
             "fewer than 92 bytes available for the GPT header");
        return f;
    }
    f.attrs["revision"] = hex_fixed(*revision, 8);
    f.attrs["sector_size"] = dec(sector);
    f.attrs["disk_guid"] = guid_mixed(*disk_guid);
    if (*header_size < 92 || *header_size > sector) {
        diag(f, Severity::Warning, "gpt-bad-header-size",
             "header_size " + dec(*header_size) + " is not in [92, " + dec(sector) + "]");
        return f;
    }
    if (*entry_size < 128 || (*entry_size % 8) != 0) {
        diag(f, Severity::Warning, "gpt-bad-entry-size",
             "entry_size " + dec(*entry_size) + " is not a multiple of 8 >= 128");
        return f;
    }
    f.confidence = Confidence::Structural;

    // Header CRC: header bytes with the crc field zeroed.
    bool header_ok = false;
    if (auto raw = span.bytes(hdr, *header_size)) {
        (*raw)[16] = (*raw)[17] = (*raw)[18] = (*raw)[19] = 0;
        header_ok =
            crc32_zlib(std::span<const std::uint8_t>(raw->data(), raw->size())) == *header_crc;
    }
    if (!header_ok)
        diag(f, Severity::Warning, "gpt-header-crc-mismatch", "header CRC32 does not match");

    if (*my_lba != 1) {
        // Backup header at the end of the disk: report it, sized to its sector.
        f.attrs["backup"] = "true";
        f.attrs["my_lba"] = dec(*my_lba);
        f.offset = hdr;
        f.size = sector <= remaining(span, hdr) ? sector : remaining(span, hdr);
        f.confidence = header_ok ? Confidence::Verified : Confidence::Structural;
        f.evidence = std::string("backup GPT header") + (header_ok ? ", CRC ok" : "");
        return f;
    }

    // Entries.
    const std::uint64_t avail = remaining(span, start);
    const std::uint64_t array_off =
        *entry_lba > UINT64_MAX / sector ? UINT64_MAX : *entry_lba * sector;
    const std::uint64_t array_len = static_cast<std::uint64_t>(*num_entries) * *entry_size;
    bool entries_inside = array_off < avail && array_len <= avail - array_off;
    f.attrs["entry_count"] = dec(*num_entries);
    f.attrs["entry_size"] = dec(*entry_size);
    std::string list;
    std::uint64_t used_entries = 0;
    std::uint64_t max_end = 2 * sector;
    if (!entries_inside) {
        diag(f, Severity::Warning, "gpt-entries-outside",
             "partition entry array is not inside the available data");
    } else {
        const std::optional<std::uint64_t> max_entries = extra_u64(sig, "max_entries");
        std::uint64_t n = *num_entries;
        if (max_entries && n > *max_entries) {
            diag(f, Severity::Warning, "gpt-entry-limit",
                 "only the first " + dec(*max_entries) + " of " + dec(n) +
                     " entries were read (max_entries)");
            n = *max_entries;
        }
        for (std::uint64_t i = 0; i < n; ++i) {
            const std::uint64_t eo = start + array_off + i * *entry_size;
            const auto type = span.bytes(eo, 16);
            const auto unique = span.bytes(eo + 16, 16);
            const auto first = span.at<std::uint64_t>(eo + 32, e);
            const auto last = span.at<std::uint64_t>(eo + 40, e);
            const auto attrs = span.at<std::uint64_t>(eo + 48, e);
            const auto name = span.bytes(eo + 56, 72);
            if (!name) break;
            if (all_bytes(std::span<const std::uint8_t>(type->data(), type->size()), 0)) continue;
            ++used_entries;
            const std::uint64_t pstart =
                *first > UINT64_MAX / sector ? UINT64_MAX : *first * sector;
            const std::uint64_t psize = *last < *first ? 0
                                                       : (*last - *first + 1 > UINT64_MAX / sector
                                                              ? UINT64_MAX
                                                              : (*last - *first + 1) * sector);
            if (!list.empty()) list += ";";
            list += "p" + dec(i + 1) + ":" + dec(pstart) + ":" + dec(psize) + ":" +
                    guid_mixed(*type) + ":" + guid_mixed(*unique) + ":" +
                    list_safe(
                        utf16le_to_utf8(std::span<const std::uint8_t>(name->data(), name->size())));
            if (*attrs != 0) list += ":attrs=" + hex(*attrs);
            const std::uint64_t pend = psize > UINT64_MAX - pstart ? UINT64_MAX : pstart + psize;
            max_end = std::max(max_end, pend);
        }
        f.attrs["partitions"] = list;
        f.attrs["partition_count"] = dec(used_entries);
        if (const auto computed =
                crc32_span(span, start + array_off, array_len, 0xFFFFFFFFu, 0xFFFFFFFFu)) {
            if (*computed == *array_crc)
                f.attrs["entry_array_crc"] = "ok";
            else {
                f.attrs["entry_array_crc"] = "mismatch";
                diag(f, Severity::Warning, "gpt-entry-array-crc-mismatch",
                     "partition entry array CRC32 does not match");
            }
        }
    }
    f.attrs["first_usable_lba"] = dec(*first_usable);
    f.attrs["last_usable_lba"] = dec(*last_usable);
    f.attrs["alternate_lba"] = dec(*alternate_lba);

    // Size: through the backup header (alternate_lba) when it is plausible,
    // otherwise through the last partition; clamped to the data.
    std::uint64_t claimed = max_end;
    if (*alternate_lba > 1 && *alternate_lba < UINT64_MAX / sector)
        claimed = std::max(claimed, (*alternate_lba + 1) * sector);
    bool truncated = false;
    f.size = clamp_size(span, start, claimed, truncated);
    if (truncated)
        diag(f, Severity::Warning, "gpt-truncated",
             "disk extent " + dec(claimed) + " exceeds the " + dec(avail) + " bytes available");

    if (header_ok && entries_inside) {
        f.confidence =
            f.attrs["entry_array_crc"] == "ok" ? Confidence::Verified : Confidence::Consistent;
    } else if (header_ok) {
        f.confidence = Confidence::Consistent;
    }
    f.evidence = dec(used_entries) + " partition(s)" + (header_ok ? ", header CRC ok" : "");
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("gpt", validate_gpt);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(gpt)
