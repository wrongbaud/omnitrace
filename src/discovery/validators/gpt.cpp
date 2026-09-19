// gpt.cpp — GUID Partition Table validator (primary and backup headers).
//
// Header (little-endian): 0 "EFI PART", 8 revision, 12 header_size,
// 16 header_crc32 (over header_size bytes with this field zeroed), 24 my_lba,
// 32 alternate_lba, 40 first_usable, 48 last_usable, 56 disk_guid[16],
// 72 partition_entry_lba, 80 num_entries, 84 entry_size, 88 entry_array_crc32.
// Entry: 0 type_guid[16], 16 unique_guid[16], 32 first_lba, 40 last_lba,
// 48 attributes, 56 name[36] UTF-16LE. The sector size is the signature's
// magic_offset (512 or 4096). Reference: UEFI Specification §5.3.
//
// Every LBA in a header is relative to LBA 0 of the disk the header describes.
// The validator locates that origin from my_lba (header offset - my_lba *
// sector) and reads the entry array and the alternate header relative to the
// header, so a backup header at the end of a disk, a primary at a vendor LBA
// (audio puts it at 12289) and a carved slice that no longer contains LBA 0
// all parse the same way. Partition offsets in attrs["partitions"] are
// disk-relative bytes; attrs["disk_offset"] says where LBA 0 is in the Span.
//
// The finding covers the table's own bytes only, never the disk:
//   primary  [LBA 0, end of the entry array)          typically 0x4400 bytes
//   backup   [entry array, end of the header sector)  typically 0x4200 bytes
// (the entry array is only included when it is adjacent to the header; a
// detached array leaves the finding at the header sectors). What the table
// implies about the disk goes into attrs["disk_size"]. See
// docs/formats/partition-tables.md for the full attrs and diagnostics contract.
#include <array>

#include "../crc32.h"
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint64_t kHeaderMin = 92;
constexpr std::uint64_t kEntryMin = 128;

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

struct Header {
    std::uint32_t revision = 0, header_size = 0, header_crc = 0;
    std::uint64_t my_lba = 0, alternate_lba = 0, first_usable = 0, last_usable = 0;
    std::vector<std::uint8_t> disk_guid;
    std::uint64_t entry_lba = 0;
    std::uint32_t num_entries = 0, entry_size = 0, array_crc = 0;
};

// The 92 fixed header bytes at `hdr`; nullopt when fewer are available.
std::optional<Header> read_header(const Span& span, std::uint64_t hdr) {
    const Endian e = Endian::Little;
    Header h;
    const auto array_crc = span.at<std::uint32_t>(hdr + 88, e);
    if (!array_crc) return std::nullopt;
    h.revision = *span.at<std::uint32_t>(hdr + 8, e);
    h.header_size = *span.at<std::uint32_t>(hdr + 12, e);
    h.header_crc = *span.at<std::uint32_t>(hdr + 16, e);
    h.my_lba = *span.at<std::uint64_t>(hdr + 24, e);
    h.alternate_lba = *span.at<std::uint64_t>(hdr + 32, e);
    h.first_usable = *span.at<std::uint64_t>(hdr + 40, e);
    h.last_usable = *span.at<std::uint64_t>(hdr + 48, e);
    h.disk_guid = *span.bytes(hdr + 56, 16);
    h.entry_lba = *span.at<std::uint64_t>(hdr + 72, e);
    h.num_entries = *span.at<std::uint32_t>(hdr + 80, e);
    h.entry_size = *span.at<std::uint32_t>(hdr + 84, e);
    h.array_crc = *array_crc;
    return h;
}

bool header_size_ok(const Header& h, std::uint64_t sector) {
    return h.header_size >= kHeaderMin && h.header_size <= sector;
}
bool entry_size_ok(const Header& h) {
    return h.entry_size >= kEntryMin && (h.entry_size % 8) == 0;
}

// Header CRC: header_size bytes with the crc field zeroed.
bool header_crc_ok(const Span& span, std::uint64_t hdr, const Header& h) {
    auto raw = span.bytes(hdr, h.header_size);
    if (!raw) return false;
    (*raw)[16] = (*raw)[17] = (*raw)[18] = (*raw)[19] = 0;
    return crc32_zlib(std::span<const std::uint8_t>(raw->data(), raw->size())) == h.header_crc;
}

// Span offset of `lba` given that the header at `hdr` sits at `my_lba`.
// nullopt when the sector lies before the Span or the arithmetic overflows.
std::optional<std::uint64_t> lba_offset(std::uint64_t hdr, std::uint64_t my_lba, std::uint64_t lba,
                                        std::uint64_t sector) {
    if (lba >= my_lba) {
        const std::uint64_t delta = sat_mul(lba - my_lba, sector);
        if (delta == UINT64_MAX || delta > UINT64_MAX - hdr) return std::nullopt;
        return hdr + delta;
    }
    const std::uint64_t delta = sat_mul(my_lba - lba, sector);
    if (delta > hdr) return std::nullopt;
    return hdr - delta;
}

// "valid" | "invalid" | "outside": the state of the header this one names as
// its alternate. `matches` reports whether a valid alternate describes the
// same disk (GUID and entry array CRC agree).
std::string alternate_state(const Span& span, std::uint64_t hdr, const Header& h,
                            std::uint64_t sector, bool& matches) {
    matches = false;
    const auto off = lba_offset(hdr, h.my_lba, h.alternate_lba, sector);
    if (!off || *off >= span.size()) return "outside";
    static constexpr std::uint8_t kMagic[8] = {'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T'};
    if (!span.matches_at(*off, std::span<const std::uint8_t>(kMagic, 8))) {
        return remaining(span, *off) < sector ? "outside" : "invalid";
    }
    const auto alt = read_header(span, *off);
    if (!alt || !header_size_ok(*alt, sector) || !entry_size_ok(*alt)) return "invalid";
    if (alt->my_lba != h.alternate_lba || alt->alternate_lba != h.my_lba) return "invalid";
    if (!header_crc_ok(span, *off, *alt)) return "invalid";
    matches = alt->disk_guid == h.disk_guid && alt->array_crc == h.array_crc;
    return "valid";
}

// True when the entry array read with `sector`-byte LBAs has the CRC the
// header records: the discriminator between the 512 and 4096 signatures.
bool array_verifies_at(const Span& span, std::uint64_t hdr, const Header& h, std::uint64_t sector) {
    if (hdr % sector != 0) return false;
    const auto off = lba_offset(hdr, h.my_lba, h.entry_lba, sector);
    const std::uint64_t len = sat_mul(h.num_entries, h.entry_size);
    if (!off || len == UINT64_MAX) return false;
    const auto crc = crc32_span(span, *off, len, 0xFFFFFFFFu, 0xFFFFFFFFu);
    return crc && *crc == h.array_crc;
}

struct EntryList {
    std::string list;
    std::uint64_t used = 0;     // entries with a non-zero type GUID and sane LBAs
    std::uint64_t skipped = 0;  // non-zero type but first_lba == 0 or last < first
    std::uint64_t max_end = 0;  // disk-relative end of the farthest partition
};

EntryList read_entries(const Span& span, std::uint64_t array_off, std::uint64_t n,
                       std::uint64_t entry_size, std::uint64_t sector) {
    const Endian e = Endian::Little;
    EntryList out;
    for (std::uint64_t i = 0; i < n; ++i) {
        const std::uint64_t eo = sat_add(array_off, sat_mul(i, entry_size));
        const auto type = span.bytes(eo, 16);
        const auto unique = span.bytes(eo + 16, 16);
        const auto first = span.at<std::uint64_t>(eo + 32, e);
        const auto last = span.at<std::uint64_t>(eo + 40, e);
        const auto attrs = span.at<std::uint64_t>(eo + 48, e);
        const auto name = span.bytes(eo + 56, 72);
        if (!name) break;
        if (all_bytes(std::span<const std::uint8_t>(type->data(), type->size()), 0)) continue;
        // LBA 0 is the protective MBR and can never start a partition; an
        // entry with a type GUID but no extent is a stale or zeroed slot.
        if (*first == 0 || *last < *first) {
            ++out.skipped;
            continue;
        }
        ++out.used;
        const std::uint64_t pstart = sat_mul(*first, sector);
        const std::uint64_t psize = sat_mul(*last - *first + 1, sector);
        if (!out.list.empty()) out.list += ";";
        out.list +=
            "p" + dec(i + 1) + ":" + dec(pstart) + ":" + dec(psize) + ":" + guid_mixed(*type) +
            ":" + guid_mixed(*unique) + ":" +
            list_safe(utf16le_to_utf8(std::span<const std::uint8_t>(name->data(), name->size())));
        if (*attrs != 0) out.list += ":attrs=" + hex(*attrs);
        out.max_end = std::max(out.max_end, sat_add(pstart, psize));
    }
    return out;
}

std::optional<Finding> validate_gpt(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    if (start % kPartitionTableAlignment != 0) return std::nullopt;
    const std::uint64_t sector = sig.magic_offset == 0 ? 512 : sig.magic_offset;
    const std::uint64_t hdr = start + sig.magic_offset;
    // The header sits on a sector boundary of its own sector size; a 512-byte
    // disk's backup header is never 4 KiB aligned and vice versa.
    if (hdr % sector != 0) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);

    const auto h = read_header(span, hdr);
    if (!h) {
        diag(f, Severity::Warning, "gpt-truncated-header",
             "fewer than 92 bytes available for the GPT header");
        return f;
    }
    f.attrs["revision"] = hex_fixed(h->revision, 8);
    f.attrs["sector_size"] = dec(sector);
    f.attrs["disk_guid"] = guid_mixed(h->disk_guid);
    f.attrs["header_lba"] = dec(h->my_lba);
    f.attrs["alternate_lba"] = dec(h->alternate_lba);
    if (!header_size_ok(*h, sector)) {
        diag(f, Severity::Warning, "gpt-bad-header-size",
             "header_size " + dec(h->header_size) + " is not in [92, " + dec(sector) + "]");
        return f;
    }
    if (!entry_size_ok(*h)) {
        diag(f, Severity::Warning, "gpt-bad-entry-size",
             "entry_size " + dec(h->entry_size) + " is not a multiple of 8 >= 128");
        return f;
    }
    if (h->my_lba == 0 || h->my_lba == h->alternate_lba) {
        diag(f, Severity::Warning, "gpt-bad-my-lba",
             "my_lba " + dec(h->my_lba) + " / alternate_lba " + dec(h->alternate_lba) +
                 " cannot describe a header");
        return f;
    }
    f.confidence = Confidence::Structural;

    const bool header_ok = header_crc_ok(span, hdr, *h);
    if (!header_ok)
        diag(f, Severity::Warning, "gpt-header-crc-mismatch", "header CRC32 does not match");

    // Role and disk origin. A backup header sits after its alternate.
    const bool backup = h->my_lba > h->alternate_lba;
    f.attrs["table"] = backup ? "gpt-backup" : "gpt-primary";
    if (backup) f.attrs["my_lba"] = dec(h->my_lba);  // alias of header_lba kept for consumers
    const std::optional<std::uint64_t> origin = lba_offset(hdr, h->my_lba, 0, sector);
    if (origin) {
        f.attrs["disk_offset"] = dec(*origin);
    } else {
        diag(f, Severity::Info, "gpt-origin-outside",
             "LBA 0 of the disk this header describes lies before the start of the data "
             "(carved slice); partition offsets are disk-relative");
    }

    // Entry array.
    const std::optional<std::uint64_t> array_off = lba_offset(hdr, h->my_lba, h->entry_lba, sector);
    const std::uint64_t array_len = sat_mul(h->num_entries, h->entry_size);
    const bool entries_inside = array_off && *array_off < span.size() && array_len != UINT64_MAX &&
                                array_len <= span.size() - *array_off;
    f.attrs["entry_count"] = dec(h->num_entries);
    f.attrs["entry_size"] = dec(h->entry_size);
    f.attrs["entries_lba"] = dec(h->entry_lba);
    f.attrs["first_usable_lba"] = dec(h->first_usable);
    f.attrs["last_usable_lba"] = dec(h->last_usable);
    EntryList entries;
    bool array_ok = false;
    std::string array_evidence;
    if (!entries_inside) {
        diag(f, Severity::Warning, "gpt-entries-outside",
             "partition entry array (LBA " + dec(h->entry_lba) + ", " + dec(array_len) +
                 " bytes) is not inside the available data");
    } else {
        const std::optional<std::uint64_t> max_entries = extra_u64(sig, "max_entries");
        std::uint64_t n = h->num_entries;
        if (max_entries && n > *max_entries) {
            diag(f, Severity::Warning, "gpt-entry-limit",
                 "only the first " + dec(*max_entries) + " of " + dec(n) +
                     " entries were read (max_entries)");
            n = *max_entries;
        }
        entries = read_entries(span, *array_off, n, h->entry_size, sector);
        f.attrs["partitions"] = entries.list;
        f.attrs["partition_count"] = dec(entries.used);
        if (entries.skipped != 0)
            diag(f, Severity::Info, "gpt-entry-invalid",
                 dec(entries.skipped) +
                     " entry(ies) with a type GUID but no valid LBA range "
                     "were skipped");
        if (const auto computed =
                crc32_span(span, *array_off, array_len, 0xFFFFFFFFu, 0xFFFFFFFFu)) {
            array_ok = *computed == h->array_crc;
            // An intact header whose array verifies at the other sector size
            // belongs to the other GPT signature: let that one report it.
            if (header_ok && !array_ok &&
                array_verifies_at(span, hdr, *h, sector == 512 ? 4096 : 512))
                return std::nullopt;
            f.attrs["entry_array_crc"] = array_ok ? "ok" : "mismatch";
            array_evidence = array_ok ? ", entry array CRC ok" : ", entry array CRC mismatch";
            if (!array_ok)
                diag(f, Severity::Warning, "gpt-entry-array-crc-mismatch",
                     "partition entry array CRC32 does not match");
        }
    }

    // Extent: the table's own bytes. The array is included only when it is
    // adjacent to the header (LBA 2 for a primary, immediately before a backup).
    const std::uint64_t array_end = entries_inside ? *array_off + array_len : 0;
    std::uint64_t lo = backup ? hdr : start;
    std::uint64_t hi = hdr + sector;
    if (entries_inside && !backup && *array_off == hdr + sector) hi = std::max(hi, array_end);
    if (entries_inside && backup && array_end == hdr) lo = *array_off;
    if (entries_inside &&
        !((!backup && *array_off == hdr + sector) || (backup && array_end == hdr)))
        diag(f, Severity::Info, "gpt-entries-detached",
             "partition entry array at LBA " + dec(h->entry_lba) +
                 " is not adjacent to the header; the finding covers the header only");
    f.offset = lo;
    f.size = std::min(hi, span.size()) - lo;

    // What the table implies about the disk: the last LBA is my_lba for a
    // backup and alternate_lba for a primary; never smaller than the farthest
    // partition.
    const std::uint64_t last_lba = backup ? h->my_lba : h->alternate_lba;
    std::uint64_t disk_size = sat_mul(sat_add(last_lba, 1), sector);
    if (disk_size == UINT64_MAX) disk_size = 0;
    disk_size = std::max(disk_size, entries.max_end);
    f.attrs["disk_size"] = dec(disk_size);
    if (origin && disk_size > span.size() - *origin)
        diag(f, Severity::Warning, "gpt-disk-truncated",
             "table describes a disk of " + dec(disk_size) + " bytes; only " +
                 dec(span.size() - *origin) + " bytes are available from LBA 0");

    // The other header.
    bool alt_matches = false;
    const std::string alt = alternate_state(span, hdr, *h, sector, alt_matches);
    f.attrs["alternate"] = alt;
    if (backup) {
        if (alt == "valid") {
            f.attrs["primary"] = alt_matches ? "valid" : "mismatch";
            if (alt_matches)
                diag(f, Severity::Info, "gpt-backup", "backup header, matches primary");
            else
                diag(f, Severity::Warning, "gpt-backup-mismatch",
                     "backup header disagrees with the primary at LBA " + dec(h->alternate_lba) +
                         " (disk GUID or entry array CRC differ)");
        } else {
            f.attrs["primary"] = alt;
            diag(f, Severity::Warning, "gpt-primary-missing",
                 "primary GPT header at LBA " + dec(h->alternate_lba) + " is " +
                     (alt == "outside" ? "outside the data" : "invalid") +
                     "; partition list recovered from the backup header at LBA " + dec(h->my_lba));
        }
    } else {
        f.attrs["backup"] = alt == "valid" ? (alt_matches ? "valid" : "mismatch") : alt;
        if (alt == "valid" && !alt_matches)
            diag(f, Severity::Warning, "gpt-backup-mismatch",
                 "backup header at LBA " + dec(h->alternate_lba) +
                     " disagrees with this primary (disk GUID or entry array CRC differ)");
    }

    if (header_ok && entries_inside)
        f.confidence = array_ok ? Confidence::Verified : Confidence::Consistent;
    else if (header_ok)
        f.confidence = Confidence::Consistent;
    f.evidence = std::string(backup ? "backup header at LBA " : "primary header at LBA ") +
                 dec(h->my_lba) + ", " + dec(entries.used) + " partition(s)" +
                 (header_ok ? ", header CRC ok" : ", header CRC mismatch") + array_evidence;
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("gpt", validate_gpt);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(gpt)
