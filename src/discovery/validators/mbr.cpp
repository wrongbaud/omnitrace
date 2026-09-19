// mbr.cpp — DOS/MBR partition table validator with EBR chain walking.
//
// Sector 0: 440 disk signature u32, 446 four 16-byte entries, 510 0x55AA.
// Entry: 0 status (0x00/0x80), 4 type, 8 lba_start u32 LE, 12 sectors u32 LE.
// Types 0x05/0x0F/0x85 are extended containers: each EBR holds one logical
// partition (relative to that EBR) and one link to the next EBR (relative to
// the extended partition start).
//
// The finding is the table itself: offset = the boot sector, size = 512.
// What the table describes goes into attrs (see docs/formats/partition-tables.md):
//   partitions  "pN:start_bytes:size_bytes:type[:boot][:logical];..."
//               primaries keep their slot number (p1..p4), logicals count
//               from p5 in chain order, as Linux numbers /dev/sdXN
//   disk_offset span-relative offset of LBA 0 (== the finding offset)
//   disk_size   bytes the table implies: the end of the farthest partition
//   table       "mbr-primary"
// 0x55AA is a 2-byte magic, so a candidate is rejected (not downgraded) when
// it is not sector aligned or no entry is sane; see docs/formats/signatures.md.
#include <array>
#include <set>

#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint64_t kSector = 512;

struct Part {
    std::uint64_t index = 0;  // pN
    std::uint64_t start = 0;  // bytes, relative to structure start
    std::uint64_t size = 0;   // bytes, as claimed (never clamped)
    std::uint8_t type = 0;
    bool bootable = false;
    bool logical = false;
};

struct Entry {
    std::uint8_t status = 0, type = 0;
    std::uint32_t lba = 0, sectors = 0;
};

std::optional<std::array<Entry, 4>> read_table(const Span& span, std::uint64_t sector) {
    std::array<std::uint8_t, 66> raw{};
    if (span.read(sector + 446, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size())
        return std::nullopt;
    if (raw[64] != 0x55 || raw[65] != 0xAA) return std::nullopt;
    std::array<Entry, 4> out{};
    for (std::size_t i = 0; i < 4; ++i) {
        const std::uint8_t* p = raw.data() + i * 16;
        out[i].status = p[0];
        out[i].type = p[4];
        out[i].lba = load_int<std::uint32_t>(p + 8, Endian::Little);
        out[i].sectors = load_int<std::uint32_t>(p + 12, Endian::Little);
    }
    return out;
}

bool is_extended(std::uint8_t t) {
    return t == 0x05 || t == 0x0F || t == 0x85;
}

// Entries that legitimately share bytes with others: extended containers hold
// their logicals, and a protective/hybrid 0xEE entry covers the GPT's disk.
bool may_overlap(const Part& p) {
    return !p.logical && (is_extended(p.type) || p.type == 0xEE);
}

std::optional<Finding> validate_mbr(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    if (start % kPartitionTableAlignment != 0) return std::nullopt;
    const auto table = read_table(span, start);
    if (!table) return std::nullopt;
    const std::uint64_t avail = remaining(span, start);
    Finding f = make_finding(sig, start, Confidence::Magic);

    std::vector<Part> parts;
    std::vector<std::uint64_t> extended_starts;
    bool any_bad = false, any_truncated = false;
    for (std::size_t i = 0; i < 4; ++i) {
        const Entry& en = (*table)[i];
        if (en.type == 0) continue;  // empty slot
        const std::uint64_t pstart = static_cast<std::uint64_t>(en.lba) * kSector;
        const std::uint64_t psize = static_cast<std::uint64_t>(en.sectors) * kSector;
        if ((en.status != 0x00 && en.status != 0x80) || en.sectors == 0 || pstart >= avail) {
            any_bad = true;
            diag(f, Severity::Info, "mbr-entry-invalid",
                 "entry " + dec(i + 1) + " (type " + hex_fixed(en.type, 2) +
                     ") has an invalid status, size or start");
            continue;
        }
        if (psize > avail - pstart) {
            any_truncated = true;
            diag(
                f, Severity::Warning, "mbr-partition-truncated",
                "entry " + dec(i + 1) + " ends past the available data (" + dec(avail) + " bytes)");
        }
        parts.push_back({i + 1, pstart, psize, en.type, en.status == 0x80, false});
        if (is_extended(en.type)) extended_starts.push_back(pstart);
    }
    // No sane entry that starts inside the data: a VBR, a boot sector, or
    // random bytes that happen to end in 0x55AA. Not a partition table.
    if (parts.empty()) return std::nullopt;

    // Walk each extended container's EBR chain. Logicals are numbered from 5.
    const std::optional<std::uint64_t> max_chain = extra_u64(sig, "ebr_max_chain");
    std::uint64_t next_logical = 5;
    std::string ebrs;  // span-relative "offset:512;..." of every EBR read
    for (const std::uint64_t ext_start : extended_starts) {
        std::set<std::uint64_t> seen;
        std::uint64_t ebr = ext_start;
        std::uint64_t hops = 0;
        while (ebr < avail && seen.insert(ebr).second) {
            if (max_chain && hops >= *max_chain) {
                diag(f, Severity::Warning, "mbr-ebr-chain-limit",
                     "EBR chain longer than ebr_max_chain (" + dec(*max_chain) + ")");
                break;
            }
            ++hops;
            const auto t = read_table(span, start + ebr);
            if (!t) {
                diag(f, Severity::Warning, "mbr-ebr-missing", "no EBR signature at " + hex(ebr));
                break;
            }
            if (!ebrs.empty()) ebrs += ";";
            ebrs += dec(start + ebr) + ":" + dec(kSector);
            const Entry& lg = (*t)[0];
            if (lg.type != 0 && lg.sectors != 0) {
                const std::uint64_t ls = ebr + static_cast<std::uint64_t>(lg.lba) * kSector;
                const std::uint64_t lz = static_cast<std::uint64_t>(lg.sectors) * kSector;
                if (ls < avail) {
                    if (lz > avail - ls) {
                        any_truncated = true;
                        diag(f, Severity::Warning, "mbr-partition-truncated",
                             "logical partition p" + dec(next_logical) +
                                 " ends past the available data (" + dec(avail) + " bytes)");
                    }
                    parts.push_back({next_logical, ls, lz, lg.type, lg.status == 0x80, true});
                }
            }
            ++next_logical;
            const Entry& nx = (*t)[1];
            if (nx.type == 0 || nx.sectors == 0) break;
            ebr = ext_start + static_cast<std::uint64_t>(nx.lba) * kSector;
        }
    }

    // Overlap check: primaries against primaries, logicals against logicals.
    bool overlap = false;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        for (std::size_t j = i + 1; j < parts.size(); ++j) {
            const Part& a = parts[i];
            const Part& b = parts[j];
            if (a.logical != b.logical) continue;
            if (may_overlap(a) || may_overlap(b)) continue;
            if (a.start < sat_add(b.start, b.size) && b.start < sat_add(a.start, a.size))
                overlap = true;
        }
    }
    if (overlap)
        diag(f, Severity::Warning, "mbr-partitions-overlap", "two partition entries overlap");

    std::string list;
    std::uint64_t disk_size = kSector;
    bool protective = false;
    for (const Part& p : parts) {
        if (!list.empty()) list += ";";
        list += "p" + dec(p.index) + ":" + dec(p.start) + ":" + dec(p.size) + ":" +
                hex_fixed(p.type, 2);
        if (p.bootable) list += ":boot";
        if (p.logical) list += ":logical";
        if (p.type == 0xEE) protective = true;
        disk_size = std::max(disk_size, sat_add(p.start, p.size));
    }
    f.attrs["table"] = "mbr-primary";
    f.attrs["partitions"] = list;
    f.attrs["partition_count"] = dec(parts.size());
    f.attrs["disk_offset"] = dec(start);
    f.attrs["disk_size"] = dec(disk_size);
    if (const auto sigw = span.at<std::uint32_t>(start + 440, Endian::Little))
        f.attrs["disk_signature"] = hex_fixed(*sigw, 8);
    if (protective) f.attrs["protective"] = "true";
    // The EBRs are part of this table: the scanner must not report each 0x55AA
    // link sector as a table of its own (see Scan.cpp, also_covers).
    if (!ebrs.empty()) f.attrs["also_covers"] = ebrs;
    // The finding is the table sector, never the disk it describes.
    f.size = kSector;
    f.confidence = Confidence::Structural;
    if (!any_bad && !any_truncated && !overlap) f.confidence = Confidence::Consistent;
    f.evidence = dec(parts.size()) + " partition(s)" + (protective ? ", protective (GPT)" : "") +
                 ", disk " + dec(disk_size) + " bytes";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("mbr", validate_mbr);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(mbr)
