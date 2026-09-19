// mbr.cpp — DOS/MBR partition table validator with EBR chain walking.
//
// Sector 0: 440 disk signature u32, 446 four 16-byte entries, 510 0x55AA.
// Entry: 0 status (0x00/0x80), 4 type, 8 lba_start u32 LE, 12 sectors u32 LE.
// Types 0x05/0x0F/0x85 are extended containers: each EBR holds one logical
// partition (relative to that EBR) and one link to the next EBR (relative to
// the extended partition start).
#include <array>
#include <set>

#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint64_t kSector = 512;

struct Part {
    std::uint64_t start = 0;  // bytes, relative to structure start
    std::uint64_t size = 0;   // bytes
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

std::optional<Finding> validate_mbr(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
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
        parts.push_back({pstart, psize, en.type, en.status == 0x80, false});
        if (is_extended(en.type)) extended_starts.push_back(pstart);
    }
    if (parts.empty()) return std::nullopt;  // a VBR or boot sector, not a partition table

    // Walk each extended container's EBR chain.
    const std::optional<std::uint64_t> max_chain = extra_u64(sig, "ebr_max_chain");
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
            const Entry& lg = (*t)[0];
            if (lg.type != 0 && lg.sectors != 0) {
                const std::uint64_t ls = ebr + static_cast<std::uint64_t>(lg.lba) * kSector;
                const std::uint64_t lz = static_cast<std::uint64_t>(lg.sectors) * kSector;
                if (ls < avail) {
                    if (lz > avail - ls) any_truncated = true;
                    parts.push_back({ls, lz, lg.type, lg.status == 0x80, true});
                }
            }
            const Entry& nx = (*t)[1];
            if (nx.type == 0 || nx.sectors == 0) break;
            ebr = ext_start + static_cast<std::uint64_t>(nx.lba) * kSector;
        }
    }

    // Overlap check among primaries (containers may legitimately hold logicals).
    bool overlap = false;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        for (std::size_t j = i + 1; j < parts.size(); ++j) {
            const Part& a = parts[i];
            const Part& b = parts[j];
            if (a.logical != b.logical) continue;
            if (!a.logical && (is_extended(a.type) || is_extended(b.type))) continue;
            const std::uint64_t a_end =
                a.size > UINT64_MAX - a.start ? UINT64_MAX : a.start + a.size;
            const std::uint64_t b_end =
                b.size > UINT64_MAX - b.start ? UINT64_MAX : b.start + b.size;
            if (a.start < b_end && b.start < a_end) overlap = true;
        }
    }
    if (overlap)
        diag(f, Severity::Warning, "mbr-partitions-overlap", "two partition entries overlap");

    std::string list;
    std::uint64_t extent = kSector;
    bool protective = false;
    bool any_inside = false;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        const Part& p = parts[i];
        if (!list.empty()) list += ";";
        list +=
            "p" + dec(i + 1) + ":" + dec(p.start) + ":" + dec(p.size) + ":" + hex_fixed(p.type, 2);
        if (p.bootable) list += ":boot";
        if (p.logical) list += ":logical";
        if (p.type == 0xEE) protective = true;
        const std::uint64_t pend = p.size > UINT64_MAX - p.start ? UINT64_MAX : p.start + p.size;
        if (pend <= avail) any_inside = true;
        extent = std::max(extent, pend > avail ? avail : pend);
    }
    f.attrs["partitions"] = list;
    f.attrs["partition_count"] = dec(parts.size());
    if (const auto sigw = span.at<std::uint32_t>(start + 440, Endian::Little))
        f.attrs["disk_signature"] = hex_fixed(*sigw, 8);
    if (protective) f.attrs["protective"] = "true";
    f.size = extent;
    f.confidence = Confidence::Structural;
    if (any_inside && !overlap) f.confidence = Confidence::Consistent;
    (void)any_bad;
    (void)any_truncated;
    f.evidence = dec(parts.size()) + " partition(s)" + (protective ? ", protective (GPT)" : "");
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("mbr", validate_mbr);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(mbr)
