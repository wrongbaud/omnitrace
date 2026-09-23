// fat.cpp — FAT12/FAT16/FAT32 BIOS Parameter Block validator.
//
// FAT has no magic. What the signatures match is the **file-system type
// string** ("FAT32   " at 82, "FAT12   "/"FAT16   "/"FAT     " at 54), and
// Microsoft's own specification says that field "is not required to be
// correct" and must not be used to determine the type. So it is treated here
// as what it is — a cheap screen that says "a BPB might start 54 or 82 bytes
// back" — and everything this validator trusts comes out of the BPB itself.
//
// That matters because those strings turn up inside binaries: three corpus
// images carry "FAT32   ", "FAT12   " and "FAT16   " within twenty bytes of
// each other, which is a driver's or a formatter's string table, not three
// overlapping filesystems. The BPB behind them is nonsense, and this refuses
// them on that basis.
//
// Layout (offsets from the volume start; everything little-endian):
//    0  jmpBoot 3     13  SecPerClus 1   21  Media      1    32  TotSec32  4
//    3  OEMName 8     14  RsvdSecCnt 2   22  FATSz16    2
//   11  BytsPerSec 2  16  NumFATs    1   24  SecPerTrk  2
//                     17  RootEntCnt 2   26  NumHeads   2
//                     19  TotSec16   2   28  HiddSec    4
// FAT12/16 then:  36 DrvNum 1, 38 BootSig 1, 39 VolID 4, 43 VolLab 11, 54 Type 8
// FAT32 then:     36 FATSz32 4, 40 ExtFlags 2, 42 FSVer 2, 44 RootClus 4,
//                 48 FSInfo 2, 50 BkBootSec 2, 64 DrvNum 1, 66 BootSig 1,
//                 67 VolID 4, 71 VolLab 11, 82 Type 8
//   510 0x55 0xAA
//
// The type is decided the way the specification says it must be — by counting
// data clusters — and not by the string that led us here.
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

// The two thresholds are exact and are the *only* definition of the type.
// Microsoft is emphatic that being off by one here makes a volume unreadable.
constexpr std::uint32_t kMaxClustersFat12 = 4085;
constexpr std::uint32_t kMaxClustersFat16 = 65525;

bool is_pow2_u32(std::uint32_t v) {
    return v != 0 && (v & (v - 1)) == 0;
}

// The BPB fields every FAT shares, already range-checked.
struct Bpb {
    std::uint16_t bytes_per_sector = 0;
    std::uint8_t sectors_per_cluster = 0;
    std::uint16_t reserved_sectors = 0;
    std::uint8_t num_fats = 0;
    std::uint16_t root_entries = 0;
    std::uint8_t media = 0;
    std::uint64_t total_sectors = 0;
    std::uint64_t fat_size = 0;
    std::uint32_t root_cluster = 0;
};

// The cheap structural screens, in the order that rejects a string table
// fastest. Every one is a hard requirement of the format. Returns false and
// leaves the reason on `f` when the bytes cannot be a BPB.
bool screen_bpb(const Span& span, std::uint64_t start, Finding& f, Bpb& b) {
    constexpr Endian e = Endian::Little;
    const auto jmp0 = span.at<std::uint8_t>(start + 0, e);
    const auto bytes_per_sector = span.at<std::uint16_t>(start + 11, e);
    const auto sectors_per_cluster = span.at<std::uint8_t>(start + 13, e);
    const auto reserved_sectors = span.at<std::uint16_t>(start + 14, e);
    const auto num_fats = span.at<std::uint8_t>(start + 16, e);
    const auto root_entries = span.at<std::uint16_t>(start + 17, e);
    const auto total_sectors_16 = span.at<std::uint16_t>(start + 19, e);
    const auto media = span.at<std::uint8_t>(start + 21, e);
    const auto fat_size_16 = span.at<std::uint16_t>(start + 22, e);
    const auto total_sectors_32 = span.at<std::uint32_t>(start + 32, e);
    if (!jmp0 || !bytes_per_sector || !sectors_per_cluster || !reserved_sectors || !num_fats ||
        !root_entries || !total_sectors_16 || !media || !fat_size_16 || !total_sectors_32) {
        return false;
    }
    if (*jmp0 != 0xEB && *jmp0 != 0xE9) {
        diag(f, Severity::Warning, "fat-bad-jump",
             "the volume does not begin with a jump instruction (0x" + hex_fixed(*jmp0, 2) + ")");
        return false;
    }
    if (*bytes_per_sector < 512 || *bytes_per_sector > 4096 || !is_pow2_u32(*bytes_per_sector)) {
        diag(
            f, Severity::Warning, "fat-bad-sector-size",
            "bytes per sector " + dec(*bytes_per_sector) + " is not a power of two in [512, 4096]");
        return false;
    }
    if (!is_pow2_u32(*sectors_per_cluster) || *sectors_per_cluster > 128) {
        diag(f, Severity::Warning, "fat-bad-cluster-size",
             "sectors per cluster " + dec(*sectors_per_cluster) +
                 " is not a power of two in [1, 128]");
        return false;
    }
    if (*reserved_sectors == 0 || *num_fats == 0 || *num_fats > 4) {
        diag(f, Severity::Warning, "fat-bad-geometry",
             "reserved sectors " + dec(*reserved_sectors) + " / FAT count " + dec(*num_fats) +
                 " cannot describe a volume");
        return false;
    }
    // 0xF0 and 0xF8..0xFF are the media bytes the format allows; anything else
    // is a coincidence behind the type string.
    if (*media != 0xF0 && *media < 0xF8) {
        diag(f, Severity::Warning, "fat-bad-media",
             "media descriptor 0x" + hex_fixed(*media, 2) + " is not 0xF0 or 0xF8..0xFF");
        return false;
    }
    b.bytes_per_sector = *bytes_per_sector;
    b.sectors_per_cluster = *sectors_per_cluster;
    b.reserved_sectors = *reserved_sectors;
    b.num_fats = *num_fats;
    b.root_entries = *root_entries;
    b.media = *media;
    b.total_sectors = *total_sectors_16 != 0 ? *total_sectors_16 : *total_sectors_32;
    b.fat_size = *fat_size_16;
    if (*fat_size_16 == 0) {  // the FAT32 shape: the 32-bit twins carry it
        const auto fat_size_32 = span.at<std::uint32_t>(start + 36, e);
        const auto root_clus = span.at<std::uint32_t>(start + 44, e);
        if (!fat_size_32 || !root_clus) return false;
        b.fat_size = *fat_size_32;
        b.root_cluster = *root_clus;
    }
    if (b.total_sectors == 0 || b.fat_size == 0) {
        diag(f, Severity::Warning, "fat-bad-geometry",
             "total sectors " + dec(b.total_sectors) + " / FAT size " + dec(b.fat_size) +
                 " cannot describe a volume");
        return false;
    }
    return true;
}

// The boot sector's trailing 0x55AA and FAT[0] are the two confirmations
// available without reading the tree. FAT[0] holds the media byte in its low
// bits with the rest set: the format's own cross-check that the BPB and the
// table agree.
bool confirm_bpb(const Span& span, std::uint64_t start, const Bpb& b, std::uint64_t clusters,
                 bool is_fat32, Finding& f) {
    constexpr Endian e = Endian::Little;
    bool ok = true;
    const auto boot_sig = span.at<std::uint16_t>(start + 510, e);
    if (!boot_sig || *boot_sig != 0xAA55) {
        diag(f, Severity::Info, "fat-no-boot-signature",
             "the boot sector does not end with 0x55AA; the BPB is otherwise consistent");
        ok = false;
    }
    const std::uint64_t fat_off =
        start + static_cast<std::uint64_t>(b.reserved_sectors) * b.bytes_per_sector;
    const auto fat0 = span.at<std::uint32_t>(fat_off, e);
    if (!fat0) return false;
    std::uint32_t mask = 0x0000FFFFu;
    if (is_fat32)
        mask = 0x0FFFFFFFu;
    else if (clusters < kMaxClustersFat12)
        mask = 0x00000FFFu;
    const std::uint32_t entry = *fat0 & mask;
    const std::uint32_t want = (mask & ~0xFFu) | b.media;
    if (entry != want) {
        diag(f, Severity::Info, "fat-first-entry-mismatch",
             "FAT[0] is 0x" + hex_fixed(entry, 8) + ", not the 0x" + hex_fixed(want, 8) +
                 " the media byte implies");
        ok = false;
    }
    return ok;
}

std::optional<Finding> validate_fat(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;

    Finding f = make_finding(sig, start, Confidence::Magic);
    f.endian = Endian::Little;  // FAT is little-endian everywhere
    Bpb b;
    if (!screen_bpb(span, start, f, b)) {
        // No diagnostic means there were not enough bytes to judge: say
        // nothing rather than report a finding nobody can act on.
        return f.diagnostics.empty() ? std::nullopt : std::optional<Finding>(f);
    }

    // The root directory is a fixed area on FAT12/16 and a cluster chain on
    // FAT32, where RootEntCnt must be zero.
    const std::uint64_t root_dir_sectors =
        (static_cast<std::uint64_t>(b.root_entries) * 32 + b.bytes_per_sector - 1) /
        b.bytes_per_sector;
    const std::uint64_t meta_sectors = static_cast<std::uint64_t>(b.reserved_sectors) +
                                       static_cast<std::uint64_t>(b.num_fats) * b.fat_size +
                                       root_dir_sectors;
    if (meta_sectors >= b.total_sectors) {
        diag(f, Severity::Warning, "fat-bad-geometry",
             "reserved, FAT and root-directory sectors (" + dec(meta_sectors) +
                 ") leave no data area in " + dec(b.total_sectors) + " sectors");
        return f;
    }
    const std::uint64_t clusters = (b.total_sectors - meta_sectors) / b.sectors_per_cluster;
    if (clusters == 0) {
        diag(f, Severity::Warning, "fat-bad-geometry", "the volume has no data clusters");
        return f;
    }

    // The specification's definition, and the only one: count the clusters.
    const bool is_fat32 = clusters >= kMaxClustersFat16;
    const char* type = clusters < kMaxClustersFat12 ? "fat12" : (is_fat32 ? "fat32" : "fat16");
    const std::uint64_t cluster_bytes =
        static_cast<std::uint64_t>(b.bytes_per_sector) * b.sectors_per_cluster;

    f.attrs["fat_type"] = type;
    f.attrs["bytes_per_sector"] = dec(b.bytes_per_sector);
    f.attrs["sectors_per_cluster"] = dec(b.sectors_per_cluster);
    f.attrs["cluster_size"] = dec(cluster_bytes);
    f.attrs["reserved_sectors"] = dec(b.reserved_sectors);
    f.attrs["fat_count"] = dec(b.num_fats);
    f.attrs["fat_sectors"] = dec(b.fat_size);
    f.attrs["clusters"] = dec(clusters);
    f.attrs["total_sectors"] = dec(b.total_sectors);
    f.attrs["root_entries"] = dec(b.root_entries);

    // A volume whose counted type contradicts the string that found it is
    // still a volume -- that string is the field the specification says not to
    // trust -- but an examiner should be told, because it is also what a
    // resized or hand-edited image looks like.
    if (sig.name != "fat-generic" && sig.name != type) {
        diag(f, Severity::Info, "fat-type-string-disagrees",
             "the type string says " + sig.name + " but " + dec(clusters) +
                 " data clusters make this " + type + "; the count decides");
    }

    // FAT32-only fields, checked only when the cluster count says FAT32.
    if (is_fat32) {
        if (b.root_entries != 0) {
            diag(f, Severity::Warning, "fat-bad-geometry",
                 "a FAT32 volume must have a zero root-entry count, not " + dec(b.root_entries));
            return f;
        }
        if (b.root_cluster < 2 || b.root_cluster - 2 >= clusters) {
            diag(f, Severity::Warning, "fat-bad-root",
                 "root cluster " + dec(b.root_cluster) + " is outside the " + dec(clusters) +
                     " data clusters");
            return f;
        }
        f.attrs["root_cluster"] = dec(b.root_cluster);
    } else if (b.root_entries == 0) {
        diag(f, Severity::Warning, "fat-bad-root",
             "a FAT12/16 volume needs a fixed root directory, but the root-entry count is zero");
        return f;
    }

    // Everything the BPB says is self-consistent.
    f.confidence = Confidence::Structural;

    bool truncated = false;
    const std::uint64_t claimed = b.total_sectors * b.bytes_per_sector;
    f.size = clamp_size(span, start, claimed, truncated);
    if (truncated) {
        diag(f, Severity::Warning, "fat-truncated",
             "the BPB describes " + dec(claimed) + " bytes but only " +
                 dec(remaining(span, start)) + " are available");
    }

    // Both confirmations live inside the claimed extent, so a truncated volume
    // cannot reach them and stays at Structural.
    if (!truncated && confirm_bpb(span, start, b, clusters, is_fat32, f)) {
        f.confidence = Confidence::Consistent;
    }

    f.evidence = std::string(type) + " volume, " + dec(clusters) + " clusters of " +
                 dec(cluster_bytes) + " bytes, " + dec(b.total_sectors) + " sectors";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("fat", validate_fat);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(fat)
