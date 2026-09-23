// FatReader.cpp — FAT12/FAT16/FAT32.
//
// The format has no inode table and no superblock beyond the BPB. Three areas
// follow each other: the reserved sectors (boot sector first), then `NumFATs`
// copies of the allocation table, then the data area. On FAT12/16 a fixed
// root directory sits between the tables and the data; on FAT32 the root is an
// ordinary cluster chain like any other directory.
//
// Cluster numbering starts at 2, so cluster N begins at
// `data_start + (N - 2) * cluster_bytes`. Values 0 and 1 are reserved and are
// the usual shape of a corrupt or hostile entry.
//
// **Long names come before the entry they name, in reverse order.** A file
// called `ünïcödé ファイル.txt` is three 32-byte "long name" entries holding
// UTF-16 fragments, ordinals 3, 2, 1 with 0x40 set on the first one read, then
// the real 8.3 entry. A reader that assembles them in the order it meets them
// gets the name backwards.
//
// Timestamps are local time with no zone recorded — the format simply has no
// way to say which one. They are converted as if UTC, which is what every
// other tool does, and `docs/formats/fat.md` says so.
//
// Reference: Microsoft "FAT32 File System Specification" (fatgen103), which
// also specifies FAT12 and FAT16.
#include "FatReader.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include "omnitrace/core/Endian.h"
#include "omnitrace/core/Node.h"

namespace omnitrace::fs {

namespace detail {
void omnitrace_fs_anchor_fat() {}
}  // namespace detail

namespace {

// ------------------------------------------------------------------ constants

constexpr std::size_t kDirEntrySize = 32;
constexpr std::uint8_t kAttrReadOnly = 0x01;
constexpr std::uint8_t kAttrHidden = 0x02;
constexpr std::uint8_t kAttrSystem = 0x04;
constexpr std::uint8_t kAttrVolumeId = 0x08;
constexpr std::uint8_t kAttrDirectory = 0x10;
constexpr std::uint8_t kAttrLongName = 0x0F;  // RO|HIDDEN|SYSTEM|VOLUME_ID
constexpr std::uint8_t kEntryFree = 0xE5;     // deleted; the name's first byte
constexpr std::uint8_t kEntryEnd = 0x00;      // this and every later entry unused
constexpr std::uint8_t kEntryKanji = 0x05;    // a real 0xE5 as the first name byte
constexpr std::uint8_t kLastLongEntry = 0x40;

// A directory is bounded by its chain, but a hostile chain can be long; these
// keep a walk finite independently of Limits.
constexpr std::uint64_t kMaxChainClusters = 1u << 22;
constexpr std::size_t kMaxDirDepth = 64;
constexpr std::size_t kMaxLongNameChars = 260;

constexpr const char* kCodeBadChain = "fat-bad-chain";
constexpr const char* kCodeBadEntry = "fat-bad-entry";
constexpr const char* kCodeDirLoop = "fat-dir-loop";
constexpr const char* kCodeShortRead = "fat-short-read";
constexpr const char* kCodeSinkError = "fat-sink-error";
constexpr const char* kCodeLimitNodes = "fat-limit-nodes";
constexpr const char* kCodeOrphanLongName = "fat-orphan-long-name";
constexpr const char* kCodeDeletedFragmented = "fat-deleted-unchained";

std::string dec(std::uint64_t v) {
    return std::to_string(v);
}

// FAT stores local time with no zone. Converting as UTC is what every other
// tool does; docs/formats/fat.md records the choice.
std::int64_t fat_time(std::uint16_t date, std::uint16_t time) {
    if (date == 0) return 0;
    const int year = 1980 + ((date >> 9) & 0x7F);
    const int month = (date >> 5) & 0x0F;
    const int day = date & 0x1F;
    const int hour = (time >> 11) & 0x1F;
    const int minute = (time >> 5) & 0x3F;
    const int second = (time & 0x1F) * 2;
    if (month < 1 || month > 12 || day < 1 || day > 31) return 0;
    // days_from_civil (Howard Hinnant): no <ctime>, no zone, no clock.
    int y = year;
    y -= month <= 2;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy =
        static_cast<unsigned>((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1);
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const std::int64_t days =
        static_cast<std::int64_t>(era) * 146097 + static_cast<std::int64_t>(doe) - 719468;
    return days * 86400 + hour * 3600 + minute * 60 + second;
}

// UTF-16 code units to UTF-8, surrogate pairs included. Anything unpaired
// becomes U+FFFD rather than being dropped: the name is evidence.
void utf16_to_utf8(const std::vector<std::uint16_t>& in, std::string& out) {
    for (std::size_t i = 0; i < in.size(); ++i) {
        std::uint32_t cp = in[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < in.size() && in[i + 1] >= 0xDC00 &&
            in[i + 1] <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (in[++i] - 0xDC00);
        } else if (cp >= 0xD800 && cp <= 0xDFFF) {
            cp = 0xFFFD;
        }
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
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
}

// The 8.3 name, space-padded and in an OEM code page this reader does not try
// to guess. Bytes above 0x7F are passed through as Latin-1, which round-trips
// and keeps the entry printable; the long name is the authoritative one
// whenever there is one.
// Deleting a file overwrites the first byte of its name with 0xE5, and
// nothing else in the format keeps a copy. Rendering that byte as a character
// invents one -- `DELETED.TXT` came out as `åeleted.txt`, which reads like a
// real name. It is written as this placeholder instead, and the entry says so.
constexpr char kLostNameChar = '_';

std::string short_name(const std::uint8_t* e, bool& is_dot) {
    std::string base, ext;
    const bool lower_base = (e[12] & 0x08) != 0;
    const bool lower_ext = (e[12] & 0x10) != 0;
    for (int i = 0; i < 8; ++i) {
        if (e[i] == ' ') break;
        std::uint8_t c = e[i];
        if (i == 0 && c == kEntryKanji) c = 0xE5;  // a name that really starts 0xE5
        if (i == 0 && c == kEntryFree) {
            base.push_back(kLostNameChar);
            continue;
        }
        base.push_back(static_cast<char>(lower_base && c >= 'A' && c <= 'Z' ? c + 32 : c));
    }
    for (int i = 8; i < 11; ++i) {
        if (e[i] == ' ') break;
        const std::uint8_t c = e[i];
        ext.push_back(static_cast<char>(lower_ext && c >= 'A' && c <= 'Z' ? c + 32 : c));
    }
    is_dot = base == "." || base == "..";
    std::string out;
    for (const char c : base) {
        const auto u = static_cast<std::uint8_t>(c);
        if (u < 0x80) {
            out.push_back(c);
        } else {
            out.push_back(static_cast<char>(0xC0 | (u >> 6)));
            out.push_back(static_cast<char>(0x80 | (u & 0x3F)));
        }
    }
    if (!ext.empty()) {
        out.push_back('.');
        for (const char c : ext) {
            const auto u = static_cast<std::uint8_t>(c);
            if (u < 0x80) {
                out.push_back(c);
            } else {
                out.push_back(static_cast<char>(0xC0 | (u >> 6)));
                out.push_back(static_cast<char>(0x80 | (u & 0x3F)));
            }
        }
    }
    return out;
}

// The checksum a long-name entry carries, over the 8.3 name it belongs to.
// It is what tells an assembled long name from a stale one left behind by a
// rename.
std::uint8_t short_name_checksum(const std::uint8_t* e) {
    std::uint8_t sum = 0;
    for (int i = 0; i < 11; ++i)
        sum = static_cast<std::uint8_t>(((sum & 1) != 0 ? 0x80 : 0) + (sum >> 1) + e[i]);
    return sum;
}

// One 32-byte directory entry, already decoded.
struct Entry {
    std::string name;
    bool directory = false;
    bool deleted = false;
    /// The name came from the 8.3 field of a deleted entry, so its first
    /// character is the 0xE5 stamp rather than anything the file was called.
    bool name_stamped = false;
    std::uint32_t first_cluster = 0;
    std::uint64_t size = 0;
    std::uint8_t attr = 0;
    std::int64_t mtime = 0, crtime = 0, atime = 0;
};

}  // namespace

// ------------------------------------------------------------------ Impl

struct FatReader::Impl {
    Span span;
    bool opened = false;

    int bits = 0;  // 12, 16 or 32
    std::uint16_t bytes_per_sector = 0;
    std::uint8_t sectors_per_cluster = 0;
    std::uint32_t cluster_bytes = 0;
    std::uint16_t reserved_sectors = 0;
    std::uint8_t num_fats = 0;
    std::uint16_t root_entries = 0;
    std::uint64_t fat_sectors = 0, total_sectors = 0, clusters = 0;
    std::uint64_t fat_start = 0, root_dir_start = 0, root_dir_bytes = 0, data_start = 0;
    std::uint32_t root_cluster = 0, volume_id = 0;
    std::string label, oem;
    std::vector<Diagnostic> open_diags;

    // per-walk
    struct Walk {
        Sink* sink = nullptr;
        const WalkOptions* opts = nullptr;
        WalkResult* out = nullptr;
        bool stop = false;
    };

    void diag(WalkResult& out, Severity s, const char* code, std::string msg) const {
        out.diagnostics.push_back({s, code, std::move(msg)});
    }

    const Limits& limits(const Walk& w) const {
        static const Limits kDefault{};
        return w.opts != nullptr ? w.opts->limits : kDefault;
    }

    std::uint64_t cluster_offset(std::uint32_t c) const {
        return data_start + static_cast<std::uint64_t>(c - 2) * cluster_bytes;
    }
    bool valid_cluster(std::uint32_t c) const { return c >= 2 && (c - 2) < clusters; }

    /// The end-of-chain marker for this width. Anything at or above it ends a
    /// chain; one below it is the bad-cluster mark.
    std::uint32_t eoc() const {
        return bits == 12 ? 0x0FF8u : (bits == 16 ? 0xFFF8u : 0x0FFFFFF8u);
    }

    /// FAT[n]. FAT12 packs one and a half bytes per entry, so an entry can
    /// straddle a sector; it is read as a 16-bit window and shifted.
    bool fat_entry(std::uint32_t c, std::uint32_t& next) const {
        if (bits == 32) {
            const auto v = span.at<std::uint32_t>(fat_start + 4ull * c, Endian::Little);
            if (!v) return false;
            next = *v & 0x0FFFFFFFu;
            return true;
        }
        if (bits == 16) {
            const auto v = span.at<std::uint16_t>(fat_start + 2ull * c, Endian::Little);
            if (!v) return false;
            next = *v;
            return true;
        }
        const std::uint64_t off = fat_start + c + (c / 2);
        const auto v = span.at<std::uint16_t>(off, Endian::Little);
        if (!v) return false;
        next = (c & 1u) != 0 ? static_cast<std::uint32_t>(*v >> 4)
                             : static_cast<std::uint32_t>(*v & 0x0FFFu);
        return true;
    }

    /// Every cluster of a chain, in order. Stops at the end marker, at a
    /// cluster outside the data area, at a repeat (a loop) and at
    /// kMaxChainClusters. `why` says which, for the caller's diagnostic.
    bool chain(std::uint32_t first, std::vector<std::uint32_t>& out, std::string* why) const {
        out.clear();
        if (!valid_cluster(first)) {
            if (why) *why = "first cluster " + dec(first) + " is outside the data area";
            return false;
        }
        std::set<std::uint32_t> seen;
        std::uint32_t c = first;
        while (out.size() < kMaxChainClusters) {
            if (!seen.insert(c).second) {
                if (why) *why = "the cluster chain loops at " + dec(c);
                return false;
            }
            out.push_back(c);
            std::uint32_t next = 0;
            if (!fat_entry(c, next)) {
                if (why) *why = "FAT entry for cluster " + dec(c) + " is outside the image";
                return false;
            }
            if (next >= eoc()) return true;  // normal end
            if (next == eoc() - 1) {         // the bad-cluster mark
                if (why) *why = "cluster " + dec(c) + " chains to the bad-cluster mark";
                return false;
            }
            if (!valid_cluster(next)) {
                if (why)
                    *why = "cluster " + dec(c) + " chains to " + dec(next) +
                           ", which is outside the data area";
                return false;
            }
            c = next;
        }
        if (why) *why = "the cluster chain is longer than " + dec(kMaxChainClusters) + " clusters";
        return false;
    }

    Status parse_bpb();
    // Decodes one directory's worth of bytes into entries, assembling long
    // names. `deleted_too` keeps the 0xE5 entries.
    void parse_dir(const std::vector<std::uint8_t>& bytes, bool deleted_too,
                   std::vector<Entry>& out, WalkResult& res) const;
    bool read_dir_bytes(std::uint32_t first_cluster, bool fixed_root,
                        std::vector<std::uint8_t>& out, std::string* why) const;
    void walk_dir(std::uint32_t first_cluster, bool fixed_root, const std::string& prefix,
                  std::size_t depth, std::set<std::uint32_t>& visiting, Walk& w);
    void emit_file(const Entry& e, const std::string& path, Walk& w);
    void emit_deleted(const Entry& e, const std::string& path, Walk& w);
};

// ------------------------------------------------------------------ superblock

Status FatReader::Impl::parse_bpb() {
    constexpr Endian e = Endian::Little;
    auto u8 = [&](std::uint64_t o) { return span.at<std::uint8_t>(o, e); };
    auto u16 = [&](std::uint64_t o) { return span.at<std::uint16_t>(o, e); };
    auto u32 = [&](std::uint64_t o) { return span.at<std::uint32_t>(o, e); };

    const auto jmp = u8(0);
    const auto bps = u16(11);
    const auto spc = u8(13);
    const auto rsv = u16(14);
    const auto nfat = u8(16);
    const auto rent = u16(17);
    const auto tot16 = u16(19);
    const auto fsz16 = u16(22);
    const auto tot32 = u32(32);
    if (!jmp || !bps || !spc || !rsv || !nfat || !rent || !tot16 || !fsz16 || !tot32)
        return Status::fail("fat-bad-superblock: fewer than 36 bytes of BPB");
    if (*jmp != 0xEB && *jmp != 0xE9)
        return Status::fail("fat-bad-superblock: no jump instruction at offset 0");
    if (*bps < 512 || *bps > 4096 || (*bps & (*bps - 1)) != 0)
        return Status::fail("fat-bad-superblock: bytes per sector " + dec(*bps));
    if (*spc == 0 || (*spc & (*spc - 1)) != 0 || *spc > 128)
        return Status::fail("fat-bad-superblock: sectors per cluster " + dec(*spc));
    if (*rsv == 0 || *nfat == 0 || *nfat > 4)
        return Status::fail("fat-bad-superblock: reserved sectors " + dec(*rsv) + ", FAT count " +
                            dec(*nfat));

    bytes_per_sector = *bps;
    sectors_per_cluster = *spc;
    cluster_bytes = static_cast<std::uint32_t>(*bps) * *spc;
    reserved_sectors = *rsv;
    num_fats = *nfat;
    root_entries = *rent;
    total_sectors = *tot16 != 0 ? *tot16 : *tot32;
    fat_sectors = *fsz16;
    if (*fsz16 == 0) {
        const auto fsz32 = u32(36);
        const auto rclus = u32(44);
        if (!fsz32 || !rclus) return Status::fail("fat-bad-superblock: truncated FAT32 BPB");
        fat_sectors = *fsz32;
        root_cluster = *rclus;
    }
    if (total_sectors == 0 || fat_sectors == 0)
        return Status::fail("fat-bad-superblock: total sectors " + dec(total_sectors) +
                            ", FAT size " + dec(fat_sectors));

    const std::uint64_t root_dir_sectors =
        (static_cast<std::uint64_t>(root_entries) * kDirEntrySize + bytes_per_sector - 1) /
        bytes_per_sector;
    const std::uint64_t meta = static_cast<std::uint64_t>(reserved_sectors) +
                               static_cast<std::uint64_t>(num_fats) * fat_sectors +
                               root_dir_sectors;
    if (meta >= total_sectors)
        return Status::fail("fat-bad-superblock: no data area in " + dec(total_sectors) +
                            " sectors");
    clusters = (total_sectors - meta) / sectors_per_cluster;
    if (clusters == 0) return Status::fail("fat-bad-superblock: no data clusters");

    // The specification's definition, and the only one.
    bits = clusters < 4085 ? 12 : (clusters < 65525 ? 16 : 32);

    fat_start = static_cast<std::uint64_t>(reserved_sectors) * bytes_per_sector;
    root_dir_start =
        fat_start + static_cast<std::uint64_t>(num_fats) * fat_sectors * bytes_per_sector;
    root_dir_bytes = root_dir_sectors * bytes_per_sector;
    data_start = root_dir_start + root_dir_bytes;

    if (bits == 32) {
        if (root_entries != 0)
            return Status::fail("fat-bad-superblock: FAT32 with a non-zero root-entry count");
        if (!valid_cluster(root_cluster))
            return Status::fail("fat-bad-superblock: root cluster " + dec(root_cluster) +
                                " outside the data area");
    } else if (root_entries == 0) {
        return Status::fail("fat-bad-superblock: FAT12/16 with no fixed root directory");
    }

    // Label and volume id live in the extended BPB, at a different offset per
    // width. They are cosmetic; a missing one is not a failure.
    const std::uint64_t ext = bits == 32 ? 64 : 36;
    if (const auto boot_sig = u8(ext + 2); boot_sig && *boot_sig == 0x29) {
        if (const auto vid = u32(ext + 3)) volume_id = *vid;
        if (const auto raw = span.bytes(ext + 7, 11)) {
            label.assign(raw->begin(), raw->end());
            while (!label.empty() && (label.back() == ' ' || label.back() == '\0'))
                label.pop_back();
        }
    }
    if (const auto raw = span.bytes(3, 8)) {
        oem.assign(raw->begin(), raw->end());
        while (!oem.empty() && (oem.back() == ' ' || oem.back() == '\0')) oem.pop_back();
    }

    const std::uint64_t claimed = total_sectors * bytes_per_sector;
    if (claimed > span.size())
        open_diags.push_back({Severity::Warning, "fat-truncated",
                              "the BPB describes " + dec(claimed) + " bytes but only " +
                                  dec(span.size()) + " are available"});
    opened = true;
    return Status::success();
}

// ------------------------------------------------------------------ directories

void FatReader::Impl::parse_dir(const std::vector<std::uint8_t>& bytes, bool deleted_too,
                                std::vector<Entry>& out, WalkResult& res) const {
    out.clear();
    // Long-name fragments accumulate until the 8.3 entry they belong to.
    std::vector<std::uint16_t> lfn;
    std::uint8_t lfn_checksum = 0;
    std::uint32_t lfn_expect = 0;  // the ordinal the next entry must carry
    bool lfn_deleted = false;
    auto drop_lfn = [&]() {
        lfn.clear();
        lfn_expect = 0;
        lfn_checksum = 0;
        lfn_deleted = false;
    };

    for (std::size_t off = 0; off + kDirEntrySize <= bytes.size(); off += kDirEntrySize) {
        const std::uint8_t* e = bytes.data() + off;
        if (e[0] == kEntryEnd) break;  // this and everything after it is unused
        const std::uint8_t attr = e[11];
        const bool deleted = e[0] == kEntryFree;
        if (deleted && !deleted_too) {
            drop_lfn();
            continue;
        }

        if ((attr & kAttrLongName) == kAttrLongName && e[11] == kAttrLongName) {
            // A long-name fragment. The ordinal counts down, so the entries
            // are met last-fragment-first and each one prepends.
            //
            // A deleted fragment has that ordinal overwritten by the same 0xE5
            // stamp, so it cannot be used to count or order anything: those
            // are accumulated positionally and accepted for whatever they
            // turn out to spell.
            const std::uint8_t ord = e[0];
            const std::uint32_t n = ord & 0x1FU;
            if (deleted) {
                if (!lfn_deleted) drop_lfn();
                lfn_deleted = true;
                lfn_checksum = e[13];
                lfn_expect = 0;
            } else if ((ord & kLastLongEntry) != 0 || lfn_expect == 0) {
                drop_lfn();
                lfn_expect = n;
                lfn_checksum = e[13];
            } else if (n != lfn_expect) {
                drop_lfn();  // out of order: a stale fragment, not a name
                continue;
            }
            if (!deleted && (n == 0 || n > 20)) {
                drop_lfn();
                continue;
            }
            std::vector<std::uint16_t> part;
            static constexpr int kOffsets[] = {1,  3,  5,  7,  9,  14, 16,
                                               18, 20, 22, 24, 28, 30};  // 5 + 6 + 2 UTF-16 units
            for (const int o : kOffsets) {
                const auto u = static_cast<std::uint16_t>(e[o] | (e[o + 1] << 8));
                if (u == 0x0000 || u == 0xFFFF) break;
                part.push_back(u);
            }
            lfn.insert(lfn.begin(), part.begin(), part.end());
            if (!deleted) lfn_expect = n - 1;
            if (lfn.size() > kMaxLongNameChars) drop_lfn();
            continue;
        }

        // A real 8.3 entry. The volume label is not a file.
        if ((attr & kAttrVolumeId) != 0) {
            drop_lfn();
            continue;
        }
        bool is_dot = false;
        const std::string sname = short_name(e, is_dot);
        if (is_dot) {  // "." and ".." are how a walk loops
            drop_lfn();
            continue;
        }

        Entry ent;
        ent.attr = attr;
        ent.deleted = deleted;
        ent.directory = (attr & kAttrDirectory) != 0;
        ent.first_cluster = static_cast<std::uint32_t>(e[26] | (e[27] << 8)) |
                            (static_cast<std::uint32_t>(e[20] | (e[21] << 8)) << 16);
        ent.size = static_cast<std::uint64_t>(e[28]) | (static_cast<std::uint64_t>(e[29]) << 8) |
                   (static_cast<std::uint64_t>(e[30]) << 16) |
                   (static_cast<std::uint64_t>(e[31]) << 24);
        ent.mtime = fat_time(static_cast<std::uint16_t>(e[24] | (e[25] << 8)),
                             static_cast<std::uint16_t>(e[22] | (e[23] << 8)));
        ent.crtime = fat_time(static_cast<std::uint16_t>(e[16] | (e[17] << 8)),
                              static_cast<std::uint16_t>(e[14] | (e[15] << 8)));
        ent.atime = fat_time(static_cast<std::uint16_t>(e[18] | (e[19] << 8)), 0);

        // The long name is authoritative when its checksum matches the 8.3
        // entry it precedes. A deleted file loses the first character of its
        // short name to the 0xE5 stamp, so its long name is the only intact
        // one -- and the checksum still covers the *stamped* short name, so it
        // cannot be verified. Take it, and say the name came from the
        // fragments rather than pretending it was confirmed.
        if (!lfn.empty() && lfn_expect == 0) {
            const bool ok = lfn_checksum == short_name_checksum(e);
            if (ok || (deleted && lfn_deleted)) {
                utf16_to_utf8(lfn, ent.name);
            }
        }
        if (ent.name.empty()) {
            ent.name = sname;
            ent.name_stamped = deleted;  // the 8.3 name lost its first character
        }
        drop_lfn();
        if (ent.name.empty() || ent.name == "." || ent.name == "..") continue;
        // A name is a path component: a separator in one would move the entry.
        if (ent.name.find('/') != std::string::npos || ent.name.find('\\') != std::string::npos) {
            res.diagnostics.push_back({Severity::Warning, kCodeBadEntry,
                                       "an entry name contains a path separator and was skipped"});
            continue;
        }
        out.push_back(std::move(ent));
    }
    if (!lfn.empty()) {
        res.diagnostics.push_back(
            {Severity::Info, kCodeOrphanLongName,
             "a directory ends with long-name entries that name nothing; ignored"});
    }
}

bool FatReader::Impl::read_dir_bytes(std::uint32_t first_cluster, bool fixed_root,
                                     std::vector<std::uint8_t>& out, std::string* why) const {
    out.clear();
    if (fixed_root) {
        auto raw = span.bytes(root_dir_start, root_dir_bytes);
        if (!raw) {
            if (why) *why = "the fixed root directory runs past the image";
            return false;
        }
        out = std::move(*raw);
        return true;
    }
    std::vector<std::uint32_t> cl;
    if (!chain(first_cluster, cl, why)) return false;
    out.reserve(cl.size() * cluster_bytes);
    for (const std::uint32_t c : cl) {
        auto raw = span.bytes(cluster_offset(c), cluster_bytes);
        if (!raw) {
            if (why) *why = "cluster " + dec(c) + " runs past the image";
            return false;
        }
        out.insert(out.end(), raw->begin(), raw->end());
    }
    return true;
}

// ------------------------------------------------------------------ walk

void FatReader::Impl::emit_file(const Entry& e, const std::string& path, Walk& w) {
    FileMeta m;
    m.path = path;
    m.kind = EntryKind::Regular;
    // FAT has no permission bits. Report the attribute byte as mode-ish
    // information in `extra` and give a plain 0644/0444 so the case directory
    // is usable; docs/formats/fat.md says the mode is synthesised.
    m.mode = (e.attr & kAttrReadOnly) != 0 ? 0444u : 0644u;
    m.size = e.size;
    if (e.mtime != 0) m.mtime = e.mtime;
    if (e.crtime != 0) m.crtime = e.crtime;
    if (e.atime != 0) m.atime = e.atime;
    m.inode = e.first_cluster;
    m.nlink = 1;
    if ((e.attr & kAttrHidden) != 0) m.extra["hidden"] = "true";
    if ((e.attr & kAttrSystem) != 0) m.extra["system"] = "true";
    if ((e.attr & kAttrReadOnly) != 0) m.extra["read_only"] = "true";

    if (w.opts != nullptr && !w.opts->extract_data) {
        EntryResult r;
        if (const Status s = w.sink->entry(m, r); !s) {
            diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + s.error);
            return;
        }
        w.out->entries_out.push_back(std::move(r));
        ++w.out->entries;
        ++w.out->files;
        return;
    }

    std::string why;
    std::vector<std::uint32_t> cl;
    if (e.size > 0 && !chain(e.first_cluster, cl, &why)) {
        diag(*w.out, Severity::Warning, kCodeBadChain, "'" + path + "': " + why);
        return;
    }
    if (const Status s = w.sink->begin_file(m); !s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + s.error);
        return;
    }
    std::uint64_t left = e.size;
    bool short_read = false;
    for (const std::uint32_t c : cl) {
        if (left == 0) break;
        const std::uint64_t n = std::min<std::uint64_t>(left, cluster_bytes);
        auto raw = span.bytes(cluster_offset(c), n);
        if (!raw) {
            short_read = true;
            break;
        }
        if (const Status s = w.sink->write(*raw); !s) {
            // A limit is the Sink's to report; it already kept the prefix.
            break;
        }
        left -= n;
    }
    EntryResult r;
    if (const Status s = w.sink->end_file(r); !s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + s.error);
        return;
    }
    if (short_read || left != 0) {
        r.truncated = true;
        diag(*w.out, Severity::Warning, kCodeShortRead,
             "'" + path + "': the chain ran out " + dec(left) + " bytes before the recorded size");
    }
    w.out->bytes += e.size - left;
    w.out->entries_out.push_back(std::move(r));
    ++w.out->entries;
    ++w.out->files;
}

void FatReader::Impl::emit_deleted(const Entry& e, const std::string& path, Walk& w) {
    // Deleting a file frees its chain, so there is nothing left to follow: the
    // entry keeps only the first cluster and the size. Reading the clusters
    // that *follow* it recovers a file that was not fragmented and, for one
    // that was, the right number of bytes from the wrong places. Both are
    // labelled the same way, because from the entry alone they are
    // indistinguishable -- the examiner needs to know that, not be told a
    // recovery succeeded.
    FileMeta m;
    m.path = path;
    m.kind = EntryKind::Regular;
    m.mode = 0644;
    m.size = e.size;
    m.deleted = true;
    if (e.mtime != 0) m.mtime = e.mtime;
    if (e.crtime != 0) m.crtime = e.crtime;
    if (e.atime != 0) m.atime = e.atime;
    m.inode = e.first_cluster;
    m.extra["recovery"] = "contiguous from the first cluster; the FAT chain was freed by deletion";
    if (e.name_stamped) {
        m.extra["name_first_char"] =
            "lost: deletion overwrote it with 0xE5 and there is no long-name entry to recover it "
            "from; it is shown as '_'";
    }

    const bool want_data =
        w.opts != nullptr && w.opts->extract_data && e.size > 0 && valid_cluster(e.first_cluster);
    if (!want_data) {
        EntryResult r;
        if (const Status s = w.sink->entry(m, r); !s) {
            diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + s.error);
            return;
        }
        w.out->entries_out.push_back(std::move(r));
        ++w.out->entries;
        ++w.out->files;
        ++w.out->deleted;
        return;
    }
    if (const Status s = w.sink->begin_file(m); !s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + s.error);
        return;
    }
    std::uint64_t left = e.size;
    std::uint32_t c = e.first_cluster;
    while (left > 0 && valid_cluster(c)) {
        const std::uint64_t n = std::min<std::uint64_t>(left, cluster_bytes);
        auto raw = span.bytes(cluster_offset(c), n);
        if (!raw) break;
        if (const Status s = w.sink->write(*raw); !s) break;
        left -= n;
        ++c;
    }
    EntryResult r;
    if (const Status s = w.sink->end_file(r); !s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + s.error);
        return;
    }
    if (e.size > cluster_bytes) {
        diag(*w.out, Severity::Info, kCodeDeletedFragmented,
             "'" + path + "': recovered " + dec(e.size) + " bytes contiguously from cluster " +
                 dec(e.first_cluster) +
                 "; the file spans more than one cluster and its chain is gone, so the bytes "
                 "after the first cluster are only correct if it was never fragmented");
    }
    if (left != 0) r.truncated = true;
    w.out->bytes += e.size - left;
    w.out->entries_out.push_back(std::move(r));
    ++w.out->entries;
    ++w.out->files;
    ++w.out->deleted;
}

void FatReader::Impl::walk_dir(std::uint32_t first_cluster, bool fixed_root,
                               const std::string& prefix, std::size_t depth,
                               std::set<std::uint32_t>& visiting, Walk& w) {
    if (w.stop || depth > kMaxDirDepth) {
        if (depth > kMaxDirDepth)
            diag(*w.out, Severity::Warning, kCodeDirLoop,
                 "'" + prefix + "': directory nesting deeper than " + dec(kMaxDirDepth));
        return;
    }
    std::string why;
    std::vector<std::uint8_t> bytes;
    if (!read_dir_bytes(first_cluster, fixed_root, bytes, &why)) {
        diag(*w.out, Severity::Warning, kCodeBadChain,
             "'" + (prefix.empty() ? std::string("/") : prefix) + "': " + why);
        return;
    }
    const bool history = w.opts != nullptr && w.opts->history;
    std::vector<Entry> entries;
    parse_dir(bytes, history, entries, *w.out);

    for (const Entry& e : entries) {
        if (w.stop) return;
        if (w.out->entries >= limits(w).max_nodes_per_fs) {
            w.stop = true;
            w.out->truncated = true;
            diag(*w.out, Severity::Warning, kCodeLimitNodes,
                 "stopped at max_nodes_per_fs (" + dec(limits(w).max_nodes_per_fs) + ")");
            return;
        }
        const std::string path = prefix.empty() ? e.name : prefix + "/" + e.name;
        if (e.deleted) {
            // A deleted directory's chain is gone too, so its children cannot
            // be reached reliably; the entry itself is still evidence.
            if (e.directory) {
                FileMeta m;
                m.path = path;
                m.kind = EntryKind::Directory;
                m.mode = 0755;
                m.deleted = true;
                if (e.mtime != 0) m.mtime = e.mtime;
                m.inode = e.first_cluster;
                m.extra["recovery"] = "directory entry only; the chain was freed by deletion";
                if (e.name_stamped) {
                    m.extra["name_first_char"] =
                        "lost: deletion overwrote it with 0xE5 and there is no long-name entry to "
                        "recover it from; it is shown as '_'";
                }
                EntryResult r;
                if (const Status s = w.sink->entry(m, r); s) {
                    w.out->entries_out.push_back(std::move(r));
                    ++w.out->entries;
                    ++w.out->dirs;
                    ++w.out->deleted;
                }
            } else {
                emit_deleted(e, path, w);
            }
            continue;
        }
        if (e.directory) {
            if (!valid_cluster(e.first_cluster)) {
                diag(*w.out, Severity::Warning, kCodeBadEntry,
                     "'" + path + "': directory first cluster " + dec(e.first_cluster) +
                         " is outside the data area");
                continue;
            }
            FileMeta m;
            m.path = path;
            m.kind = EntryKind::Directory;
            m.mode = 0755;
            if (e.mtime != 0) m.mtime = e.mtime;
            if (e.crtime != 0) m.crtime = e.crtime;
            if (e.atime != 0) m.atime = e.atime;
            m.inode = e.first_cluster;
            EntryResult r;
            if (const Status s = w.sink->entry(m, r); !s) {
                diag(*w.out, Severity::Warning, kCodeSinkError, "'" + path + "': " + s.error);
                continue;
            }
            w.out->entries_out.push_back(std::move(r));
            ++w.out->entries;
            ++w.out->dirs;
            // A directory whose chain reaches one already being walked is a
            // loop; ".." is filtered out, but a corrupt entry can still do it.
            if (!visiting.insert(e.first_cluster).second) {
                diag(
                    *w.out, Severity::Warning, kCodeDirLoop,
                    "'" + path + "': cluster " + dec(e.first_cluster) + " is already being walked");
                continue;
            }
            walk_dir(e.first_cluster, false, path, depth + 1, visiting, w);
            visiting.erase(e.first_cluster);
            continue;
        }
        emit_file(e, path, w);
    }
}

// ------------------------------------------------------------------ public

FatReader::FatReader() : impl_(std::make_unique<Impl>()) {}
FatReader::~FatReader() = default;

std::string FatReader::format() const {
    return "fat";
}

Status FatReader::open(const Span& span) {
    impl_ = std::make_unique<Impl>();
    impl_->span = span;
    return impl_->parse_bpb();
}

FilesystemInfo FatReader::info() const {
    const Impl& im = *impl_;
    FilesystemInfo fi;
    fi.format = "fat";
    if (!im.opened) return fi;
    fi.label = im.label;
    fi.size = im.total_sectors * im.bytes_per_sector;
    fi.block_size = im.cluster_bytes;
    fi.endian = Endian::Little;
    fi.attrs["fat_type"] = "fat" + dec(static_cast<std::uint64_t>(im.bits));
    fi.attrs["bytes_per_sector"] = dec(im.bytes_per_sector);
    fi.attrs["sectors_per_cluster"] = dec(im.sectors_per_cluster);
    fi.attrs["cluster_size"] = dec(im.cluster_bytes);
    fi.attrs["clusters"] = dec(im.clusters);
    fi.attrs["fat_count"] = dec(im.num_fats);
    fi.attrs["fat_sectors"] = dec(im.fat_sectors);
    fi.attrs["total_sectors"] = dec(im.total_sectors);
    fi.attrs["reserved_sectors"] = dec(im.reserved_sectors);
    if (im.bits == 32)
        fi.attrs["root_cluster"] = dec(im.root_cluster);
    else
        fi.attrs["root_entries"] = dec(im.root_entries);
    if (!im.label.empty()) fi.attrs["label"] = im.label;
    if (!im.oem.empty()) fi.attrs["oem_name"] = im.oem;
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%08X", im.volume_id);
    fi.attrs["volume_id"] = buf;
    return fi;
}

Status FatReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    Impl& im = *impl_;
    if (!im.opened) return Status::fail("fat-not-open: walk() before a successful open()");
    out = WalkResult{};
    for (const Diagnostic& d : im.open_diags) out.diagnostics.push_back(d);

    Impl::Walk w;
    w.sink = &sink;
    w.opts = &opts;
    w.out = &out;
    std::set<std::uint32_t> visiting;
    if (im.bits == 32) visiting.insert(im.root_cluster);
    im.walk_dir(im.bits == 32 ? im.root_cluster : 0, im.bits != 32, "", 0, visiting, w);
    return Status::success();
}

OMNITRACE_REGISTER_FILESYSTEM("fat", FatReader);

}  // namespace omnitrace::fs
