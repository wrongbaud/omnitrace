// UbiReader.cpp — UBI volume reassembly.
//
// A UBI image is a flat sequence of physical erase blocks (PEBs). Each PEB
// begins with a 64-byte erase-counter header ("UBI#", big-endian, validated
// in src/discovery/validators/ubi.cpp) and, at `vid_hdr_offset`, a 64-byte
// volume-identifier header:
//
//    0 magic "UBI!"    4 version u8     5 vol_type u8   6 copy_flag u8
//    7 compat u8       8 vol_id u32    12 lnum u32     16 pad u32
//   20 data_size u32  24 used_ebs u32  28 data_pad u32  32 data_crc u32
//   40 sqnum u64      60 hdr_crc u32
//
// so the PEB says which volume and which *logical* erase block it holds. The
// order on the medium is meaningless -- wear levelling scatters a volume's
// LEBs -- and the same LEB can appear in two PEBs when an update was
// interrupted or a block was moved. `sqnum` orders those: the highest wins,
// and the earlier copies are prior states of that block, which is why
// `WalkOptions::history` emits them.
//
// Volume names live in the layout volume (id 0x7FFFEFFF), whose two LEBs hold
// an array of 172-byte records:
//
//    0 reserved_pebs u32   4 alignment u32   8 data_pad u32   12 vol_type u8
//   13 upd_marker u8      14 name_len u16   16 name[128]     144 flags u8
//  168 crc u32                                    (crc32 over the first 168)
//
// What this emits is the volume image a `ubiattach` would expose: LEB 0
// first, each LEB `peb_size - data_offset - data_pad` bytes, static volumes
// cut to the `data_size` their VID headers declare. That is what `ubinize`
// consumed, and what a UBIFS or SquashFS reader can be pointed at.
//
// Reference: Linux drivers/mtd/ubi/ubi-media.h (read for understanding, no
// code copied); `ubireader_extract_images`, whose output this matches byte
// for byte.
#include "UbiReader.h"

#include <algorithm>
#include <map>
#include <array>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "../../discovery/crc32.h"
#include "../common.h"
#include "omnitrace/core/Endian.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::container {

namespace {

constexpr std::uint64_t kHeaderSize = 64;
constexpr std::array<std::uint8_t, 4> kEcMagic{'U', 'B', 'I', '#'};
constexpr std::array<std::uint8_t, 4> kVidMagic{'U', 'B', 'I', '!'};
constexpr std::uint8_t kVolStatic = 2;

// The volume table: an array of records in each LEB of the layout volume.
constexpr std::uint64_t kVtblRecordSize = 172;
constexpr std::uint64_t kVtblCrcBytes = 168;
constexpr std::uint64_t kVtblNameMax = 127;
// UBI's own cap; a table claiming more is damaged rather than large.
constexpr std::uint64_t kMaxVolumes = 128;

// A hostile or damaged image must not turn into an unbounded walk. Real
// images are thousands of PEBs; a 4 GiB NAND at the smallest 16 KiB PEB is
// 262144, so this leaves room and still terminates.
constexpr std::uint64_t kMaxPebs = 1u << 20;

// Stable codes; literal so scripts/gen_docs.py can catalogue them.
constexpr const char* kCodeNoVolumes = "ubi-no-volumes";
constexpr const char* kCodeVtblUnreadable = "ubi-vtbl-unreadable";
constexpr const char* kCodeLebGap = "ubi-leb-gap";
constexpr const char* kCodeLebSuperseded = "ubi-leb-superseded";
constexpr const char* kCodeBadPeb = "ubi-bad-peb";
constexpr const char* kCodeLimitEntries = "ubi-limit-entries";
constexpr const char* kCodeShortSection = "container-section-truncated";
constexpr const char* kCodeSinkError = "container-sink-error";

bool header_crc_ok(const std::array<std::uint8_t, kHeaderSize>& raw) {
    const std::uint32_t stored = load_int<std::uint32_t>(raw.data() + 60, Endian::Big);
    return discovery::crc32_ubi(std::span<const std::uint8_t>(raw.data(), 60)) == stored;
}

bool all_ff(std::span<const std::uint8_t> b) {
    return std::all_of(b.begin(), b.end(), [](std::uint8_t v) { return v == 0xFF; });
}

}  // namespace

Status UbiReader::open(const Span& span) {
    opened_ = false;
    volumes_.clear();
    vtbl_names_.clear();
    vtbl_problem_.clear();
    erased_pebs_ = skipped_pebs_ = unmapped_pebs_ = peb_count_ = bogus_lnums_ = 0;

    std::array<std::uint8_t, kHeaderSize> ec{};
    if (span.read(0, std::span<std::uint8_t>(ec.data(), ec.size())) != ec.size())
        return Status::fail("container-empty: fewer than 64 bytes for the EC header");
    if (!std::equal(kEcMagic.begin(), kEcMagic.end(), ec.begin()))
        return Status::fail("container-bad-magic: no UBI# magic at offset 0");
    if (!header_crc_ok(ec))
        return Status::fail("container-bad-header: the first EC header's CRC does not match, so "
                            "nothing anchors the PEB walk");

    vid_hdr_offset_ = load_int<std::uint32_t>(ec.data() + 16, Endian::Big);
    data_offset_ = load_int<std::uint32_t>(ec.data() + 20, Endian::Big);
    image_seq_ = load_int<std::uint32_t>(ec.data() + 24, Endian::Big);
    if (ec[4] != 1 || vid_hdr_offset_ < kHeaderSize ||
        data_offset_ < vid_hdr_offset_ + kHeaderSize || data_offset_ > span.size())
        return Status::fail("container-bad-header: the EC header's version or offsets are out of "
                            "range");

    span_ = span;
    peb_size_ = derive_peb_size();
    if (peb_size_ == 0)
        return Status::fail("container-bad-header: no second EC header, so the erase-block size "
                            "cannot be derived and the LEBs cannot be placed");

    scan_pebs();
    read_volume_table();
    opened_ = true;
    return Status::success();
}

// The PEB size is nowhere on the medium: it is the distance to the next EC
// header. Real producers align the next PEB to a multiple of the minimum I/O
// unit, which `vid_hdr_offset` is, so the probe steps by that.
std::uint64_t UbiReader::derive_peb_size() const {
    const std::uint64_t step = vid_hdr_offset_;
    if (step == 0) return 0;
    std::array<std::uint8_t, kHeaderSize> raw{};
    for (std::uint64_t off = data_offset_; off + kHeaderSize <= span_.size(); off += step) {
        if (span_.read(off, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size()) break;
        if (!std::equal(kEcMagic.begin(), kEcMagic.end(), raw.begin())) continue;
        if (header_crc_ok(raw)) return off;
    }
    return 0;
}

// Walk every PEB, read its VID header, and file the LEB under its volume.
void UbiReader::scan_pebs() {
    std::array<std::uint8_t, kHeaderSize> ec{};
    std::array<std::uint8_t, kHeaderSize> vid{};
    for (std::uint64_t peb = 0; peb < kMaxPebs; ++peb) {
        const std::uint64_t at = peb * peb_size_;
        if (at + data_offset_ > span_.size()) break;
        ++peb_count_;
        if (span_.read(at, std::span<std::uint8_t>(ec.data(), ec.size())) != ec.size()) break;
        if (all_ff(std::span<const std::uint8_t>(ec.data(), ec.size()))) {
            ++erased_pebs_;
            continue;
        }
        if (!std::equal(kEcMagic.begin(), kEcMagic.end(), ec.begin()) || !header_crc_ok(ec)) {
            ++skipped_pebs_;
            continue;
        }
        // Each PEB carries its own offsets; a mixed image is malformed, but
        // reading them per PEB costs nothing and mis-places nothing.
        const std::uint32_t vho = load_int<std::uint32_t>(ec.data() + 16, Endian::Big);
        const std::uint32_t dof = load_int<std::uint32_t>(ec.data() + 20, Endian::Big);
        if (vho < kHeaderSize || dof < vho + kHeaderSize || dof >= peb_size_) {
            ++skipped_pebs_;
            continue;
        }
        if (span_.read(at + vho, std::span<std::uint8_t>(vid.data(), vid.size())) != vid.size())
            break;
        if (!std::equal(kVidMagic.begin(), kVidMagic.end(), vid.begin()) || !header_crc_ok(vid)) {
            // An unmapped PEB: erased and counted, never claimed by a volume.
            ++unmapped_pebs_;
            continue;
        }

        Leb leb;
        leb.peb = peb;
        leb.data_off = at + dof;
        leb.is_static = vid[5] == kVolStatic;
        leb.copy_flag = vid[6] != 0;
        leb.data_size = load_int<std::uint32_t>(vid.data() + 20, Endian::Big);
        leb.used_ebs = load_int<std::uint32_t>(vid.data() + 24, Endian::Big);
        leb.data_pad = load_int<std::uint32_t>(vid.data() + 28, Endian::Big);
        leb.sqnum = load_int<std::uint64_t>(vid.data() + 40, Endian::Big);
        const std::uint32_t vol_id = load_int<std::uint32_t>(vid.data() + 8, Endian::Big);
        const std::uint32_t lnum = load_int<std::uint32_t>(vid.data() + 12, Endian::Big);

        Volume& v = volumes_[vol_id];
        v.id = vol_id;
        v.is_static = leb.is_static;
        const auto it = v.lebs.find(lnum);
        if (it == v.lebs.end()) {
            v.lebs.emplace(lnum, leb);
        } else if (leb.sqnum > it->second.sqnum) {
            // The block was rewritten: the older copy is a prior state of it.
            v.superseded.emplace_back(lnum, it->second);
            it->second = leb;
        } else {
            v.superseded.emplace_back(lnum, leb);
        }
    }
    // A volume cannot have more logical blocks than the image has physical
    // ones, so a larger lnum is a damaged or hostile VID header. Dropping it
    // is what bounds the gap fill in walk(): the loop there runs to the
    // highest lnum, and a header claiming 0xFFFFFFFE would otherwise ask for
    // four billion erased blocks.
    for (auto& [id, v] : volumes_) {
        for (auto it = v.lebs.begin(); it != v.lebs.end();) {
            if (it->first >= peb_count_) {
                ++bogus_lnums_;
                it = v.lebs.erase(it);
            } else {
                ++it;
            }
        }
        std::erase_if(v.superseded, [&](const auto& e) {
            if (e.first < peb_count_) return false;
            ++bogus_lnums_;
            return true;
        });
        std::stable_sort(v.superseded.begin(), v.superseded.end(),
                         [](const auto& a, const auto& b) { return a.second.sqnum < b.second.sqnum; });
    }
    std::erase_if(volumes_, [](const auto& e) { return e.second.lebs.empty(); });
}

// The layout volume's LEBs hold the volume table: one record per volume id,
// in index order. Two identical copies exist; the first that parses is used.
void UbiReader::read_volume_table() {
    const auto layout = volumes_.find(kLayoutVolumeId);
    if (layout == volumes_.end() || layout->second.lebs.empty()) {
        vtbl_problem_ = "the image has no layout volume (0x7FFFEFFF), so no volume is named";
        return;
    }
    for (const auto& [lnum, leb] : layout->second.lebs) {
        const std::uint64_t usable = usable_leb_bytes(leb);
        std::map<std::uint32_t, std::string> names;
        bool any = false;
        for (std::uint64_t i = 0; i < kMaxVolumes; ++i) {
            const std::uint64_t at = leb.data_off + i * kVtblRecordSize;
            if ((i + 1) * kVtblRecordSize > usable) break;
            const auto rec = span_.bytes(at, kVtblRecordSize);
            if (!rec) break;
            if (all_ff(std::span<const std::uint8_t>(rec->data(), rec->size()))) continue;
            const std::uint32_t stored = load_int<std::uint32_t>(rec->data() + kVtblCrcBytes,
                                                                Endian::Big);
            if (discovery::crc32_ubi(std::span<const std::uint8_t>(rec->data(), kVtblCrcBytes)) !=
                stored)
                continue;  // an empty or damaged slot, not a volume
            if (load_int<std::uint32_t>(rec->data(), Endian::Big) == 0) continue;  // reserved_pebs
            const std::uint64_t len =
                std::min<std::uint64_t>(load_int<std::uint16_t>(rec->data() + 14, Endian::Big),
                                        kVtblNameMax);
            names[static_cast<std::uint32_t>(i)] =
                sanitize_utf8(std::string(reinterpret_cast<const char*>(rec->data()) + 16,
                                          static_cast<std::size_t>(len)));
            any = true;
        }
        if (any) {
            vtbl_names_ = std::move(names);
            return;
        }
    }
    vtbl_problem_ = "the layout volume holds no volume-table record whose CRC matches";
}

// What one LEB of this volume contributes: the block minus the headers UBI
// keeps at its front, minus the padding the volume reserved for alignment.
std::uint64_t UbiReader::usable_leb_bytes(const Leb& leb) const {
    const std::uint64_t leb_size = peb_size_ > data_offset_ ? peb_size_ - data_offset_ : 0;
    return leb_size > leb.data_pad ? leb_size - leb.data_pad : 0;
}

ContainerInfo UbiReader::info() const {
    ContainerInfo i;
    i.format = "ubi";
    i.size = std::min(peb_count_ * peb_size_, span_.size());
    i.attrs["peb_size"] = std::to_string(peb_size_);
    i.attrs["leb_size"] =
        std::to_string(peb_size_ > data_offset_ ? peb_size_ - data_offset_ : 0);
    i.attrs["vid_hdr_offset"] = std::to_string(vid_hdr_offset_);
    i.attrs["data_offset"] = std::to_string(data_offset_);
    i.attrs["image_seq"] = std::to_string(image_seq_);
    i.attrs["pebs"] = std::to_string(peb_count_);
    i.attrs["erased_pebs"] = std::to_string(erased_pebs_);
    i.attrs["unmapped_pebs"] = std::to_string(unmapped_pebs_);
    if (skipped_pebs_ != 0) i.attrs["bad_pebs"] = std::to_string(skipped_pebs_);

    // "id:name:type:lebs;..." for every user volume, in id order.
    std::string list;
    std::uint64_t count = 0;
    for (const auto& [id, v] : volumes_) {
        if (id >= kInternalVolumeStart) continue;
        ++count;
        if (!list.empty()) list.push_back(';');
        const auto name = vtbl_names_.find(id);
        list += std::to_string(id) + ":" + (name != vtbl_names_.end() ? name->second : "") + ":" +
                (v.is_static ? "static" : "dynamic") + ":" + std::to_string(v.lebs.size());
    }
    i.attrs["volumes"] = std::to_string(count);
    if (!list.empty()) i.attrs["volume_table"] = list;
    return i;
}

Status UbiReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    if (!opened_) return Status::fail("container-not-open: walk before a successful open");

    if (!vtbl_problem_.empty()) {
        out.diagnostics.push_back({Severity::Warning, kCodeVtblUnreadable,
                                   vtbl_problem_ + "; volumes are named by their id"});
    }
    if (bogus_lnums_ != 0) {
        out.diagnostics.push_back(
            {Severity::Warning, kCodeBadPeb,
             std::to_string(bogus_lnums_) +
                 " PEB(s) name a logical erase block past the end of the image (" +
                 std::to_string(peb_count_) + " blocks); their VID headers are not believable and "
                 "they were dropped"});
    }
    if (skipped_pebs_ != 0) {
        out.diagnostics.push_back({Severity::Warning, kCodeBadPeb,
                                   std::to_string(skipped_pebs_) +
                                       " PEB(s) have an unreadable EC header and were skipped; any "
                                       "LEBs they held are missing from their volume"});
    }

    std::uint64_t emitted = 0;
    const std::uint64_t cap = opts.limits.max_nodes_per_fs;
    std::vector<std::uint8_t> buf;

    // One entry: the volume's LEBs in lnum order, gaps filled so every later
    // LEB still lands at the offset its volume puts it at.
    auto emit_volume = [&](const Volume& v, const std::string& path) {
        const std::uint32_t last = v.lebs.rbegin()->first;
        std::uint64_t total = 0;
        for (std::uint32_t n = 0; n <= last; ++n) {
            const auto it = v.lebs.find(n);
            if (it == v.lebs.end()) {
                total += usable_leb_bytes(v.lebs.begin()->second);
            } else {
                total += v.is_static ? std::min<std::uint64_t>(it->second.data_size,
                                                               usable_leb_bytes(it->second))
                                     : usable_leb_bytes(it->second);
            }
        }

        FileMeta meta;
        meta.path = path;
        meta.kind = EntryKind::Regular;
        meta.mode = 0644;
        meta.size = total;
        meta.extra["vol_id"] = std::to_string(v.id);
        meta.extra["vol_type"] = v.is_static ? "static" : "dynamic";
        meta.extra["lebs"] = std::to_string(v.lebs.size());
        meta.extra["leb_size"] = std::to_string(usable_leb_bytes(v.lebs.begin()->second));

        EntryResult r;
        if (Status st = sink.begin_file(meta); !st) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error});
            return;
        }
        std::uint64_t gaps = 0;
        bool short_read = false;
        for (std::uint32_t n = 0; n <= last && !short_read; ++n) {
            const auto it = v.lebs.find(n);
            const std::uint64_t want =
                it == v.lebs.end()
                    ? usable_leb_bytes(v.lebs.begin()->second)
                    : (v.is_static ? std::min<std::uint64_t>(it->second.data_size,
                                                             usable_leb_bytes(it->second))
                                   : usable_leb_bytes(it->second));
            if (!opts.extract_data) continue;
            if (buf.size() < static_cast<std::size_t>(std::min<std::uint64_t>(want, kCopyChunk)))
                buf.resize(static_cast<std::size_t>(std::min<std::uint64_t>(want, kCopyChunk)));
            if (it == v.lebs.end()) {
                // An unmapped LEB inside the volume. Erased flash reads as
                // 0xFF, and writing it keeps every later LEB at its right
                // offset, which is what a filesystem on top needs.
                ++gaps;
                std::fill(buf.begin(), buf.end(), static_cast<std::uint8_t>(0xFF));
                for (std::uint64_t done = 0; done < want;) {
                    const std::size_t n_out =
                        static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), want - done));
                    if (Status st = sink.write(std::span<const std::uint8_t>(buf.data(), n_out));
                        !st) {
                        out.diagnostics.push_back(
                            {Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error});
                        short_read = true;
                        break;
                    }
                    done += n_out;
                }
                continue;
            }
            for (std::uint64_t done = 0; done < want;) {
                const std::size_t n_in =
                    static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), want - done));
                const std::size_t got =
                    span_.read(it->second.data_off + done,
                               std::span<std::uint8_t>(buf.data(), n_in));
                if (got == 0) {
                    short_read = true;
                    break;
                }
                if (Status st = sink.write(std::span<const std::uint8_t>(buf.data(), got)); !st) {
                    out.diagnostics.push_back(
                        {Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error});
                    short_read = true;
                    break;
                }
                done += got;
                if (got < n_in) {
                    short_read = true;
                    break;
                }
            }
        }
        if (gaps != 0) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeLebGap,
                 "'" + path + "' is missing " + std::to_string(gaps) +
                     " logical erase block(s); they are filled with 0xFF so the blocks after them "
                     "stay at their own offsets"});
            out.truncated = true;
        }
        if (short_read) {
            out.diagnostics.push_back({Severity::Warning, kCodeShortSection,
                                       "'" + path + "' ends before the " + std::to_string(total) +
                                           " bytes its logical erase blocks add up to"});
            out.truncated = true;
        }
        if (Status st = sink.end_file(r); !st) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeSinkError, "'" + path + "': " + st.error});
            return;
        }
        if (gaps != 0 || short_read) r.truncated = true;
        count_entry(out, r);
        out.entries_out.push_back(std::move(r));
        ++emitted;
    };

    // One entry: a single superseded LEB, as it was before it was rewritten.
    auto emit_old_leb = [&](const Volume& v, const std::string& vol, std::uint32_t lnum,
                            const Leb& leb) {
        const std::uint64_t want = v.is_static
                                       ? std::min<std::uint64_t>(leb.data_size,
                                                                 usable_leb_bytes(leb))
                                       : usable_leb_bytes(leb);
        FileMeta meta;
        meta.path = vol + ".leb" + std::to_string(lnum) + ".sqnum" + std::to_string(leb.sqnum);
        meta.kind = EntryKind::Regular;
        meta.mode = 0644;
        meta.size = want;
        meta.superseded = true;
        meta.version = leb.sqnum;
        meta.extra["vol_id"] = std::to_string(v.id);
        meta.extra["lnum"] = std::to_string(lnum);
        meta.extra["sqnum"] = std::to_string(leb.sqnum);
        meta.extra["peb"] = std::to_string(leb.peb);
        if (leb.copy_flag) meta.extra["copy_flag"] = "1";

        EntryResult r;
        bool short_read = false;
        const Status st =
            emit_span_file(sink, opts, meta, span_, leb.data_off, want, r, short_read);
        if (!st) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + st.error});
            return;
        }
        if (short_read) r.truncated = true;
        count_entry(out, r);
        ++out.superseded;
        out.entries_out.push_back(std::move(r));
        ++emitted;
    };

    std::vector<std::string> taken;
    for (const auto& [id, v] : volumes_) {
        if (id >= kInternalVolumeStart) continue;  // UBI's own bookkeeping
        if (v.lebs.empty()) continue;
        if (emitted >= cap) {
            out.diagnostics.push_back({Severity::Warning, kCodeLimitEntries,
                                       "the entry limit (" + std::to_string(cap) +
                                           ") stopped the walk before every volume was emitted"});
            out.truncated = true;
            break;
        }
        const auto named = vtbl_names_.find(id);
        std::string path = named != vtbl_names_.end() && !named->second.empty()
                               ? safe_filename_component(named->second)
                               : "vol" + std::to_string(id);
        // A name comes from the volume table, which is evidence: two volumes
        // whose names collapse to the same component must not overwrite.
        const std::string base = path;
        for (unsigned n = 2; std::find(taken.begin(), taken.end(), path) != taken.end(); ++n)
            path = base + "_" + std::to_string(n);
        taken.push_back(path);

        emit_volume(v, path);
        if (!opts.history || v.superseded.empty()) {
            if (!v.superseded.empty()) {
                out.diagnostics.push_back(
                    {Severity::Info, kCodeLebSuperseded,
                     "'" + path + "' has " + std::to_string(v.superseded.size()) +
                         " superseded logical erase block(s); re-run with --history to extract "
                         "them"});
            }
            continue;
        }
        for (const auto& [lnum, leb] : v.superseded) {
            if (emitted >= cap) break;
            emit_old_leb(v, path, lnum, leb);
        }
    }

    if (emitted == 0) {
        out.diagnostics.push_back({Severity::Warning, kCodeNoVolumes,
                                   "no PEB carries a volume-identifier header, so the image holds "
                                   "no volume to rebuild"});
    }
    return Status::success();
}

OMNITRACE_REGISTER_CONTAINER("ubi", UbiReader);

namespace detail {
void omnitrace_container_anchor_ubi() {}
}  // namespace detail

}  // namespace omnitrace::container
