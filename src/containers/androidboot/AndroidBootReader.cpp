// AndroidBootReader.cpp — Android boot.img and vendor_boot.img. See the header.
//
// Layout, in both flavours: a header, then every non-empty section in a fixed
// order, each starting on a page boundary. The only subtlety is where the
// first section begins. For a boot image the header always occupies exactly
// one page, whatever `header_size` says; for a vendor boot image it occupies
// ceil(header_size / page_size). That is what AOSP's unpack_bootimg does, and
// the two rules genuinely differ.
//
// Field offsets are in src/discovery/validators/android_boot.cpp, which
// validates and sizes the same headers. This reader re-parses them because a
// reader is handed a Span, never a Finding.
//
// Reference: AOSP system/tools/mkbootimg/include/bootimg/bootimg.h and
// unpack_bootimg.py.
#include "AndroidBootReader.h"

#include <algorithm>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "../common.h"
#include "omnitrace/core/Endian.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::container {

namespace {

constexpr const char* kCodeShortSection = "container-section-truncated";
constexpr const char* kCodeSinkError = "container-sink-error";

// v3 and v4 boot images have no page_size field; the format fixes it.
constexpr std::uint32_t kV3Page = 4096;

std::uint64_t pages_for(std::uint64_t bytes, std::uint32_t page) {
    if (page == 0) return 0;
    return (bytes + page - 1) / page;
}

bool is_pow2(std::uint32_t v) {
    return v != 0 && (v & (v - 1)) == 0;
}

}  // namespace

Status AndroidBootReader::open(const Span& span) {
    opened_ = false;
    sections_.clear();
    name_.clear();

    static constexpr std::uint8_t kBoot[8] = {'A', 'N', 'D', 'R', 'O', 'I', 'D', '!'};
    static constexpr std::uint8_t kVendor[8] = {'V', 'N', 'D', 'R', 'B', 'O', 'O', 'T'};
    const std::span<const std::uint8_t> magic(vendor_ ? kVendor : kBoot, 8);
    if (!span.matches_at(0, magic))
        return Status::fail("container-bad-magic: no " + format() + " magic at offset 0");

    auto u32 = [&](std::uint64_t off) { return span.at<std::uint32_t>(off, Endian::Little); };

    if (vendor_) {
        const auto hv = u32(8), page = u32(12), ramdisk = u32(24), hs = u32(2096), dtb = u32(2100);
        if (!hv || !page || !ramdisk || !hs || !dtb)
            return Status::fail("container-empty: fewer than 2104 vendor boot header bytes");
        if (*hv < 3 || *hv > 4 || !is_pow2(*page))
            return Status::fail("container-bad-magic: vendor boot header_version " +
                                std::to_string(*hv) + " / page_size " + std::to_string(*page) +
                                " is not supported");
        version_ = *hv;
        page_ = *page;
        header_pages_ = pages_for(*hs, *page);
        if (const auto n = span.cstring(2080, 16)) name_ = sanitize_utf8(*n);
        sections_.push_back({"vendor_ramdisk", *ramdisk});
        sections_.push_back({"dtb", *dtb});
        if (*hv >= 4) {
            const auto table = u32(2112), bootconfig = u32(2124);
            if (table) sections_.push_back({"vendor_ramdisk_table", *table});
            if (bootconfig) sections_.push_back({"bootconfig", *bootconfig});
        }
    } else {
        const auto hv = u32(40);
        if (!hv) return Status::fail("container-empty: fewer than 44 boot header bytes");
        if (*hv > 4)
            return Status::fail("container-bad-magic: boot header_version " + std::to_string(*hv) +
                                " is not 0..4");
        version_ = *hv;
        if (*hv >= 3) {
            const auto kernel = u32(8), ramdisk = u32(12);
            if (!kernel || !ramdisk)
                return Status::fail("container-empty: fewer than 16 boot header bytes");
            page_ = kV3Page;
            header_pages_ = 1;
            sections_.push_back({"kernel", *kernel});
            sections_.push_back({"ramdisk", *ramdisk});
            if (*hv >= 4) {
                if (const auto sig = u32(1580); sig && *sig != 0)
                    sections_.push_back({"boot_signature", *sig});
            }
        } else {
            const auto kernel = u32(8), ramdisk = u32(16), second = u32(24), page = u32(36);
            if (!kernel || !ramdisk || !second || !page)
                return Status::fail("container-empty: fewer than 40 boot header bytes");
            if (!is_pow2(*page))
                return Status::fail("container-bad-magic: page_size " + std::to_string(*page) +
                                    " is not a power of two");
            page_ = *page;
            header_pages_ = 1;  // always one page for a boot image, whatever header_size says
            if (const auto n = span.cstring(48, 16)) name_ = sanitize_utf8(*n);
            sections_.push_back({"kernel", *kernel});
            sections_.push_back({"ramdisk", *ramdisk});
            sections_.push_back({"second", *second});
            if (*hv >= 1) {
                if (const auto dtbo = u32(1632)) sections_.push_back({"recovery_dtbo", *dtbo});
            }
            if (*hv >= 2) {
                if (const auto dtb = u32(1648)) sections_.push_back({"dtb", *dtb});
            }
        }
    }

    total_ = header_pages_ * page_;
    for (const Section& s : sections_) total_ += pages_for(s.size, page_) * page_;
    span_ = span;
    opened_ = true;
    return Status::success();
}

ContainerInfo AndroidBootReader::info() const {
    ContainerInfo i;
    i.format = format();
    i.size = total_;
    i.attrs["header_version"] = std::to_string(version_);
    i.attrs["page_size"] = std::to_string(page_);
    if (!name_.empty()) i.attrs["board_name"] = name_;
    for (const Section& s : sections_)
        i.attrs[std::string(s.name) + "_size"] = std::to_string(s.size);
    return i;
}

Status AndroidBootReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    if (!opened_) return Status::fail("container-not-open: walk before a successful open");

    std::uint64_t pos = header_pages_ * page_;
    for (const Section& s : sections_) {
        if (s.size == 0) continue;  // an absent section has no entry
        if (pos >= span_.size()) {
            out.diagnostics.push_back({Severity::Warning, kCodeShortSection,
                                       std::string(s.name) +
                                           " starts past the end of the image; not emitted"});
            out.truncated = true;
            break;
        }
        const std::uint64_t len = std::min<std::uint64_t>(s.size, span_.size() - pos);

        FileMeta meta;
        meta.path = s.name;
        meta.kind = EntryKind::Regular;
        meta.mode = 0644;
        meta.size = len;
        EntryResult r;
        bool short_read = false;
        const Status st = emit_span_file(sink, opts, meta, span_, pos, len, r, short_read);
        if (!st) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeSinkError, "'" + std::string(s.name) + "': " + st.error});
        } else {
            if (short_read || len < s.size) {
                out.diagnostics.push_back({Severity::Warning, kCodeShortSection,
                                           "'" + std::string(s.name) + "' claims " +
                                               std::to_string(s.size) + " bytes but only " +
                                               std::to_string(len) + " are present"});
                r.truncated = true;
                out.truncated = true;
            }
            count_entry(out, r);
            out.entries_out.push_back(std::move(r));
        }
        pos += pages_for(s.size, page_) * page_;
    }
    return Status::success();
}

namespace {
// One reader per format id; the layouts diverge enough to be told apart at
// construction rather than re-sniffed on every call.
class BootReader final : public AndroidBootReader {
   public:
    BootReader() : AndroidBootReader(false) {}
};
class VendorBootReader final : public AndroidBootReader {
   public:
    VendorBootReader() : AndroidBootReader(true) {}
};
}  // namespace

OMNITRACE_REGISTER_CONTAINER("android-boot", BootReader);
OMNITRACE_REGISTER_CONTAINER("android-vendor-boot", VendorBootReader);

namespace detail {
void omnitrace_container_anchor_androidboot() {}
}  // namespace detail

}  // namespace omnitrace::container
