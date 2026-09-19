// android_boot.cpp — Android boot image (boot.img) and vendor boot validator.
//
// Header versions 0-2 ("ANDROID!", little-endian):
//    8 kernel_size  12 kernel_addr  16 ramdisk_size  20 ramdisk_addr  24 second_size
//   28 second_addr  32 tags_addr    36 page_size     40 header_version 44 os_version
//   48 name[16]     64 cmdline[512] 576 id[32]       608 extra_cmdline[1024]
//   v1: 1632 recovery_dtbo_size u32, 1636 recovery_dtbo_offset u64, 1644 header_size u32
//   v2: 1648 dtb_size u32, 1652 dtb_addr u64
// Sections follow the header, each padded to page_size: kernel, ramdisk,
// second, recovery_dtbo (v1+), dtb (v2+).
// Versions 3-4 (fixed 4096-byte page):
//    8 kernel_size 12 ramdisk_size 16 os_version 20 header_size 24 reserved[16]
//   40 header_version 44 cmdline[1536]; v4: 1580 signature_size
// Vendor boot ("VNDRBOOT", v3/v4): 8 header_version 12 page_size 16 kernel_addr
//   20 ramdisk_addr 24 vendor_ramdisk_size 28 cmdline[2048] 2076 tags_addr
//   2080 name[16] 2096 header_size 2100 dtb_size 2104 dtb_addr u64;
//   v4: 2112 vendor_ramdisk_table_size 2116 entry_num 2120 entry_size 2124 bootconfig_size
// Reference: AOSP system/tools/mkbootimg/include/bootimg/bootimg.h
#include <array>

#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint64_t kV3Page = 4096;
constexpr std::array<std::uint8_t, 8> kVendorMagic{'V', 'N', 'D', 'R', 'B', 'O', 'O', 'T'};

std::uint64_t page_align(std::uint64_t v, std::uint64_t page) {
    return (v + page - 1) / page * page;
}

// Printable ASCII only; control bytes become '_', trailing space trimmed.
std::string clean(const std::string& s) {
    std::string out;
    for (const char c : s) {
        const auto u = static_cast<unsigned char>(c);
        out.push_back(u < 0x20 || u >= 0x7F ? '_' : c);
    }
    while (!out.empty() && out.back() == ' ') out.pop_back();
    return out;
}

// os_version: bits 31..11 = A.B.C (7 bits each), bits 10..0 = patch level
// (year - 2000 in 7 bits, month in 4 bits).
void os_version_attrs(Finding& f, std::uint32_t v) {
    if (v == 0) return;
    const std::uint32_t a = (v >> 25) & 0x7F, b = (v >> 18) & 0x7F, c = (v >> 11) & 0x7F;
    const std::uint32_t year = ((v >> 4) & 0x7F) + 2000, month = v & 0xF;
    f.attrs["os_version"] = dec(a) + "." + dec(b) + "." + dec(c);
    f.attrs["os_patch_level"] = dec(year) + "-" + (month < 10 ? "0" : "") + dec(month);
}

std::optional<Finding> vendor_boot(const Span& span, std::uint64_t start, Finding f) {
    auto u32 = [&](std::uint64_t o) { return span.at<std::uint32_t>(start + o, Endian::Little); };
    const auto hv = u32(8);
    const auto page = u32(12);
    const auto ramdisk = u32(24);
    const auto header_size = u32(2096);
    const auto dtb = u32(2100);
    if (!hv || !page || !ramdisk || !header_size || !dtb) {
        diag(f, Severity::Warning, "android-boot-truncated-header",
             "fewer than 2112 bytes available for the vendor boot header");
        return f;
    }
    if (*hv < 3 || *hv > 4 || !is_pow2(*page) || *page < 2048 || *page > 65536) {
        diag(f, Severity::Warning, "android-boot-bad-header",
             "vendor boot header_version " + dec(*hv) + " / page_size " + dec(*page) +
                 " out of range");
        return f;
    }
    f.confidence = Confidence::Structural;
    f.attrs["header_version"] = dec(*hv);
    f.attrs["page_size"] = dec(*page);
    f.attrs["vendor_ramdisk_size"] = dec(*ramdisk);
    f.attrs["dtb_size"] = dec(*dtb);
    f.attrs["header_size"] = dec(*header_size);
    if (const auto name = span.cstring(start + 2080, 16)) f.attrs["name"] = clean(*name);
    if (const auto cmd = span.cstring(start + 28, 2048)) f.attrs["cmdline"] = clean(*cmd);
    std::uint64_t total =
        page_align(*header_size, *page) + page_align(*ramdisk, *page) + page_align(*dtb, *page);
    if (*hv == 4) {
        const auto table = u32(2112);
        const auto bootconfig = u32(2124);
        if (table && bootconfig) {
            f.attrs["vendor_ramdisk_table_size"] = dec(*table);
            f.attrs["bootconfig_size"] = dec(*bootconfig);
            total += page_align(*table, *page) + page_align(*bootconfig, *page);
        }
    }
    bool truncated = false;
    f.size = clamp_size(span, start, total, truncated);
    if (truncated)
        diag(f, Severity::Warning, "android-boot-truncated",
             "declared sections (" + dec(total) + " bytes) extend past the available data");
    else
        f.confidence = Confidence::Consistent;
    f.evidence = "vendor boot v" + dec(*hv) + ", ramdisk " + dec(*ramdisk) + " bytes, dtb " +
                 dec(*dtb) + " bytes";
    return f;
}

std::optional<Finding> validate_android_boot(const Span& span, std::uint64_t start,
                                             const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);
    f.endian = Endian::Little;
    if (span.matches_at(start,
                        std::span<const std::uint8_t>(kVendorMagic.data(), kVendorMagic.size())))
        return vendor_boot(span, start, std::move(f));
    auto u32 = [&](std::uint64_t o) { return span.at<std::uint32_t>(start + o, Endian::Little); };
    const auto hv = u32(40);
    if (!hv) {
        diag(f, Severity::Warning, "android-boot-truncated-header",
             "fewer than 44 bytes available for the boot header");
        return f;
    }
    if (*hv > 4) {
        // "ANDROID!" also appears as a string literal in bootloaders.
        diag(f, Severity::Warning, "android-boot-bad-header",
             "header_version " + dec(*hv) + " is not 0..4");
        return f;
    }
    f.attrs["header_version"] = dec(*hv);
    std::uint64_t total = 0;
    std::uint32_t kernel = 0, ramdisk = 0;
    if (*hv >= 3) {
        const auto ks = u32(8), rs = u32(12), osv = u32(16), hs = u32(20);
        const auto cmd = span.cstring(start + 44, 1536);
        if (!ks || !rs || !osv || !hs || !cmd) {
            diag(f, Severity::Warning, "android-boot-truncated-header",
                 "fewer than 1580 bytes available for the v3/v4 header");
            return f;
        }
        kernel = *ks;
        ramdisk = *rs;
        f.attrs["page_size"] = dec(kV3Page);
        f.attrs["header_size"] = dec(*hs);
        f.attrs["cmdline"] = clean(*cmd);
        os_version_attrs(f, *osv);
        total = kV3Page + page_align(kernel, kV3Page) + page_align(ramdisk, kV3Page);
        if (*hv == 4) {
            if (const auto sg = u32(1580)) {
                f.attrs["signature_size"] = dec(*sg);
                total += page_align(*sg, kV3Page);
            }
        }
    } else {
        const auto ks = u32(8), ka = u32(12), rs = u32(16), ra = u32(20), ss = u32(24),
                   sa = u32(28), ta = u32(32), page = u32(36), osv = u32(44);
        const auto name = span.cstring(start + 48, 16);
        const auto cmd = span.cstring(start + 64, 512);
        const auto id = span.bytes(start + 576, 32);
        const auto extra = span.cstring(start + 608, 1024);
        if (!ks || !ka || !rs || !ra || !ss || !sa || !ta || !page || !osv || !name || !cmd ||
            !id || !extra) {
            diag(f, Severity::Warning, "android-boot-truncated-header",
                 "fewer than 1632 bytes available for the v0-v2 header");
            return f;
        }
        if (!is_pow2(*page) || *page < 2048 || *page > 65536) {
            diag(f, Severity::Warning, "android-boot-bad-header",
                 "page_size " + dec(*page) + " is not a power of two in 2048..65536");
            return f;
        }
        kernel = *ks;
        ramdisk = *rs;
        f.attrs["page_size"] = dec(*page);
        f.attrs["second_size"] = dec(*ss);
        f.attrs["kernel_addr"] = hex_fixed(*ka, 8);
        f.attrs["ramdisk_addr"] = hex_fixed(*ra, 8);
        f.attrs["second_addr"] = hex_fixed(*sa, 8);
        f.attrs["tags_addr"] = hex_fixed(*ta, 8);
        if (!name->empty()) f.attrs["name"] = clean(*name);
        f.attrs["cmdline"] = clean(*cmd + (extra->empty() ? std::string{} : *extra));
        f.attrs["id"] = hex_bytes(std::span<const std::uint8_t>(id->data(), id->size()));
        os_version_attrs(f, *osv);
        total =
            *page + page_align(kernel, *page) + page_align(ramdisk, *page) + page_align(*ss, *page);
        if (*hv >= 1) {
            const auto rd = u32(1632);
            const auto hs = u32(1644);
            if (rd && hs) {
                f.attrs["recovery_dtbo_size"] = dec(*rd);
                f.attrs["header_size"] = dec(*hs);
                total += page_align(*rd, *page);
            }
        }
        if (*hv >= 2) {
            if (const auto dtb = u32(1648)) {
                f.attrs["dtb_size"] = dec(*dtb);
                total += page_align(*dtb, *page);
            }
        }
    }
    f.attrs["kernel_size"] = dec(kernel);
    f.attrs["ramdisk_size"] = dec(ramdisk);
    if (kernel == 0 && ramdisk == 0) {
        diag(f, Severity::Warning, "android-boot-empty",
             "kernel_size and ramdisk_size are both zero");
        return f;
    }
    f.confidence = Confidence::Structural;
    bool truncated = false;
    f.size = clamp_size(span, start, total, truncated);
    if (truncated)
        diag(f, Severity::Warning, "android-boot-truncated",
             "declared sections (" + dec(total) + " bytes) extend past the available data");
    else
        f.confidence = Confidence::Consistent;
    f.evidence = "boot image v" + dec(*hv) + ", kernel " + dec(kernel) + " bytes, ramdisk " +
                 dec(ramdisk) + " bytes, page " + f.attrs["page_size"];
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("android-boot", validate_android_boot);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(android_boot)
