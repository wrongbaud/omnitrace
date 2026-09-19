// uimage.cpp — U-Boot legacy image header validator.
//
// 64-byte big-endian header: 0 magic 0x27051956, 4 ih_hcrc (crc32 of the
// header with this field zeroed), 8 ih_time, 12 ih_size (payload bytes),
// 16 ih_load, 20 ih_ep, 24 ih_dcrc (crc32 of the payload), 28 ih_os,
// 29 ih_arch, 30 ih_type, 31 ih_comp, 32 ih_name[32].
// Reference: U-Boot include/image.h
#include <array>

#include "../crc32.h"
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

std::string os_name(std::uint8_t v) {
    static const char* names[] = {"invalid",  "openbsd",
                                  "netbsd",   "freebsd",
                                  "4_4bsd",   "linux",
                                  "svr4",     "esix",
                                  "solaris",  "irix",
                                  "sco",      "dell",
                                  "ncr",      "lynxos",
                                  "vxworks",  "psos",
                                  "qnx",      "u-boot",
                                  "rtems",    "artos",
                                  "unity",    "integrity",
                                  "ose",      "plan9",
                                  "openrtos", "arm-trusted-firmware",
                                  "tee",      "opensbi",
                                  "efi"};
    return v < sizeof(names) / sizeof(names[0]) ? names[v] : "unknown(" + dec(v) + ")";
}

std::string arch_name(std::uint8_t v) {
    static const char* names[] = {
        "invalid",    "alpha", "arm",      "x86",    "ia64",    "mips",    "mips64",
        "powerpc",    "s390",  "sh",       "sparc",  "sparc64", "m68k",    "nios",
        "microblaze", "nios2", "blackfin", "avr32",  "st200",   "sandbox", "nds32",
        "openrisc",   "arm64", "arc",      "x86_64", "xtensa",  "riscv"};
    return v < sizeof(names) / sizeof(names[0]) ? names[v] : "unknown(" + dec(v) + ")";
}

std::string type_name(std::uint8_t v) {
    static const char* names[] = {
        "invalid",         "standalone",   "kernel",       "ramdisk",      "multi",
        "firmware",        "script",       "filesystem",   "flatdt",       "kwbimage",
        "imximage",        "ublimage",     "omapimage",    "aisimage",     "kernel_noload",
        "pblimage",        "mxsimage",     "gpimage",      "atmelimage",   "socfpgaimage",
        "x86_setup",       "lpc32xximage", "loadable",     "rkimage",      "rksd",
        "rkspi",           "zynqimage",    "zynqmpimage",  "zynqmpbif",    "fpga",
        "vybridimage",     "tee",          "firmware_ivt", "pmmc",         "stm32image",
        "socfpgaimage_v1", "mtkimage",     "imx8mimage",   "imx8image",    "copro",
        "sunxi_egon",      "sunxi_toc0",   "fdt_legacy",   "renesas_spkg", "starfive_spl",
        "tfa_bl31"};
    return v < sizeof(names) / sizeof(names[0]) ? names[v] : "unknown(" + dec(v) + ")";
}

std::string comp_name(std::uint8_t v) {
    static const char* names[] = {"none", "gzip", "bzip2", "lzma", "lzo", "lz4", "zstd"};
    return v < sizeof(names) / sizeof(names[0]) ? names[v] : "unknown(" + dec(v) + ")";
}

std::optional<Finding> validate_uimage(const Span& span, std::uint64_t start,
                                       const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    std::array<std::uint8_t, 64> raw{};
    Finding f = make_finding(sig, start, Confidence::Magic);
    f.endian = Endian::Big;
    if (span.read(start, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size()) {
        diag(f, Severity::Warning, "uimage-truncated-header",
             "fewer than 64 bytes available for the header");
        return f;
    }
    const std::uint32_t hcrc = load_int<std::uint32_t>(raw.data() + 4, Endian::Big);
    const std::uint32_t time = load_int<std::uint32_t>(raw.data() + 8, Endian::Big);
    const std::uint32_t size = load_int<std::uint32_t>(raw.data() + 12, Endian::Big);
    const std::uint32_t load = load_int<std::uint32_t>(raw.data() + 16, Endian::Big);
    const std::uint32_t ep = load_int<std::uint32_t>(raw.data() + 20, Endian::Big);
    const std::uint32_t dcrc = load_int<std::uint32_t>(raw.data() + 24, Endian::Big);
    const std::uint8_t os = raw[28], arch = raw[29], type = raw[30], comp = raw[31];
    std::array<std::uint8_t, 64> zeroed = raw;
    zeroed[4] = zeroed[5] = zeroed[6] = zeroed[7] = 0;
    const bool header_ok =
        crc32_zlib(std::span<const std::uint8_t>(zeroed.data(), zeroed.size())) == hcrc;
    if (!header_ok) {
        diag(f, Severity::Warning, "uimage-header-crc-mismatch",
             "header CRC32 does not match; fields not trusted");
        return f;
    }
    f.confidence = Confidence::Verified;
    if (const auto name = span.cstring(start + 32, 32)) f.attrs["name"] = *name;
    f.attrs["os"] = os_name(os);
    f.attrs["arch"] = arch_name(arch);
    f.attrs["type"] = type_name(type);
    f.attrs["compression"] = comp_name(comp);
    f.attrs["data_size"] = dec(size);
    f.attrs["load_address"] = hex_fixed(load, 8);
    f.attrs["entry_point"] = hex_fixed(ep, 8);
    f.attrs["timestamp"] = dec(time);
    if (type == 2 || type == 14) f.category = "kernel";

    const std::uint64_t claimed = 64 + static_cast<std::uint64_t>(size);
    bool truncated = false;
    f.size = clamp_size(span, start, claimed, truncated);
    if (truncated) {
        diag(f, Severity::Warning, "uimage-truncated",
             "payload of " + dec(size) + " bytes extends past the available data");
        f.confidence = Confidence::Consistent;
        f.attrs["data_crc"] = "unchecked";
    } else if (const auto computed = crc32_span(span, start + 64, size, 0xFFFFFFFFu, 0xFFFFFFFFu)) {
        if (*computed == dcrc) {
            f.attrs["data_crc"] = "ok";
        } else {
            f.attrs["data_crc"] = "mismatch";
            f.confidence = Confidence::Consistent;
            diag(f, Severity::Warning, "uimage-data-crc-mismatch",
                 "payload CRC32 does not match ih_dcrc");
        }
    }
    f.evidence = "header CRC ok; " + type_name(type) + " for " + os_name(os) + "/" +
                 arch_name(arch) + ", " + comp_name(comp) + ", " + dec(size) + " bytes";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("uimage", validate_uimage);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(uimage)
