// elf.cpp — ELF header validator and extent estimator.
//
// e_ident: 0 "\x7fELF", 4 EI_CLASS (1 = 32-bit, 2 = 64-bit), 5 EI_DATA
// (1 = LSB, 2 = MSB), 6 EI_VERSION (1), 7 EI_OSABI, 8 EI_ABIVERSION.
// Then e_type u16, e_machine u16, e_version u32 (1), e_entry, e_phoff,
// e_shoff (32 or 64 bits), e_flags u32, e_ehsize u16 (52 / 64),
// e_phentsize u16 (32 / 56), e_phnum u16, e_shentsize u16 (40 / 64),
// e_shnum u16, e_shstrndx u16. The file extent is the furthest byte any
// program header (p_offset + p_filesz), section header (sh_offset + sh_size,
// SHT_NOBITS excluded) or header table reaches.
// Reference: System V ABI, ELF chapter (refspecs.linuxfoundation.org/elf/)
#include <array>

#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint32_t kShtNobits = 8;
constexpr std::uint16_t kPnXnum = 0xFFFF;
constexpr std::uint16_t kShnXindex = 0xFFFF;

std::string machine_name(std::uint16_t m) {
    switch (m) {
        case 0:
            return "none";
        case 2:
            return "sparc";
        case 3:
            return "x86";
        case 4:
            return "m68k";
        case 8:
            return "mips";
        case 15:
            return "parisc";
        case 18:
            return "sparc32plus";
        case 20:
            return "powerpc";
        case 21:
            return "powerpc64";
        case 22:
            return "s390";
        case 40:
            return "arm";
        case 42:
            return "superh";
        case 43:
            return "sparcv9";
        case 44:
            return "tricore";
        case 50:
            return "ia64";
        case 62:
            return "x86-64";
        case 83:
            return "avr";
        case 92:
            return "openrisc";
        case 93:
            return "arc-a5";
        case 94:
            return "xtensa";
        case 105:
            return "msp430";
        case 106:
            return "blackfin";
        case 113:
            return "nios2";
        case 138:
            return "lm32";
        case 140:
            return "c6000";
        case 164:
            return "hexagon";
        case 183:
            return "aarch64";
        case 189:
            return "microblaze";
        case 195:
            return "arc";
        case 243:
            return "riscv";
        case 247:
            return "bpf";
        case 258:
            return "loongarch";
        default:
            return "unknown(" + dec(m) + ")";
    }
}

std::string type_name(std::uint16_t t) {
    switch (t) {
        case 0:
            return "none";
        case 1:
            return "relocatable";
        case 2:
            return "executable";
        case 3:
            return "shared-object";
        case 4:
            return "core";
        default:
            if (t >= 0xFE00 && t <= 0xFEFF) return "os-specific(" + hex_fixed(t, 4) + ")";
            if (t >= 0xFF00) return "processor-specific(" + hex_fixed(t, 4) + ")";
            return "unknown(" + dec(t) + ")";
    }
}

std::string osabi_name(std::uint8_t v) {
    switch (v) {
        case 0:
            return "sysv";
        case 1:
            return "hpux";
        case 2:
            return "netbsd";
        case 3:
            return "linux";
        case 6:
            return "solaris";
        case 7:
            return "aix";
        case 8:
            return "irix";
        case 9:
            return "freebsd";
        case 12:
            return "openbsd";
        case 64:
            return "arm-aeabi";
        case 97:
            return "arm";
        case 255:
            return "standalone";
        default:
            return "unknown(" + dec(v) + ")";
    }
}

std::optional<Finding> validate_elf(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    std::array<std::uint8_t, 64> raw{};
    const std::size_t got = span.read(start, std::span<std::uint8_t>(raw.data(), raw.size()));
    if (got < 52) return std::nullopt;
    const std::uint8_t cls = raw[4], data = raw[5], ei_version = raw[6], osabi = raw[7];
    if ((cls != 1 && cls != 2) || (data != 1 && data != 2) || ei_version != 1) return std::nullopt;
    const bool is64 = cls == 2;
    if (is64 && got < 64) return std::nullopt;
    const Endian e = data == 1 ? Endian::Little : Endian::Big;
    auto u16 = [&](std::size_t o) { return load_int<std::uint16_t>(raw.data() + o, e); };
    auto u32 = [&](std::size_t o) { return load_int<std::uint32_t>(raw.data() + o, e); };
    auto word = [&](std::size_t o) -> std::uint64_t {
        return is64 ? load_int<std::uint64_t>(raw.data() + o, e) : u32(o);
    };
    const std::uint16_t type = u16(16), machine = u16(18);
    const std::uint32_t version = u32(20);
    const std::uint64_t entry = word(24);
    const std::uint64_t phoff = is64 ? word(32) : word(28);
    const std::uint64_t shoff = is64 ? word(40) : word(32);
    const std::size_t tail = is64 ? 48 : 36;  // e_flags
    const std::uint32_t flags = u32(tail);
    const std::uint16_t ehsize = u16(tail + 4), phentsize = u16(tail + 6), phnum = u16(tail + 8),
                        shentsize = u16(tail + 10), shnum = u16(tail + 12),
                        shstrndx = u16(tail + 14);
    const std::uint16_t want_eh = is64 ? 64 : 52, want_ph = is64 ? 56 : 32,
                        want_sh = is64 ? 64 : 40;
    const bool type_ok = type <= 4 || type >= 0xFE00;

    // Hard constraints: any failure means the magic sits in other data.
    if (version != 1 || ehsize != want_eh || !type_ok) return std::nullopt;
    if (phnum != 0 && (phentsize != want_ph || phoff < ehsize)) return std::nullopt;
    if (shnum != 0 && (shentsize != want_sh || shoff < ehsize)) return std::nullopt;
    if (shnum != 0 && shstrndx >= shnum && shstrndx != kShnXindex) return std::nullopt;
    if (phnum == 0 && phoff != 0 && phentsize != want_ph) return std::nullopt;

    Finding f = make_finding(sig, start, Confidence::Structural);
    f.endian = e;
    f.attrs["class"] = is64 ? "64" : "32";
    f.attrs["endian"] = endian_name(e);
    f.attrs["type"] = type_name(type);
    f.attrs["machine"] = machine_name(machine);
    f.attrs["machine_id"] = dec(machine);
    f.attrs["osabi"] = osabi_name(osabi);
    f.attrs["entry"] = hex_fixed(entry, is64 ? 16 : 8);
    f.attrs["flags"] = hex_fixed(flags, 8);
    f.attrs["program_headers"] = dec(phnum);
    f.attrs["section_headers"] = dec(shnum);
    if (phnum == kPnXnum || (shnum == 0 && shoff != 0))
        diag(f, Severity::Info, "elf-extended-numbering",
             "header counts use the extended (section 0) numbering; tables not walked");

    // Class-sized field at (off32 | off64) from a table entry at `base`.
    auto field = [&](std::uint64_t base, std::uint64_t off32,
                     std::uint64_t off64) -> std::optional<std::uint64_t> {
        if (is64) return span.at<std::uint64_t>(base + off64, e);
        const auto v = span.at<std::uint32_t>(base + off32, e);
        if (!v) return std::nullopt;
        return std::uint64_t{*v};
    };
    const std::uint64_t avail = remaining(span, start);
    std::uint64_t extent = ehsize;
    bool consistent = true;
    auto extend = [&](std::uint64_t off, std::uint64_t len) {
        if (off > avail || len > avail - off) {
            consistent = false;
            extent = avail;  // clamp: the file claims bytes past the Span
            return;
        }
        if (consistent && off + len > extent) extent = off + len;
    };
    if (phnum != 0 && phnum != kPnXnum) {
        extend(phoff, static_cast<std::uint64_t>(phnum) * phentsize);
        for (std::uint32_t i = 0; i < phnum && consistent; ++i) {
            const std::uint64_t ph = start + phoff + static_cast<std::uint64_t>(i) * phentsize;
            const auto p_offset = field(ph, 4, 8);
            const auto p_filesz = field(ph, 16, 32);
            if (!p_offset || !p_filesz) {
                consistent = false;
                break;
            }
            extend(*p_offset, *p_filesz);
        }
    }
    if (shnum != 0 && consistent) {
        extend(shoff, static_cast<std::uint64_t>(shnum) * shentsize);
        for (std::uint32_t i = 0; i < shnum && consistent; ++i) {
            const std::uint64_t sh = start + shoff + static_cast<std::uint64_t>(i) * shentsize;
            const auto sh_type = span.at<std::uint32_t>(sh + 4, e);
            const auto sh_offset = field(sh, 16, 24);
            const auto sh_size = field(sh, 20, 32);
            if (!sh_type || !sh_offset || !sh_size) {
                consistent = false;
                break;
            }
            if (*sh_type == kShtNobits) continue;
            extend(*sh_offset, *sh_size);
        }
    }
    const bool has_tables = (phnum != 0 && phnum != kPnXnum) || shnum != 0;
    if (!consistent) {
        // A header whose tables or segments reach past the data: at an
        // unaligned offset that is the signature of stray bytes, not a file.
        if (start % 4 != 0) return std::nullopt;
        diag(f, Severity::Warning, "elf-truncated",
             "program/section headers or segments extend past the available data");
        f.size = 0;
        f.evidence = "ELF" + f.attrs["class"] + " " + f.attrs["machine"] + " " + f.attrs["type"] +
                     " (tables not inside the data)";
        return f;
    }
    if (!has_tables) {
        if (start % 4 != 0) return std::nullopt;
        f.size = ehsize;
        diag(f, Severity::Info, "elf-no-tables", "no program or section headers; size unknown");
        f.evidence = "ELF" + f.attrs["class"] + " " + f.attrs["machine"] + " " + f.attrs["type"] +
                     ", no header tables";
        return f;
    }
    f.confidence = Confidence::Consistent;
    f.size = extent;
    f.evidence = "ELF" + f.attrs["class"] + " " + f.attrs["endian"] + "-endian " +
                 f.attrs["machine"] + " " + f.attrs["type"] + ", " + dec(phnum) + " segments, " +
                 dec(shnum) + " sections, " + dec(extent) + " bytes";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("elf", validate_elf);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(elf)
