// Elf.cpp — the ELF header and its section table. See the header.
//
// Offsets, for both classes. Everything before e_entry is class-independent:
//   0  e_ident[16]   (7f 'E' 'L' 'F', class, data, version, ...)
//  16  e_type   u16
//  18  e_machine u16
//  20  e_version u32
// Then the address-sized fields diverge:
//            ELF32                 ELF64
//  e_entry   24 (4)                24 (8)
//  e_phoff   28 (4)                32 (8)
//  e_shoff   32 (4)                40 (8)
//  e_flags   36 (4)                48 (4)
//  e_ehsize  40 (2)                52 (2)
//  ...
//  e_shentsize 46 (2)              58 (2)
//  e_shnum     48 (2)              60 (2)
//  e_shstrndx  50 (2)              62 (2)
//
// A section header entry:
//            ELF32                 ELF64
//  sh_name   0  (4)                0  (4)
//  sh_type   4  (4)                4  (4)
//  sh_offset 16 (4)                24 (8)
//  sh_size   20 (4)                32 (8)
#include "omnitrace/core/Elf.h"

#include <cstring>

namespace omnitrace::elf {

namespace {

constexpr std::uint32_t kShtNobits = 8;

std::uint16_t rd16(const std::uint8_t* p, bool be) {
    return be ? static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1])
              : static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[1]) << 8) | p[0]);
}
std::uint32_t rd32(const std::uint8_t* p, bool be) {
    return be ? (static_cast<std::uint32_t>(p[0]) << 24) |
                    (static_cast<std::uint32_t>(p[1]) << 16) |
                    (static_cast<std::uint32_t>(p[2]) << 8) | p[3]
              : (static_cast<std::uint32_t>(p[3]) << 24) |
                    (static_cast<std::uint32_t>(p[2]) << 16) |
                    (static_cast<std::uint32_t>(p[1]) << 8) | p[0];
}
std::uint64_t rd64(const std::uint8_t* p, bool be) {
    const std::uint64_t hi = rd32(p + (be ? 0 : 4), be);
    const std::uint64_t lo = rd32(p + (be ? 4 : 0), be);
    return (hi << 32) | lo;
}

// Does [off, off+len) fit inside `size`? Written with subtraction so the sum
// cannot overflow on a hostile sh_offset.
bool fits(std::uint64_t off, std::uint64_t len, std::size_t size) {
    return off <= size && len <= static_cast<std::uint64_t>(size) - off;
}

}  // namespace

std::optional<Header> parse_header(std::span<const std::uint8_t> data) {
    if (data.size() < 24) return std::nullopt;
    if (data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') return std::nullopt;
    Header h;
    if (data[4] == 2)
        h.is64 = true;
    else if (data[4] != 1)
        return std::nullopt;  // an invalid class is not an ELF this can read
    if (data[5] == 2)
        h.big_endian = true;
    else if (data[5] != 1)
        return std::nullopt;

    const std::size_t need = h.is64 ? 64u : 52u;
    if (data.size() < need) return std::nullopt;
    const std::uint8_t* p = data.data();
    h.type = rd16(p + 16, h.big_endian);
    h.machine = rd16(p + 18, h.big_endian);
    if (h.is64) {
        h.shoff = rd64(p + 40, h.big_endian);
        h.shentsize = rd16(p + 58, h.big_endian);
        h.shnum = rd16(p + 60, h.big_endian);
        h.shstrndx = rd16(p + 62, h.big_endian);
    } else {
        h.shoff = rd32(p + 32, h.big_endian);
        h.shentsize = rd16(p + 46, h.big_endian);
        h.shnum = rd16(p + 48, h.big_endian);
        h.shstrndx = rd16(p + 50, h.big_endian);
    }
    return h;
}

std::span<const std::uint8_t> section(std::span<const std::uint8_t> data, const Header& h,
                                      std::string_view name) {
    const std::span<const std::uint8_t> none;
    const std::size_t entry = h.is64 ? 64u : 40u;
    if (h.shoff == 0 || h.shnum == 0 || h.shentsize < entry) return none;
    if (h.shstrndx >= h.shnum) return none;
    if (!fits(h.shoff, static_cast<std::uint64_t>(h.shnum) * h.shentsize, data.size())) return none;

    // Locate the section-name string table first: every name is an offset into
    // it, so without it no section can be identified by name.
    const auto extent = [&](std::uint16_t i, std::uint64_t& off, std::uint64_t& len,
                            std::uint32_t& type, std::uint32_t& name_off) {
        const std::uint8_t* e = data.data() + h.shoff + static_cast<std::uint64_t>(i) * h.shentsize;
        name_off = rd32(e, h.big_endian);
        type = rd32(e + 4, h.big_endian);
        if (h.is64) {
            off = rd64(e + 24, h.big_endian);
            len = rd64(e + 32, h.big_endian);
        } else {
            off = rd32(e + 16, h.big_endian);
            len = rd32(e + 20, h.big_endian);
        }
    };

    std::uint64_t str_off = 0, str_len = 0;
    std::uint32_t str_type = 0, ignored = 0;
    extent(h.shstrndx, str_off, str_len, str_type, ignored);
    if (str_type == kShtNobits || !fits(str_off, str_len, data.size())) return none;

    for (std::uint16_t i = 0; i < h.shnum; ++i) {
        std::uint64_t off = 0, len = 0;
        std::uint32_t type = 0, name_off = 0;
        extent(i, off, len, type, name_off);
        if (name_off >= str_len) continue;
        // The name is NUL terminated inside the string table; a table that
        // does not terminate it is not a name this will match.
        const char* first = reinterpret_cast<const char*>(data.data() + str_off + name_off);
        const std::size_t room = static_cast<std::size_t>(str_len - name_off);
        const std::string_view got(first, ::strnlen(first, room));
        if (got != name) continue;
        if (type == kShtNobits) return none;  // occupies no file bytes
        if (!fits(off, len, data.size())) return none;
        return data.subspan(static_cast<std::size_t>(off), static_cast<std::size_t>(len));
    }
    return none;
}

const char* machine_name(std::uint16_t m) {
    switch (m) {
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
        case 50:
            return "ia64";
        case 62:
            return "x86-64";
        case 83:
            return "avr";
        case 94:
            return "xtensa";
        case 106:
            return "blackfin";
        case 183:
            return "aarch64";
        case 189:
            return "microblaze";
        case 243:
            return "riscv";
        case 258:
            return "loongarch";
        default:
            return "unknown";
    }
}

}  // namespace omnitrace::elf
