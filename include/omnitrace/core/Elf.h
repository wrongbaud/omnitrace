// Elf.h — just enough ELF to find a named section.
/// @file Elf.h
/// @brief `omnitrace::elf`: the ELF header, its section table, and the machine
/// names, for the layers that need to look *inside* an ELF rather than
/// identify one.
///
/// This is not an ELF reader. It answers one question -- "what are the bytes
/// of the section called X?" -- because two layers now need it and a parser
/// two layers need lives in `core` (docs/ARCHITECTURE.md). The
/// `artifacts` layer reads `.modinfo` out of a kernel module with it; the
/// `elf` validator scores a file without it, since sizing an ELF is a
/// different question from reading one.
///
/// Every accessor is bounds-checked against the span it was given. A truncated
/// or hostile ELF yields `nullopt` or an empty section, never a read past the
/// end: these files come out of evidence.
#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace omnitrace::elf {

/// The fields of an ELF header that locate the section table, for either
/// class (32/64) and either byte order.
struct Header {
    bool is64 = false;
    bool big_endian = false;
    std::uint16_t type = 0;     ///< ET_REL (1) for a kernel module.
    std::uint16_t machine = 0;  ///< `e_machine`; see `machine_name`.
    std::uint64_t shoff = 0;    ///< Section table offset; 0 when there is none.
    std::uint16_t shentsize = 0;
    std::uint16_t shnum = 0;
    std::uint16_t shstrndx = 0;  ///< Index of the section-name string table.
};

/// Parse the ELF header at the start of `data`. `nullopt` when the magic,
/// class or byte order is not one, or the header does not fit.
std::optional<Header> parse_header(std::span<const std::uint8_t> data);

/// The bytes of the section named `name`, or an empty span when there is no
/// such section, the section table does not fit, or the section's own extent
/// runs past the end of `data`.
///
/// A `SHT_NOBITS` section occupies no file bytes and comes back empty, which
/// is the honest answer rather than whatever happens to follow it.
std::span<const std::uint8_t> section(std::span<const std::uint8_t> data, const Header& h,
                                      std::string_view name);

/// Short lowercase name for `e_machine` ("arm", "mips", "x86-64"); "unknown"
/// for a value this build does not name.
const char* machine_name(std::uint16_t m);

}  // namespace omnitrace::elf
