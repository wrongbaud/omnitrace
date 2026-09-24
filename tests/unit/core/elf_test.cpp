// elf_test.cpp — the ELF header and section lookup in `omnitrace::elf`.
//
// The fixtures are built byte by byte rather than compiled, so a test says
// exactly what was in the file. Both classes and both byte orders are covered
// because embedded evidence is routinely 32-bit big-endian MIPS, which is the
// combination a little-endian-only reader gets silently wrong.
//
// Hostile shapes get as much attention as valid ones: these bytes come out of
// evidence, and every field that locates something is a chance to read past
// the end of the buffer.
#include "omnitrace/core/Elf.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

using namespace omnitrace;

namespace {

using Bytes = std::vector<std::uint8_t>;

void put16(Bytes& b, std::size_t at, std::uint16_t v, bool be) {
    b[at] = static_cast<std::uint8_t>(be ? v >> 8 : v & 0xFF);
    b[at + 1] = static_cast<std::uint8_t>(be ? v & 0xFF : v >> 8);
}
void put32(Bytes& b, std::size_t at, std::uint32_t v, bool be) {
    for (int i = 0; i < 4; ++i)
        b[at + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>(be ? v >> (24 - 8 * i) : v >> (8 * i));
}
void put64(Bytes& b, std::size_t at, std::uint64_t v, bool be) {
    for (int i = 0; i < 8; ++i)
        b[at + static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>(be ? v >> (56 - 8 * i) : v >> (8 * i));
}

/// A minimal ELF with one named section: header, the section's bytes, a
/// section-name string table, then three section headers (the mandatory null
/// one, the named section, the string table).
Bytes elf_with_section(const std::string& name, const std::string& content, bool is64, bool be,
                       std::uint16_t machine = 8 /* mips */) {
    const std::size_t ehsize = is64 ? 64u : 52u;
    const std::size_t shent = is64 ? 64u : 40u;

    std::string shstr;
    shstr.push_back('\0');
    const std::uint32_t name_off = static_cast<std::uint32_t>(shstr.size());
    shstr += name;
    shstr.push_back('\0');
    const std::uint32_t shstr_name_off = static_cast<std::uint32_t>(shstr.size());
    shstr += ".shstrtab";
    shstr.push_back('\0');

    const std::size_t sec_off = ehsize;
    const std::size_t shstr_off = sec_off + content.size();
    const std::size_t sh_off = shstr_off + shstr.size();

    Bytes b(sh_off + 3 * shent, 0);
    b[0] = 0x7F;
    b[1] = 'E';
    b[2] = 'L';
    b[3] = 'F';
    b[4] = is64 ? 2 : 1;
    b[5] = be ? 2 : 1;
    b[6] = 1;
    put16(b, 16, 1, be);        // ET_REL, which is what a kernel module is
    put16(b, 18, machine, be);  // e_machine
    put32(b, 20, 1, be);        // e_version
    if (is64) {
        put64(b, 40, sh_off, be);
        put16(b, 58, static_cast<std::uint16_t>(shent), be);
        put16(b, 60, 3, be);
        put16(b, 62, 2, be);
    } else {
        put32(b, 32, static_cast<std::uint32_t>(sh_off), be);
        put16(b, 46, static_cast<std::uint16_t>(shent), be);
        put16(b, 48, 3, be);
        put16(b, 50, 2, be);
    }
    std::copy(content.begin(), content.end(), b.begin() + static_cast<std::ptrdiff_t>(sec_off));
    std::copy(shstr.begin(), shstr.end(), b.begin() + static_cast<std::ptrdiff_t>(shstr_off));

    const auto write_sh = [&](std::size_t idx, std::uint32_t nm, std::uint32_t type,
                              std::uint64_t off, std::uint64_t len) {
        const std::size_t at = sh_off + idx * shent;
        put32(b, at, nm, be);
        put32(b, at + 4, type, be);
        if (is64) {
            put64(b, at + 24, off, be);
            put64(b, at + 32, len, be);
        } else {
            put32(b, at + 16, static_cast<std::uint32_t>(off), be);
            put32(b, at + 20, static_cast<std::uint32_t>(len), be);
        }
    };
    write_sh(0, 0, 0, 0, 0);  // SHN_UNDEF
    write_sh(1, name_off, 1 /*SHT_PROGBITS*/, sec_off, content.size());
    write_sh(2, shstr_name_off, 3 /*SHT_STRTAB*/, shstr_off, shstr.size());
    return b;
}

std::string as_text(std::span<const std::uint8_t> s) {
    return std::string(reinterpret_cast<const char*>(s.data()), s.size());
}

}  // namespace

TEST(Elf, ReadsBothClassesAndBothByteOrders) {
    for (const bool is64 : {false, true}) {
        for (const bool be : {false, true}) {
            const Bytes b = elf_with_section(".modinfo", "license=GPL", is64, be);
            const auto h = elf::parse_header(b);
            ASSERT_TRUE(h.has_value()) << "is64=" << is64 << " be=" << be;
            EXPECT_EQ(h->is64, is64);
            EXPECT_EQ(h->big_endian, be);
            EXPECT_EQ(h->type, 1u) << "ET_REL";
            EXPECT_EQ(h->machine, 8u);
            EXPECT_EQ(h->shnum, 3u);
            EXPECT_EQ(as_text(elf::section(b, *h, ".modinfo")), "license=GPL");
        }
    }
}

TEST(Elf, RefusesWhatIsNotAnElfItCanRead) {
    const Bytes good = elf_with_section(".modinfo", "x=1", false, false);
    EXPECT_FALSE(elf::parse_header({}).has_value());
    EXPECT_FALSE(elf::parse_header(std::span(good).first(3)).has_value()) << "shorter than magic";
    EXPECT_FALSE(elf::parse_header(std::span(good).first(30)).has_value())
        << "magic but no room for the header";

    Bytes bad = good;
    bad[0] = 0x7E;
    EXPECT_FALSE(elf::parse_header(bad).has_value()) << "wrong magic";
    bad = good;
    bad[4] = 3;
    EXPECT_FALSE(elf::parse_header(bad).has_value()) << "class is neither 32 nor 64";
    bad = good;
    bad[5] = 0;
    EXPECT_FALSE(elf::parse_header(bad).has_value()) << "byte order is neither";
}

TEST(Elf, AMissingSectionIsEmptyNotSomeOtherSection) {
    const Bytes b = elf_with_section(".modinfo", "license=GPL", false, false);
    const auto h = elf::parse_header(b);
    ASSERT_TRUE(h.has_value());
    EXPECT_TRUE(elf::section(b, *h, ".text").empty());
    EXPECT_TRUE(elf::section(b, *h, "").empty()) << "the null name is not a section";
    EXPECT_TRUE(elf::section(b, *h, ".modinfo2").empty()) << "a prefix is not a match";
    EXPECT_TRUE(elf::section(b, *h, ".modinf").empty()) << "nor is a truncation";
}

// Every field that locates something is a chance to read past the end. The
// file is evidence, so each of these has to come back empty rather than
// crash -- which is what the ASan build is there to prove.
TEST(Elf, HostileOffsetsAndSizesReadNothing) {
    const Bytes good = elf_with_section(".modinfo", "license=GPL", false, false);
    const auto h0 = elf::parse_header(good);
    ASSERT_TRUE(h0.has_value());
    const std::size_t sh_off = static_cast<std::size_t>(h0->shoff);

    struct Case {
        const char* what;
        std::size_t at;
        std::uint32_t value;
    };
    // Section 1 is .modinfo: sh_offset at +16, sh_size at +20 in a 32-bit entry.
    for (const Case& c : {Case{"offset past the end", sh_off + 40 + 16, 0xFFFF0000u},
                          Case{"size past the end", sh_off + 40 + 20, 0xFFFF0000u},
                          Case{"size that wraps", sh_off + 40 + 20, 0xFFFFFFFFu},
                          Case{"name past the string table", sh_off + 40 + 0, 0xFFFFFFFFu}}) {
        Bytes b = good;
        put32(b, c.at, c.value, false);
        const auto h = elf::parse_header(b);
        ASSERT_TRUE(h.has_value()) << c.what;
        EXPECT_TRUE(elf::section(b, *h, ".modinfo").empty()) << c.what;
    }

    // A section table that does not fit, and one whose entries are too small
    // to hold the fields they must.
    Bytes b = good;
    put32(b, 32, 0xFFFF0000u, false);  // e_shoff
    auto h = elf::parse_header(b);
    ASSERT_TRUE(h.has_value());
    EXPECT_TRUE(elf::section(b, *h, ".modinfo").empty());

    b = good;
    put16(b, 46, 8, false);  // e_shentsize, smaller than a 32-bit entry
    h = elf::parse_header(b);
    ASSERT_TRUE(h.has_value());
    EXPECT_TRUE(elf::section(b, *h, ".modinfo").empty());

    b = good;
    put16(b, 50, 99, false);  // e_shstrndx outside the table
    h = elf::parse_header(b);
    ASSERT_TRUE(h.has_value());
    EXPECT_TRUE(elf::section(b, *h, ".modinfo").empty());
}

// SHT_NOBITS occupies no file bytes, so its "contents" are whatever follows
// it. Returning that would be inventing data.
TEST(Elf, ANobitsSectionHasNoBytes) {
    Bytes b = elf_with_section(".modinfo", "license=GPL", false, false);
    const auto h = elf::parse_header(b);
    ASSERT_TRUE(h.has_value());
    put32(b, static_cast<std::size_t>(h->shoff) + 40 + 4, 8 /*SHT_NOBITS*/, false);
    EXPECT_TRUE(elf::section(b, *h, ".modinfo").empty());
}

TEST(Elf, NamesTheMachinesEmbeddedEvidenceActuallyUses) {
    EXPECT_STREQ(elf::machine_name(8), "mips");
    EXPECT_STREQ(elf::machine_name(40), "arm");
    EXPECT_STREQ(elf::machine_name(183), "aarch64");
    EXPECT_STREQ(elf::machine_name(62), "x86-64");
    EXPECT_STREQ(elf::machine_name(0xBEEF), "unknown") << "never a guess";
}
