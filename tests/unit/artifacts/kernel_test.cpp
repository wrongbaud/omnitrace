// kernel_test.cpp — the kallsyms decoder and the Linux kernel extractor.
//
// A kallsyms table is built here byte by byte, in the order the kernel lays
// it out, so a test says exactly what was in the image. The decoder finds it
// with no magic to go on, so the fixtures that matter most are the ones that
// look like a table and are not one.
#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include "../../../src/artifacts/kernel/Kallsyms.h"
#include "omnitrace/artifacts/Artifact.h"

using namespace omnitrace;
using namespace omnitrace::artifacts;
namespace stdfs = std::filesystem;

namespace {

using Bytes = std::vector<std::uint8_t>;

void put16(Bytes& b, std::uint16_t v, bool be) {
    b.push_back(static_cast<std::uint8_t>(be ? v >> 8 : v & 0xFF));
    b.push_back(static_cast<std::uint8_t>(be ? v & 0xFF : v >> 8));
}
void putword(Bytes& b, std::uint64_t v, bool be, unsigned w) {
    for (unsigned i = 0; i < w; ++i)
        b.push_back(static_cast<std::uint8_t>(be ? v >> (8 * (w - 1 - i)) : v >> (8 * i)));
}

/// A kallsyms table as the kernel writes it: num_syms, names, markers,
/// token_table, token_index.
///
/// The token alphabet is the identity -- token i is the single byte i -- so a
/// name encodes as its own bytes. That is a legal table (tokens are arbitrary
/// strings) and it keeps the fixture readable.
/// Which address array to put in front of the table, if any.
enum class Addrs { None, Absolute, Relative, RelativePercpu };

Bytes kallsyms_blob(const std::vector<std::string>& symbols, bool be = false, unsigned word = 4,
                    Addrs addrs = Addrs::None, std::uint64_t base = 0xc0000000ULL) {
    Bytes names;
    std::vector<std::uint64_t> markers;
    for (std::size_t i = 0; i < symbols.size(); ++i) {
        if (i % 256 == 0) markers.push_back(names.size());
        names.push_back(static_cast<std::uint8_t>(symbols[i].size()));
        for (const char c : symbols[i]) names.push_back(static_cast<std::uint8_t>(c));
    }

    Bytes table;
    std::vector<std::uint16_t> index(256, 0);
    // Token 0 is empty so that its index entry is 1, which is what a real
    // table looks like; tokens 1..255 are the byte they stand for.
    index[0] = 0;
    table.push_back(0);
    for (unsigned i = 1; i < 256; ++i) {
        index[i] = static_cast<std::uint16_t>(table.size());
        table.push_back(static_cast<std::uint8_t>(i));
        table.push_back(0);
    }

    Bytes out;
    // The address array comes first, then (for the relative forms) the base
    // word, then num_syms. That is the order the kernel emits.
    if (addrs == Addrs::Absolute) {
        for (std::size_t i = 0; i < symbols.size(); ++i) putword(out, base + i * 16, be, word);
    } else if (addrs == Addrs::Relative) {
        for (std::size_t i = 0; i < symbols.size(); ++i) putword(out, 0x1000 + i * 16, be, 4);
        putword(out, base, be, word);
    } else if (addrs == Addrs::RelativePercpu) {
        // How a real --absolute-percpu table looks: an ordinary symbol is
        // stored as the *negative* number that resolves to its address
        // through `base - 1 - offset`. Only per-cpu variables are positive.
        for (std::size_t i = 0; i < symbols.size(); ++i) {
            const std::uint64_t addr = base + 0x1000 + i * 16;
            const std::int32_t off = static_cast<std::int32_t>(static_cast<std::int64_t>(base) - 1 -
                                                               static_cast<std::int64_t>(addr));
            putword(out, static_cast<std::uint32_t>(off), be, 4);
        }
        putword(out, base, be, word);
    }
    putword(out, symbols.size(), be, word);
    out.insert(out.end(), names.begin(), names.end());
    while (out.size() % word != 0) out.push_back(0);
    for (const std::uint64_t m : markers) putword(out, m, be, word);
    out.insert(out.end(), table.begin(), table.end());
    while (out.size() % 2 != 0) out.push_back(0);
    for (const std::uint16_t v : index) put16(out, v, be);
    return out;
}

/// `n` plausible symbols, each with its nm type letter first, as kallsyms
/// stores them.
std::vector<std::string> made_up_symbols(std::size_t n) {
    std::vector<std::string> out;
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        const char type = (i % 3 == 0) ? 'T' : (i % 3 == 1 ? 't' : 'd');
        out.push_back(std::string(1, type) + "sym_" + std::to_string(i) + "_func");
    }
    return out;
}

class TempDir {
   public:
    TempDir() {
        stdfs::path base;
        if (const char* env = std::getenv("OMNITRACE_TEST_TMPDIR"))
            base = env;
        else
            base = stdfs::temp_directory_path();
        static int counter = 0;
        std::random_device rd;
        path_ = base / ("omnitrace-kern-" + std::to_string(rd()) + "-" + std::to_string(counter++));
        stdfs::remove_all(path_);
        stdfs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        stdfs::remove_all(path_, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    const stdfs::path& path() const { return path_; }

   private:
    stdfs::path path_;
};

class Fs {
   public:
    explicit Fs(const stdfs::path& root) : root_(root) {}
    Fs& file(const std::string& path, const std::string& content) {
        EntryResult e;
        e.meta.path = path;
        e.meta.kind = EntryKind::Regular;
        e.meta.size = content.size();
        const stdfs::path host = root_ / path;
        stdfs::create_directories(host.parent_path());
        std::ofstream f(host, std::ios::binary);
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
        e.host_path = host.string();
        e.written = true;
        entries_.push_back(std::move(e));
        return *this;
    }
    FilesystemEntries entries() const { return {{"n000001", entries_}}; }

   private:
    stdfs::path root_;
    std::vector<EntryResult> entries_;
};

const Artifact* of_kind(const Collection& c, const std::string& kind) {
    for (const Artifact& a : c.artifacts)
        if (a.kind == kind) return &a;
    return nullptr;
}
std::size_t count_kind(const Collection& c, const std::string& kind) {
    std::size_t n = 0;
    for (const Artifact& a : c.artifacts)
        if (a.kind == kind) ++n;
    return n;
}
std::string as_string(const Bytes& b) {
    return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

}  // namespace

TEST(Kallsyms, DecodesATableInEitherByteOrderAndWordSize) {
    for (const bool be : {false, true}) {
        for (const unsigned word : {4u, 8u}) {
            const auto syms = made_up_symbols(600);
            Bytes img(4096, 0x5A);  // leading data the table has to be found in
            const Bytes blob = kallsyms_blob(syms, be, word);
            img.insert(img.end(), blob.begin(), blob.end());

            const kernel::Kallsyms ks = kernel::parse(img);
            ASSERT_TRUE(ks.found) << "be=" << be << " word=" << word;
            EXPECT_EQ(ks.big_endian, be);
            EXPECT_EQ(ks.word_size, word);
            ASSERT_EQ(ks.symbols.size(), 600u);
            EXPECT_EQ(ks.symbols[0].type, 'T');
            EXPECT_EQ(ks.symbols[0].name, "sym_0_func");
            EXPECT_EQ(ks.symbols[1].type, 't');
            EXPECT_EQ(ks.symbols[599].name, "sym_599_func");
        }
    }
}

// Addresses are a second array, found by arithmetic from `num_syms` rather
// than by searching. Which of the three forms it is has to be decided by what
// the values look like, because all three sit in the same place.
TEST(Kallsyms, DecodesAbsoluteAddresses) {
    const auto syms = made_up_symbols(600);
    const Bytes blob = kallsyms_blob(syms, false, 4, Addrs::Absolute, 0xc0100000ULL);
    const kernel::Kallsyms ks = kernel::parse(blob);
    ASSERT_TRUE(ks.found);
    ASSERT_TRUE(ks.addressed);
    EXPECT_EQ(ks.mode, kernel::AddressMode::Absolute);
    ASSERT_EQ(ks.symbols.size(), 600u);
    EXPECT_EQ(ks.symbols[0].address, 0xc0100000ULL);
    EXPECT_EQ(ks.symbols[1].address, 0xc0100010ULL);
    EXPECT_EQ(ks.symbols[599].address, 0xc0100000ULL + 599 * 16);
    EXPECT_EQ(ks.symbols[0].name, "sym_0_func") << "the names are still the names";
}

// What every kernel since 4.6 builds by default: a u32 offset per symbol and
// one base word. The base sits exactly where an absolute array's last address
// would be, which is why it is tested first.
TEST(Kallsyms, DecodesBaseRelativeAddresses) {
    const auto syms = made_up_symbols(600);
    const Bytes blob = kallsyms_blob(syms, false, 4, Addrs::Relative, 0xc0088000ULL);
    const kernel::Kallsyms ks = kernel::parse(blob);
    ASSERT_TRUE(ks.found);
    ASSERT_TRUE(ks.addressed);
    EXPECT_EQ(ks.mode, kernel::AddressMode::Relative);
    EXPECT_EQ(ks.relative_base, 0xc0088000ULL);
    EXPECT_EQ(ks.symbols[0].address, 0xc0088000ULL + 0x1000);
    EXPECT_EQ(ks.symbols[10].address, 0xc0088000ULL + 0x1000 + 160);
}

// --absolute-percpu: a positive entry is the address itself. Telling it from
// the plain relative form is the reason `address_like` exists.
TEST(Kallsyms, DecodesAbsolutePercpuAddresses) {
    const auto syms = made_up_symbols(600);
    const Bytes blob = kallsyms_blob(syms, false, 4, Addrs::RelativePercpu, 0xc0000000ULL);
    const kernel::Kallsyms ks = kernel::parse(blob);
    ASSERT_TRUE(ks.found);
    ASSERT_TRUE(ks.addressed);
    EXPECT_EQ(ks.mode, kernel::AddressMode::RelativePercpu);
    EXPECT_EQ(ks.symbols[0].address, 0xc0001000ULL);
}

TEST(Kallsyms, DecodesAddressesInEitherByteOrderAndWordSize) {
    for (const bool be : {false, true}) {
        for (const unsigned word : {4u, 8u}) {
            // A 64-bit kernel does not live at 0xc0100000, and the address
            // test is right to refuse it there: the top half of a 64-bit
            // address space starts a great deal higher.
            const std::uint64_t base = word == 4 ? 0xc0100000ULL : 0xffffffff81000000ULL;
            const Bytes blob = kallsyms_blob(made_up_symbols(600), be, word, Addrs::Absolute, base);
            const kernel::Kallsyms ks = kernel::parse(blob);
            ASSERT_TRUE(ks.found) << "be=" << be << " word=" << word;
            ASSERT_TRUE(ks.addressed) << "be=" << be << " word=" << word;
            EXPECT_EQ(ks.symbols[0].address, base) << "be=" << be << " word=" << word;
        }
    }
}

// An absolute array's last address sits exactly where `relative_base` would,
// so reading it as base-relative "works": adding the array to itself still
// ascends and still looks like addresses. What gives it away is the width --
// a 32-bit kernel does not have a symbol above 4 GiB. The camera v1 is an
// absolute table and was read as relative, putting its text at 0x10043b3c4,
// until the resolved addresses were bounded to the word size.
TEST(Kallsyms, AnAbsoluteTableIsNotReadAsRelative) {
    const auto syms = made_up_symbols(600);
    const Bytes blob = kallsyms_blob(syms, false, 4, Addrs::Absolute, 0x80010400ULL);
    const kernel::Kallsyms ks = kernel::parse(blob);
    ASSERT_TRUE(ks.found);
    ASSERT_TRUE(ks.addressed);
    EXPECT_EQ(ks.mode, kernel::AddressMode::Absolute) << "not relative";
    EXPECT_EQ(ks.symbols[0].address, 0x80010400ULL);
    for (const kernel::Symbol& sy : ks.symbols)
        ASSERT_LE(sy.address, 0xFFFFFFFFULL) << "a 32-bit kernel has no symbol above 4 GiB";
}

// The count written next to the names is what says the word size was read
// right. Reading an 8-byte marker array as 4-byte words can produce a short
// chain that the real names blob then satisfies, decoding genuine symbols --
// 511 of them, in a fixture that holds 600. Nothing in the names says
// otherwise; `num_syms` does.
TEST(Kallsyms, RequiresTheRecordedSymbolCountToAgree) {
    Bytes blob = kallsyms_blob(made_up_symbols(600), false, 4, Addrs::Absolute, 0x80010400ULL);
    const kernel::Kallsyms ok = kernel::parse(blob);
    ASSERT_TRUE(ok.found);
    ASSERT_EQ(ok.symbols.size(), 600u);

    // Corrupt only the recorded count; the names and markers are untouched.
    const std::size_t ns = static_cast<std::size_t>(ok.num_syms_at);
    ASSERT_LT(ns + 4, blob.size());
    blob[ns] = 0x11;
    blob[ns + 1] = 0x22;
    EXPECT_FALSE(kernel::parse(blob).found)
        << "a table that disagrees with its own count is not decoded";
}

// The two halves are found separately, so a table whose addresses cannot be
// read is still a table: losing them must not lose the symbols.
TEST(Kallsyms, SymbolsSurviveAnUnreadableAddressArray) {
    const Bytes blob = kallsyms_blob(made_up_symbols(600));  // no address array at all
    const kernel::Kallsyms ks = kernel::parse(blob);
    ASSERT_TRUE(ks.found);
    EXPECT_FALSE(ks.addressed);
    EXPECT_EQ(ks.mode, kernel::AddressMode::None);
    ASSERT_EQ(ks.symbols.size(), 600u);
    EXPECT_EQ(ks.symbols[0].name, "sym_0_func");
    EXPECT_EQ(ks.symbols[0].address, 0u) << "absent, never invented";
}

// More than 256 symbols is what makes the markers array real: one entry per
// block, and the decoder validates a candidate by walking only the last one.
TEST(Kallsyms, HandlesManyBlocksOfSymbols) {
    const auto syms = made_up_symbols(2000);
    const Bytes blob = kallsyms_blob(syms);
    const kernel::Kallsyms ks = kernel::parse(blob);
    ASSERT_TRUE(ks.found);
    ASSERT_EQ(ks.symbols.size(), 2000u);
    EXPECT_EQ(ks.symbols[1999].name, "sym_1999_func");
    EXPECT_EQ(ks.symbols[256].name, "sym_256_func") << "the first symbol of the second block";
}

// The decoder has no magic to go on, so what matters most is that it refuses.
// A kernel image is megabytes of data that will coincidentally satisfy any one
// of its three checks.
TEST(Kallsyms, FindsNothingInDataThatIsNotATable) {
    EXPECT_FALSE(kernel::parse({}).found);
    EXPECT_FALSE(kernel::parse(Bytes(64 * 1024, 0)).found) << "all zeroes";
    EXPECT_FALSE(kernel::parse(Bytes(64 * 1024, 0xFF)).found);

    // Deterministic pseudo-random bytes: no seed from the host, so a failure
    // here reproduces.
    Bytes noise(1u << 20);
    std::uint32_t x = 0x12345678;
    for (std::uint8_t& b : noise) {
        x = x * 1664525u + 1013904223u;
        b = static_cast<std::uint8_t>(x >> 24);
    }
    EXPECT_FALSE(kernel::parse(noise).found);

    // An ascending u16 ramp satisfies "256 non-decreasing u16 starting at 0"
    // and is not a token index.
    Bytes ramp;
    for (std::uint16_t i = 0; i < 4096; ++i) put16(ramp, i, false);
    EXPECT_FALSE(kernel::parse(ramp).found);
}

// A table whose names decode to something that is not a symbol is not a table
// this will report: the arithmetic lining up is not enough.
TEST(Kallsyms, RefusesATableWhoseNamesAreNotSymbols) {
    std::vector<std::string> junk;
    for (std::size_t i = 0; i < 600; ++i) junk.push_back(std::string("\x01\x02\x03\x04"));
    const Bytes blob = kallsyms_blob(junk);
    EXPECT_FALSE(kernel::parse(blob).found);
}

TEST(Kallsyms, ATruncatedTableIsNotDecoded) {
    const Bytes blob = kallsyms_blob(made_up_symbols(600));
    for (const double keep : {0.25, 0.5, 0.75, 0.95}) {
        Bytes cut(blob.begin(), blob.begin() + static_cast<std::ptrdiff_t>(
                                                   static_cast<double>(blob.size()) * keep));
        EXPECT_FALSE(kernel::parse(cut).found) << "keeping " << keep;
    }
}

// ---------------------------------------------------------------- extractor

TEST(LinuxKernelExtractor, ReadsTheBannerAndTheSymbolTable) {
    const TempDir tmp;
    std::string img(8192, '\0');
    img +=
        "Linux version 5.4.55 (jenkins@host) (gcc version 8.4.0 (OpenWrt GCC 8.4.0)) #0 SMP "
        "Fri Aug 15 02:53:20 2025\n";
    img += as_string(kallsyms_blob(made_up_symbols(600)));
    Fs fs(tmp.path());
    fs.file("payload", img);

    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));
    const Artifact* k = of_kind(c, "linux-kernel");
    ASSERT_NE(k, nullptr);
    EXPECT_EQ(k->fields.at("version"), "5.4.55");
    EXPECT_NE(k->fields.at("banner").find("Linux version 5.4.55"), std::string::npos);
    EXPECT_EQ(k->fields.at("compiler"), "gcc version 8.4.0 (OpenWrt GCC 8.4.0)")
        << "the nested parentheses have to balance";
    EXPECT_EQ(k->fields.at("symbols"), "600");
    EXPECT_EQ(k->fields.at("symbol_types"), "T=200,d=200,t=200");
}

// With addresses the symbol list becomes a map of the running kernel: where it
// was linked to live, and how much of the address space it takes.
TEST(LinuxKernelExtractor, ReportsWhereTheKernelRuns) {
    const TempDir tmp;
    std::vector<std::string> syms = made_up_symbols(600);
    syms[0] = "T_stext";  // the symbol an examiner lines a disassembly up on
    std::string img(4096, '\0');
    img += "Linux version 5.4.55 (b@h) (gcc version 8.4.0) #0 SMP Fri Aug 15 02:53:20 2025\n";
    // kallsyms is word-aligned inside a real image, so the fixture aligns it
    // too: dropped at an odd offset, the marker array cannot be read as words.
    while (img.size() % 8 != 0) img.push_back('\0');
    img += as_string(kallsyms_blob(syms, false, 4, Addrs::Relative, 0xc0088000ULL));
    Fs fs(tmp.path());
    fs.file("payload", img);

    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));
    const Artifact* k = of_kind(c, "linux-kernel");
    ASSERT_NE(k, nullptr);
    EXPECT_EQ(k->fields.at("address_mode"), "relative");
    EXPECT_EQ(k->fields.at("relative_base"), "0xc0088000");
    EXPECT_EQ(k->fields.at("load_address"), "0xc0089000");
    EXPECT_EQ(k->fields.at("text_start"), "0xc0089000") << "_stext, found by name";
    EXPECT_EQ(k->fields.at("address_span"), "0x2570") << "599 * 16 bytes";
}

// Thirty thousand names do not belong in a record or a report table, and
// counting them is not the same as having them. The table goes to the case
// directory in `nm` format so the tools that read that format can read this.
TEST(LinuxKernelExtractor, WritesTheSymbolTableToTheCaseDirectory) {
    const TempDir tmp;
    std::vector<std::string> syms = made_up_symbols(600);
    syms[0] = "T_stext";
    std::string img(4096, '\0');
    img += "Linux version 5.4.55 (b@h) (gcc version 8.4.0) #0 SMP Fri Aug 15 02:53:20 2025\n";
    while (img.size() % 8 != 0) img.push_back('\0');
    img += as_string(kallsyms_blob(syms, false, 4, Addrs::Relative, 0xc0088000ULL));
    Fs fs(tmp.path());
    fs.file("payload", img);

    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));
    ASSERT_EQ(c.files.size(), 1u);
    const ExtractedFile& f = c.files.front();
    EXPECT_EQ(f.path, "symbols/n000001-payload.txt");
    EXPECT_TRUE(safe_relative_path(f.path));

    // The record points at it, so a reader of the report can find it.
    const Artifact* k = of_kind(c, "linux-kernel");
    ASSERT_NE(k, nullptr);
    EXPECT_EQ(k->fields.at("symbols_file"), f.path);

    // nm format: address, type, name -- one line per symbol, in table order.
    std::vector<std::string> lines;
    for (std::size_t at = 0; at < f.content.size();) {
        const std::size_t nl = f.content.find('\n', at);
        ASSERT_NE(nl, std::string::npos) << "every line is terminated";
        lines.push_back(f.content.substr(at, nl - at));
        at = nl + 1;
    }
    ASSERT_EQ(lines.size(), 600u);
    EXPECT_EQ(lines[0], "c0089000 T _stext");
    EXPECT_EQ(lines[1], "c0089010 t sym_1_func");
    EXPECT_EQ(lines[599], "c008b570 d sym_599_func");
}

// A kernel with no readable address array still has names worth writing, and
// nm leaves the address column blank rather than inventing one.
TEST(LinuxKernelExtractor, WritesNamesEvenWithNoAddresses) {
    const TempDir tmp;
    std::string img(4096, '\0');
    img += "Linux version 4.14.63 (l@h) (gcc version 7.3.0) #0\n";
    while (img.size() % 8 != 0) img.push_back('\0');
    img += as_string(kallsyms_blob(made_up_symbols(600)));  // no address array
    Fs fs(tmp.path());
    fs.file("boot/vmlinux", img);

    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));
    ASSERT_EQ(c.files.size(), 1u);
    EXPECT_EQ(c.files.front().path, "symbols/n000001-boot-vmlinux.txt")
        << "the separator is flattened, so one kernel per path";
    EXPECT_EQ(c.files.front().content.substr(0, 21), "         T sym_0_func")
        << "nm leaves the address blank";
}

// An extractor is built in, but what it names a file after is not: a kernel
// image's own path reaches the name. The check is on the path, not on trust.
TEST(ArtifactFiles, RefusesAPathOutsideTheCase) {
    EXPECT_TRUE(safe_relative_path("symbols/n1-payload.txt"));
    EXPECT_FALSE(safe_relative_path(""));
    EXPECT_FALSE(safe_relative_path("/etc/passwd"));
    EXPECT_FALSE(safe_relative_path("../escape.txt"));
    EXPECT_FALSE(safe_relative_path("symbols/../../escape.txt"));
    EXPECT_FALSE(safe_relative_path("symbols/./x.txt"));
    EXPECT_FALSE(safe_relative_path("C:/windows/x.txt"));
    EXPECT_FALSE(safe_relative_path("symbols\\x.txt")) << "a backslash is a separator too";
    EXPECT_FALSE(safe_relative_path(std::string("sym\0bols/x.txt", 15)));
    EXPECT_FALSE(safe_relative_path("symbols//x.txt")) << "an empty component";
}

// The whole reason `version_of` checks: the string is plain English and turns
// up in writing. The router-wrt corpus image carries exactly this sentence, and it
// produced a kernel record whose version was "of".
TEST(LinuxKernelExtractor, TheWordsAloneAreNotAKernel) {
    const TempDir tmp;
    Fs fs(tmp.path());
    fs.file("payload", std::string(2048, 'x') +
                           "Linux version of the hub software for the Direct Connect network.\n" +
                           std::string(2048, 'y'));
    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));
    EXPECT_EQ(count_kind(c, "linux-kernel"), 0u);
}

// A kernel built without CONFIG_KALLSYMS is still a kernel, and its banner is
// still the only place its version is written down.
TEST(LinuxKernelExtractor, AKernelWithNoSymbolTableIsStillReported) {
    const TempDir tmp;
    Fs fs(tmp.path());
    fs.file("boot/vmlinuz", std::string(1024, '\0') +
                                "Linux version 4.14.63 (luo@host) (gcc version 7.3.0) #0\n" +
                                std::string(4096, '\0'));
    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));
    const Artifact* k = of_kind(c, "linux-kernel");
    ASSERT_NE(k, nullptr);
    EXPECT_EQ(k->fields.at("version"), "4.14.63");
    EXPECT_EQ(k->fields.at("symbols"), "0");
    bool said = false;
    for (const Diagnostic& d : c.diagnostics)
        if (d.code == "kernel-no-symbol-table") said = true;
    EXPECT_TRUE(said) << "silence would read as 'this kernel has no functions'";
}

TEST(LinuxKernelExtractor, DoesNotReadEveryFileInTheCase) {
    const TempDir tmp;
    Fs fs(tmp.path());
    // Same content, a name no kernel is ever shipped under.
    fs.file("usr/share/doc/README", std::string(512, 'a') + "Linux version 5.4.55 (x) #0\n");
    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));
    EXPECT_EQ(count_kind(c, "linux-kernel"), 0u);
}
