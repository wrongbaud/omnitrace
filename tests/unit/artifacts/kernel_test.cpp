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
Bytes kallsyms_blob(const std::vector<std::string>& symbols, bool be = false, unsigned word = 4) {
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
