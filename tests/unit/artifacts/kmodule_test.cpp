// kmodule_test.cpp — the kernel module extractor.
//
// Modules are built byte by byte here, not compiled, so a test says exactly
// what was in the `.modinfo` section. That section is the whole point of the
// extractor: it is where a driver states what hardware it is for, who wrote
// it, what licence it ships under and which kernel it was built against.
#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include "omnitrace/artifacts/Artifact.h"

using namespace omnitrace;
using namespace omnitrace::artifacts;
namespace stdfs = std::filesystem;

namespace {

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
        path_ = base / ("omnitrace-kmod-" + std::to_string(rd()) + "-" + std::to_string(counter++));
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

void put16(std::string& b, std::size_t at, std::uint16_t v) {
    b[at] = static_cast<char>(v & 0xFF);
    b[at + 1] = static_cast<char>(v >> 8);
}
void put32(std::string& b, std::size_t at, std::uint32_t v) {
    for (int i = 0; i < 4; ++i)
        b[at + static_cast<std::size_t>(i)] = static_cast<char>(v >> (8 * i));
}

/// A 32-bit little-endian ELF relocatable holding one `.modinfo` section,
/// which is what a kernel module is. `records` are the NUL-separated
/// `key=value` pairs the section holds.
std::string module_elf(const std::vector<std::string>& records, std::uint16_t machine = 8) {
    std::string modinfo;
    for (const std::string& r : records) {
        modinfo += r;
        modinfo.push_back('\0');
    }
    std::string shstr;
    shstr.push_back('\0');
    const std::uint32_t mi_name = static_cast<std::uint32_t>(shstr.size());
    shstr += ".modinfo";
    shstr.push_back('\0');
    const std::uint32_t str_name = static_cast<std::uint32_t>(shstr.size());
    shstr += ".shstrtab";
    shstr.push_back('\0');

    const std::size_t ehsize = 52, shent = 40;
    const std::size_t mi_off = ehsize;
    const std::size_t str_off = mi_off + modinfo.size();
    const std::size_t sh_off = str_off + shstr.size();
    std::string b(sh_off + 3 * shent, '\0');
    b[0] = 0x7F;
    b[1] = 'E';
    b[2] = 'L';
    b[3] = 'F';
    b[4] = 1;  // 32-bit
    b[5] = 1;  // little-endian
    b[6] = 1;
    put16(b, 16, 1);        // ET_REL
    put16(b, 18, machine);  // e_machine
    put32(b, 20, 1);
    put32(b, 32, static_cast<std::uint32_t>(sh_off));
    put16(b, 46, static_cast<std::uint16_t>(shent));
    put16(b, 48, 3);
    put16(b, 50, 2);
    std::copy(modinfo.begin(), modinfo.end(), b.begin() + static_cast<std::ptrdiff_t>(mi_off));
    std::copy(shstr.begin(), shstr.end(), b.begin() + static_cast<std::ptrdiff_t>(str_off));
    const auto sh = [&](std::size_t i, std::uint32_t nm, std::uint32_t type, std::uint32_t off,
                        std::uint32_t len) {
        const std::size_t at = sh_off + i * shent;
        put32(b, at, nm);
        put32(b, at + 4, type);
        put32(b, at + 16, off);
        put32(b, at + 20, len);
    };
    sh(0, 0, 0, 0, 0);
    sh(1, mi_name, 1, static_cast<std::uint32_t>(mi_off),
       static_cast<std::uint32_t>(modinfo.size()));
    sh(2, str_name, 3, static_cast<std::uint32_t>(str_off),
       static_cast<std::uint32_t>(shstr.size()));
    return b;
}

const Artifact* module_named(const Collection& c, const std::string& name) {
    for (const Artifact& a : c.artifacts) {
        if (a.kind != "kernel-module") continue;
        const auto it = a.fields.find("module");
        if (it != a.fields.end() && it->second == name) return &a;
    }
    return nullptr;
}
bool has_code(const std::vector<Diagnostic>& ds, const std::string& code) {
    for (const Diagnostic& d : ds)
        if (d.code == code) return true;
    return false;
}
std::size_t count_kind(const Collection& c, const std::string& kind) {
    std::size_t n = 0;
    for (const Artifact& a : c.artifacts)
        if (a.kind == kind) ++n;
    return n;
}

}  // namespace

// The whole reason this extractor exists: the analyzer can count modules and
// name them, and only a parser can say what a driver is *for*.
TEST(KernelModuleExtractor, ReportsWhatADriverSaysAboutItself) {
    const TempDir tmp;
    Fs fs(tmp.path());
    fs.file("lib/modules/5.4.55/cfg80211.ko",
            module_elf(
                {"license=GPL", "description=wireless configuration support",
                 "author=Johannes Berg", "depends=rfkill", "vermagic=5.4.55 SMP mod_unload ARMv7",
                 "alias=one", "alias=two", "parm=debug:bool"},
                40 /* arm */));
    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));

    const Artifact* m = module_named(c, "cfg80211");
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m->path, "lib/modules/5.4.55/cfg80211.ko");
    EXPECT_EQ(m->fields.at("description"), "wireless configuration support");
    EXPECT_EQ(m->fields.at("author"), "Johannes Berg");
    EXPECT_EQ(m->fields.at("license"), "GPL");
    EXPECT_EQ(m->fields.at("depends"), "rfkill");
    EXPECT_EQ(m->fields.at("vermagic"), "5.4.55 SMP mod_unload ARMv7");
    // The architecture comes from the ELF header, so it is there even when the
    // module carries no vermagic.
    EXPECT_EQ(m->fields.at("arch"), "arm");
    // Repeating keys are counted, not listed: a wireless driver carries
    // hundreds of aliases and a table of them is not a report.
    EXPECT_EQ(m->fields.at("aliases"), "2");
    EXPECT_EQ(m->fields.at("parameters"), "1");
}

// `name=` is not always written. The file name is what modprobe would use.
TEST(KernelModuleExtractor, FallsBackToTheFileNameForTheModuleName) {
    const TempDir tmp;
    Fs fs(tmp.path());
    fs.file("lib/modules/4.14.63/usbnet.ko", module_elf({"license=GPL", "depends=usbcore,mii"}));
    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));
    const Artifact* m = module_named(c, "usbnet");
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m->fields.at("depends"), "usbcore,mii");
    EXPECT_EQ(m->fields.count("description"), 0u) << "absent, not empty";
}

// A module built against a different kernel than the one it is installed
// under cannot load. The analyzer says a filesystem has the problem; this says
// which module, which is what an examiner needs to act on it.
TEST(KernelModuleExtractor, NamesTheModuleThatCannotLoad) {
    const TempDir tmp;
    Fs fs(tmp.path());
    fs.file("lib/modules/4.14.63/stale.ko",
            module_elf({"license=GPL", "vermagic=4.9.198 SMP mod_unload ARMv7"}));
    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));
    const Artifact* m = module_named(c, "stale");
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m->severity, Severity::Warning);
    EXPECT_TRUE(has_code(c.diagnostics, "kmodule-vermagic-path-mismatch"));
}

// A binary-only driver on a device whose firmware is supposed to be GPL is
// worth saying out loud; the four MediaTek modules in the router-nand corpus image
// are exactly this.
TEST(KernelModuleExtractor, SaysWhenADriverIsBinaryOnly) {
    const TempDir tmp;
    Fs fs(tmp.path());
    fs.file("lib/modules/5.4.55/mt_wifi.ko", module_elf({"license=Proprietary"}))
        .file("lib/modules/5.4.55/ok.ko", module_elf({"license=Dual BSD/GPL"}));
    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));
    EXPECT_TRUE(has_code(c.diagnostics, "kmodule-proprietary-license"));
    unsigned proprietary = 0;
    for (const Diagnostic& d : c.diagnostics)
        if (d.code == "kmodule-proprietary-license") ++proprietary;
    EXPECT_EQ(proprietary, 1u) << "a dual-licensed module is not proprietary";
}

// Everything else in a case runs past this extractor too, and none of it is a
// module.
TEST(KernelModuleExtractor, IgnoresWhatIsNotAModule) {
    const TempDir tmp;
    Fs fs(tmp.path());
    fs.file("lib/modules/4.14.63/notelf.ko", "#!/bin/sh\necho not an elf\n")
        .file("bin/busybox", module_elf({"license=GPL"}))  // an ELF, but not under lib/modules
        .file("lib/modules/4.14.63/nomodinfo.ko", module_elf({}))
        .file("etc/passwd", "root:x:0:0::/root:/bin/sh\n");
    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));
    EXPECT_EQ(count_kind(c, "kernel-module"), 0u);
}

// A truncated module is normal in evidence -- a cut extraction, a damaged
// block -- and must not produce a record built out of whatever followed.
TEST(KernelModuleExtractor, ATruncatedModuleYieldsNothing) {
    const TempDir tmp;
    const std::string whole = module_elf({"license=GPL", "description=something"});
    Fs fs(tmp.path());
    fs.file("lib/modules/4.14.63/cut.ko", whole.substr(0, whole.size() / 2));
    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));
    EXPECT_EQ(count_kind(c, "kernel-module"), 0u);
}
