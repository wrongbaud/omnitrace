// platform_test.cpp — the platform analyzers: Tree's path namespace (which is
// where the symlink resolution lives), analyzer precedence, and the Linux
// model's reading of the two files that decide whether a system could be
// logged into.
//
// Trees are built from EntryResults rather than from a real filesystem, so the
// tests say exactly what the listing contained. Content-reading tests write a
// few small files to a temp directory, because `Tree::read` deliberately opens
// the `host_path` a Sink recorded rather than holding bytes in memory.
#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include "omnitrace/analyzers/Platform.h"

using namespace omnitrace;
using namespace omnitrace::analyzers;
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
        path_ =
            base / ("omnitrace-platform-" + std::to_string(rd()) + "-" + std::to_string(counter++));
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

// A builder for one filesystem's listing.
class Fs {
   public:
    explicit Fs(const stdfs::path& root = {}) : root_(root) {}

    Fs& dir(const std::string& path) {
        EntryResult e;
        e.meta.path = path;
        e.meta.kind = EntryKind::Directory;
        entries_.push_back(std::move(e));
        return *this;
    }
    Fs& link(const std::string& path, const std::string& target) {
        EntryResult e;
        e.meta.path = path;
        e.meta.kind = EntryKind::Symlink;
        e.meta.link_target = target;
        entries_.push_back(std::move(e));
        return *this;
    }
    // A regular file. With `content` and a root, its bytes are written so
    // `Tree::read` can open them.
    Fs& file(const std::string& path, const std::string& content = {}) {
        EntryResult e;
        e.meta.path = path;
        e.meta.kind = EntryKind::Regular;
        e.meta.size = content.size();
        if (!root_.empty()) {
            const stdfs::path host = root_ / path;
            stdfs::create_directories(host.parent_path());
            std::ofstream f(host, std::ios::binary);
            f.write(content.data(), static_cast<std::streamsize>(content.size()));
            e.host_path = host.string();
            e.written = true;
        }
        entries_.push_back(std::move(e));
        return *this;
    }
    Fs& deleted_file(const std::string& path) {
        EntryResult e;
        e.meta.path = path;
        e.meta.kind = EntryKind::Regular;
        e.meta.deleted = true;
        entries_.push_back(std::move(e));
        return *this;
    }

    const std::vector<EntryResult>& entries() const { return entries_; }
    Tree tree() const { return Tree(entries_); }

   private:
    stdfs::path root_;
    std::vector<EntryResult> entries_;
};

const Fact* fact(const Report& r, const std::string& key) {
    for (const Fact& f : r.facts)
        if (f.key == key) return &f;
    return nullptr;
}
bool has_code(const std::vector<Diagnostic>& ds, const std::string& code) {
    for (const Diagnostic& d : ds)
        if (d.code == code) return true;
    return false;
}

// A minimal but realistic OpenWrt root, of the shape the corpus routers have.
Fs openwrt(const stdfs::path& root, const std::string& shadow) {
    Fs fs(root);
    fs.dir("etc").dir("etc/init.d").dir("bin").dir("usr").dir("usr/lib").dir("proc").dir("sys");
    fs.file("usr/lib/os-release",
            "NAME=\"OpenWrt\"\nPRETTY_NAME=\"OpenWrt 18.06.1\"\nID=openwrt\n"
            "VERSION_ID=\"18.06.1\"\nBUILD_ID=\"r7258\"\n");
    // The detail the corpus made unmissable: os-release is a symlink.
    fs.link("etc/os-release", "../usr/lib/os-release");
    fs.file("etc/openwrt_release", "DISTRIB_TARGET='ramips/mt76x8'\nDISTRIB_ARCH='mipsel_24kc'\n");
    fs.file("etc/passwd", "root:x:0:0:root:/root:/bin/ash\ndaemon:*:1:1:daemon:/var:/bin/false\n");
    fs.file("etc/shadow", shadow);
    fs.file("etc/inittab", "::sysinit:/etc/init.d/rcS S boot\n");
    fs.file("bin/busybox", "ELF");
    fs.file("etc/init.d/dropbear", "#!/bin/sh\n");
    fs.file("etc/init.d/network", "#!/bin/sh\n");
    return fs;
}

}  // namespace

// ------------------------------------------------------------------- Tree

TEST(PlatformTree, ResolvesSymlinksInsideTheFilesystem) {
    // /etc/os-release -> ../usr/lib/os-release is on every modern Linux, and
    // one corpus tree has 438 symlinks. An analyzer that only looked at
    // regular files would miss the most useful file on the system.
    const Fs fs = Fs().dir("etc")
                      .dir("usr/lib")
                      .file("usr/lib/os-release")
                      .link("etc/os-release", "../usr/lib/os-release");
    const Tree t = fs.tree();
    EXPECT_TRUE(t.has_file("etc/os-release"));
    ASSERT_NE(t.find("etc/os-release"), nullptr);
    EXPECT_EQ(t.find("etc/os-release")->meta.path, "usr/lib/os-release");
}

TEST(PlatformTree, AbsoluteLinkTargetsAreRootedAtTheFilesystem) {
    // A target of /usr/lib/x means the filesystem's own root, not the host's.
    const Fs fs = Fs().dir("usr/lib").file("usr/lib/x").link("etc/x", "/usr/lib/x");
    EXPECT_TRUE(fs.tree().has_file("etc/x"));
}

TEST(PlatformTree, DotDotCannotEscapeTheRoot) {
    // The filesystem itself would clamp at its root, and following this on the
    // host is how an extraction reads something outside its case directory.
    const Fs fs = Fs().file("etc/passwd").link("etc/evil", "../../../../../../etc/passwd");
    const Tree t = fs.tree();
    ASSERT_NE(t.find("etc/evil"), nullptr);
    EXPECT_EQ(t.find("etc/evil")->meta.path, "etc/passwd");
}

TEST(PlatformTree, LinkLoopsTerminate) {
    const Fs fs = Fs().link("a", "b").link("b", "a");
    EXPECT_EQ(fs.tree().find("a"), nullptr);
    const Fs self = Fs().link("s", "s");
    EXPECT_EQ(self.tree().find("s"), nullptr);
}

TEST(PlatformTree, DeletedAndSupersededEntriesAreNotTheRunningSystem) {
    // History has its own value, but answering "what is this system?" from a
    // deleted file would describe a machine that no longer existed.
    Fs fs;
    fs.file("etc/hostname").deleted_file("etc/passwd");
    const Tree t = fs.tree();
    EXPECT_TRUE(t.has_file("etc/hostname"));
    EXPECT_FALSE(t.has_file("etc/passwd"));
    EXPECT_EQ(t.size(), 1u);
}

TEST(PlatformTree, ListDirGivesDirectChildrenOnly) {
    const Fs fs = Fs().dir("etc")
                      .dir("etc/init.d")
                      .file("etc/init.d/network")
                      .file("etc/init.d/dropbear")
                      .file("etc/init.d/sub/deeper")
                      .file("etc/passwd");
    const std::vector<std::string> got = fs.tree().list_dir("etc/init.d");
    ASSERT_EQ(got.size(), 2u) << "'sub/deeper' is not a direct child";
    EXPECT_EQ(got[0], "dropbear");
    EXPECT_EQ(got[1], "network");
    EXPECT_TRUE(fs.tree().list_dir("etc/passwd").empty()) << "not a directory";
}

// --------------------------------------------------------------- detection

TEST(PlatformDetect, ALinuxRootIsRecognisedAndADataPartitionIsNot) {
    const TempDir tmp;
    const Fs fs = openwrt(tmp.path(), "root:*:0:0:99999:7:::\n");
    auto linux_a = AnalyzerRegistry::instance().create(Platform::Linux);
    ASSERT_NE(linux_a, nullptr) << "the analyzer must be registered and linked in";
    EXPECT_GT(linux_a->detect(fs.tree()), 0u);

    // A data partition has files and directories and is not a system.
    const Fs data =
        Fs().dir("logs").file("logs/2024.bin").file("config.dat").dir("media").file("media/a.mp3");
    EXPECT_EQ(linux_a->detect(data.tree()), 0u);
}

TEST(PlatformDetect, SurveyReportsOnePlatformPerFilesystem) {
    const TempDir tmp;
    const Fs rootfs = openwrt(tmp.path(), "root:*:0:0:99999:7:::\n");
    const Fs data = Fs().dir("d").file("d/blob.bin");
    // Plain (node, entries) pairs: the analyzers take no extraction type, so
    // a test can drive them without building a Manifest or a Span.
    const FilesystemEntries filesystems{{"n000001", rootfs.entries()}, {"n000002", data.entries()}};

    Survey s;
    ASSERT_TRUE(survey(filesystems, s));
    EXPECT_EQ(s.trees_examined, 2u);
    ASSERT_EQ(s.reports.size(), 1u);
    EXPECT_EQ(s.reports[0].node, "n000001");
    EXPECT_EQ(s.reports[0].platform, Platform::Linux);
    EXPECT_EQ(s.trees_unclaimed, 1u);
    EXPECT_TRUE(has_code(s.diagnostics, "platform-unrecognised"))
        << "a filesystem nothing recognises is a finding, not a silence";
}

// ------------------------------------------------------------ linux facts

TEST(PlatformLinux, ReadsWhatTheSystemSaysAboutItself) {
    const TempDir tmp;
    const Fs fs = openwrt(tmp.path(), "root:*:0:0:99999:7:::\n");
    auto a = AnalyzerRegistry::instance().create(Platform::Linux);
    Report r;
    a->describe(fs.tree(), r);

    // Read through the symlink, which is the whole point of resolving them.
    const Fact* pretty = fact(r, "os.pretty_name");
    ASSERT_NE(pretty, nullptr);
    EXPECT_EQ(pretty->value, "OpenWrt 18.06.1");
    EXPECT_EQ(pretty->source, "etc/os-release") << "the path an examiner would open";
    ASSERT_NE(fact(r, "os.arch"), nullptr);
    EXPECT_EQ(fact(r, "os.arch")->value, "mipsel_24kc");
    ASSERT_NE(fact(r, "os.target"), nullptr);
    EXPECT_EQ(fact(r, "os.target")->value, "ramips/mt76x8");
    ASSERT_NE(fact(r, "user.uid0"), nullptr);
    EXPECT_EQ(fact(r, "user.uid0")->value, "root");
    ASSERT_NE(fact(r, "init.count"), nullptr);
    EXPECT_EQ(fact(r, "init.count")->value, "2");
}

TEST(PlatformLinux, TheSameFieldMeansDifferentThingsInPasswdAndShadow) {
    const TempDir tmp;
    // `root::` is the router corpus image exactly: an empty field, so the
    // account authenticates with no password at all. `x` in shadow is not a
    // crypt string, so nothing a user types can ever match it.
    const Fs fs = openwrt(tmp.path(), "root::0:0:99999:7:::\ndnsmasq:x:0:0:99999:7:::\n");
    auto a = AnalyzerRegistry::instance().create(Platform::Linux);
    Report r;
    a->describe(fs.tree(), r);

    ASSERT_NE(fact(r, "user.root.password"), nullptr);
    EXPECT_EQ(fact(r, "user.root.password")->value, "empty");
    ASSERT_NE(fact(r, "user.dnsmasq.password"), nullptr);
    EXPECT_EQ(fact(r, "user.dnsmasq.password")->value, "invalid")
        << "'x' means 'see shadow' in passwd, but in shadow it is a dead field";
    ASSERT_NE(fact(r, "users.with_password"), nullptr);
    EXPECT_EQ(fact(r, "users.with_password")->value, "0");

    // A login with no password is the most actionable thing on the system and
    // does not belong in a table row.
    EXPECT_TRUE(has_code(r.diagnostics, "platform-account-no-password"));
}

TEST(PlatformLinux, AHashInPasswdIsWorthSayingOutLoud) {
    const TempDir tmp;
    // IP camera's camera ships root's md5 in the world-readable file, with
    // shadow holding a dead 'x'.
    Fs fs = openwrt(tmp.path(), "root:x:0:0:99999:7:::\n");
    fs.file("etc/passwd", "root:$1$abcd$efgh:0:0:root:/root:/bin/ash\n");
    auto a = AnalyzerRegistry::instance().create(Platform::Linux);
    Report r;
    a->describe(fs.tree(), r);

    bool from_passwd = false;
    for (const Fact& f : r.facts)
        from_passwd = from_passwd || (f.key == "user.root.password" && f.value == "md5" &&
                                      f.source == "etc/passwd");
    EXPECT_TRUE(from_passwd);
    EXPECT_TRUE(has_code(r.diagnostics, "platform-account-weak-hash"));
}

TEST(PlatformLinux, AgreeingFilesAreNotReportedTwiceButDisagreeingOnesAre) {
    const TempDir tmp;
    Fs fs = openwrt(tmp.path(), "root:*:0:0:99999:7:::\n");
    // openwrt_release repeats the name identically and adds its own version.
    fs.file("etc/openwrt_release",
            "DISTRIB_ID='OpenWrt'\nDISTRIB_DESCRIPTION='OpenWrt 18.06.1 r7258'\n"
            "DISTRIB_TARGET='ramips/mt76x8'\nDISTRIB_ARCH='mipsel_24kc'\n");
    auto a = AnalyzerRegistry::instance().create(Platform::Linux);
    Report r;
    a->describe(fs.tree(), r);

    unsigned pretty = 0, name = 0;
    for (const Fact& f : r.facts) {
        if (f.key == "os.pretty_name") ++pretty;
        if (f.key == "os.name") ++name;
    }
    EXPECT_EQ(name, 1u) << "both files say OpenWrt; saying it twice is noise";
    EXPECT_EQ(pretty, 2u) << "the two files give different descriptions, and which said what "
                             "is the kind of thing an examiner needs to see";
}

TEST(PlatformLinux, ReportsNothingItCannotRead) {
    // No host bytes behind any entry: the paths are there, the contents are
    // not, and the report must not invent facts.
    const Fs fs = openwrt({}, "root::0:0:99999:7:::\n");
    auto a = AnalyzerRegistry::instance().create(Platform::Linux);
    EXPECT_GT(a->detect(fs.tree()), 0u) << "detection is by path and still works";
    Report r;
    a->describe(fs.tree(), r);
    EXPECT_EQ(fact(r, "os.pretty_name"), nullptr);
    EXPECT_EQ(fact(r, "user.root.password"), nullptr);
    // init.d is a listing, not a read, so it survives.
    ASSERT_NE(fact(r, "init.count"), nullptr);
}
