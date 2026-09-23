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

// A QNX Neutrino root of the shape the automotive Android unit VCU's IFS images have. Every marker
// here was read off that unit: /proc/boot with the security policy in it, the
// devb-/devc-/io- resource managers, ksh and slogger2, and the two
// passwd-shaped files QNX ships.
Fs qnx(const stdfs::path& root) {
    Fs fs(root);
    fs.dir("etc").dir("etc/system").dir("etc/system/config").dir("bin").dir("sbin");
    fs.dir("proc").dir("proc/boot").dir(".boot").dir("lib64").dir("usr").dir("usr/lib");
    // Shared with Linux -- which is the point: these alone would make the
    // Linux analyzer claim the tree.
    fs.file("etc/passwd",
            "root:x:0:0:Superuser:/root:/bin/sh\n"
            "sshd:x:6:6:sshd:/var/chroot/sshd:/bin/false\n"
            "startupmgr::11:11:IFS loader and launcher:/:/bin/false\n");
    fs.file("etc/group", "root::0:\n");
    // QNX's own hash format, which is not crypt(3).
    fs.file("etc/shadow", "root:@S@inACiyeyNEuiog==@YTkzNzhkMjBm:1707215459:0:0:0:0:0:0\n");
    fs.file("etc/nopasswd", "root::0:0:Superuser:/root:/bin/sh\nuser::100:100:FTP User:/bin/sh\n");
    fs.file("etc/inetd.conf",
            "ftp        stream tcp nowait root  /usr/sbin/ftpd    in.ftpd -l\n"
            "shell      stream tcp nowait root  /usr/sbin/rshd    in.rshd\n"
            "telnet     stream tcp nowait root  /usr/sbin/telnetd in.telnetd\n"
            "ssh        stream tcp nowait root  /usr/sbin/sshd    sshd -i\n");
    fs.file("Buildinfo.txt",
            "BUILD_ID=9\nBUILD_TIMESTAMP=2024-09-30 04:59:27 UTC\n"
            "TARGET_PRODUCT=burmese_orange\nTARGET_BUILD_VARIANT=user\nSECURE_BOOT=true\n"
            "QC_PRODUCT=Snapdragon_Auto.HQX.3.1.4.1\nGM.Platform=GB\n");
    fs.file("bin/ksh").file("bin/slogger2").file("bin/on").file("bin/secpolgenerate");
    fs.file("sbin/devb-umass").file("sbin/devc-serusb_dcd").file("sbin/io-usb-otg");
    fs.file("sbin/chkqnx6fs").file("lib64/libslog2.so.1").file("lib64/libsecpol.so");
    fs.file("proc/boot/secpollaunch-ham_t.cfg").file("proc/boot/libsecpol.so.1");
    fs.file("etc/secpolgenerate.cfg", "#type ais_server_t unrestricted\n");
    return fs;
}

// An Android `system` partition of the documented shape. Marked here as it is
// in the analyzer: this is built from AOSP documentation, not from a real
// Android image, because none was reachable when it was written.
Fs android_system(const stdfs::path& root) {
    Fs fs(root);
    fs.dir("bin").dir("etc").dir("etc/permissions").dir("framework").dir("app").dir("priv-app");
    fs.dir("lib64").dir("etc/init").dir("etc/selinux").dir("apex");
    fs.file(
        "build.prop",
        "ro.build.fingerprint=google/coral/coral:13/TQ3A.230805.001/10316531:user/release-keys\n"
        "ro.build.version.release=13\n"
        "ro.build.version.sdk=33\n"
        "ro.build.version.security_patch=2023-08-05\n"
        "ro.build.type=user\n"
        "ro.build.tags=release-keys\n"
        "ro.product.model=Pixel 4 XL\n"
        "ro.product.manufacturer=Google\n"
        "ro.product.brand=google\n"
        "ro.product.cpu.abi=arm64-v8a\n"
        "ro.debuggable=0\n"
        "ro.secure=1\n");
    fs.file("bin/app_process64").file("bin/toybox");
    fs.file("framework/framework.jar");
    fs.file("etc/selinux/plat_sepolicy.cil");
    // Shared with Linux, which is the point: these make the Linux model match.
    fs.file("bin/sh");
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

    // An empty password gets a row of its own: it is one of the two states an
    // examiner acts on.
    ASSERT_NE(fact(r, "user.root.password"), nullptr);
    EXPECT_EQ(fact(r, "user.root.password")->value, "empty");
    // A dead field is counted, not rowed -- 286 rows reading the same thing is
    // not a report. `x` means "see shadow" in passwd but nothing in shadow.
    EXPECT_EQ(fact(r, "user.dnsmasq.password"), nullptr);
    ASSERT_NE(fact(r, "users.password_invalid"), nullptr);
    EXPECT_EQ(fact(r, "users.password_invalid")->value, "1");
    ASSERT_NE(fact(r, "users.with_password"), nullptr);
    EXPECT_EQ(fact(r, "users.with_password")->value, "0");
    ASSERT_NE(fact(r, "users.no_password"), nullptr);
    EXPECT_EQ(fact(r, "users.no_password")->value, "1");

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
    // Both findings, not one: the hash is crackable *and* it is in the
    // world-readable file. Chaining these lost the second one.
    bool world_readable = false, crackable = false;
    for (const Diagnostic& d : r.diagnostics) {
        if (d.code != "platform-account-weak-hash") continue;
        world_readable = world_readable || d.message.find("world-readable") != std::string::npos;
        crackable = crackable || d.message.find("cracks quickly") != std::string::npos;
    }
    EXPECT_TRUE(world_readable);
    EXPECT_TRUE(crackable);
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

// --------------------------------------------------------------------- QNX

// The reason Analyzer::rank exists. A QNX root carries etc/passwd, etc/group,
// etc/shadow, proc/ and usr/lib, so the Linux analyzer scores on it and would
// report a QNX infotainment unit as Linux. Measured on the automotive Android unit before the
// QNX model existed: five Linux markers matched.
TEST(PlatformQnx, OutranksLinuxOnATreeBothClaim) {
    const TempDir tmp;
    const Fs fs = qnx(tmp.path());
    auto lin = AnalyzerRegistry::instance().create(Platform::Linux);
    auto qn = AnalyzerRegistry::instance().create(Platform::Qnx);
    ASSERT_NE(qn, nullptr) << "the QNX analyzer must be registered and linked in";
    EXPECT_GT(lin->detect(fs.tree()), 0u) << "Linux really does match a QNX tree";
    EXPECT_GT(qn->rank(), lin->rank()) << "and rank, not score, is what settles it";

    const FilesystemEntries filesystems{{"n000001", fs.entries()}};
    Survey s;
    ASSERT_TRUE(survey(filesystems, s));
    ASSERT_EQ(s.reports.size(), 1u);
    EXPECT_EQ(s.reports[0].platform, Platform::Qnx);
}

TEST(PlatformQnx, ReadsTheIntegratorBuildManifest) {
    // QNX carries no os-release; what a shipped unit has is the integrator's
    // build file, and it is the most identifying thing on the system.
    const TempDir tmp;
    const Fs fs = qnx(tmp.path());
    auto a = AnalyzerRegistry::instance().create(Platform::Qnx);
    Report r;
    a->describe(fs.tree(), r);
    ASSERT_NE(fact(r, "build.product"), nullptr);
    EXPECT_EQ(fact(r, "build.product")->value, "burmese_orange");
    ASSERT_NE(fact(r, "build.secure_boot"), nullptr);
    EXPECT_EQ(fact(r, "build.secure_boot")->value, "true");
    ASSERT_NE(fact(r, "build.soc"), nullptr);
    EXPECT_EQ(fact(r, "build.soc")->value, "Snapdragon_Auto.HQX.3.1.4.1");
    // A vendor key with a dot in it is passed through rather than dropped.
    ASSERT_NE(fact(r, "build.vendor.GM_Platform"), nullptr);
    EXPECT_EQ(fact(r, "build.vendor.GM_Platform")->value, "GB");
}

TEST(PlatformQnx, KnowsTheQnxHashFormatIsNotCrypt) {
    // @S@<base64>@<base64> is QNX's own. A crypt-only reader calls it
    // "unrecognised", which would report a hashed root account as having no
    // usable password -- the opposite of the truth.
    const TempDir tmp;
    const Fs fs = qnx(tmp.path());
    auto a = AnalyzerRegistry::instance().create(Platform::Qnx);
    Report r;
    a->describe(fs.tree(), r);
    bool named = false;
    for (const Fact& f : r.facts)
        named = named || (f.key == "user.root.password" && f.value == "qnx-strong" &&
                          f.source == std::string("etc/shadow"));
    EXPECT_TRUE(named);
    ASSERT_NE(fact(r, "users.with_password"), nullptr);
    EXPECT_EQ(fact(r, "users.with_password")->value, "1");
}

TEST(PlatformQnx, TheNopasswdFileIsReportedAsWhatItIs) {
    // QNX ships a second passwd-shaped file for accounts that need no
    // password. On the automotive Android unit it holds `root::0:0:Superuser`, and the
    // diagnostic has to name that file rather than etc/passwd.
    const TempDir tmp;
    const Fs fs = qnx(tmp.path());
    auto a = AnalyzerRegistry::instance().create(Platform::Qnx);
    Report r;
    a->describe(fs.tree(), r);
    bool from_nopasswd = false;
    for (const Diagnostic& d : r.diagnostics)
        from_nopasswd = from_nopasswd || (d.code == "platform-account-no-password" &&
                                          d.message.find("etc/nopasswd") != std::string::npos);
    EXPECT_TRUE(from_nopasswd);
}

TEST(PlatformQnx, ClearTextNetworkServicesAreAWarningNotATableRow) {
    const TempDir tmp;
    const Fs fs = qnx(tmp.path());
    auto a = AnalyzerRegistry::instance().create(Platform::Qnx);
    Report r;
    a->describe(fs.tree(), r);

    // Who each service runs as is the half that matters.
    ASSERT_NE(fact(r, "service.telnet"), nullptr);
    EXPECT_EQ(fact(r, "service.telnet")->value, "root");
    unsigned insecure = 0;
    for (const Diagnostic& d : r.diagnostics)
        if (d.code == "platform-qnx-insecure-service") ++insecure;
    EXPECT_EQ(insecure, 3u) << "ftp, shell (rsh) and telnet; ssh is not one of them";
}

TEST(PlatformQnx, ReportsWhetherProcessesAreConfined) {
    const TempDir tmp;
    const Fs with = qnx(tmp.path());
    auto a = AnalyzerRegistry::instance().create(Platform::Qnx);
    Report r;
    a->describe(with.tree(), r);
    ASSERT_NE(fact(r, "security.secpol_files"), nullptr);
    EXPECT_EQ(fact(r, "security.secpol_files")->value, "1");
    EXPECT_FALSE(has_code(r.diagnostics, "platform-qnx-no-security-policy"));

    // A QNX image with no policy at all says so.
    Fs bare(tmp.path() / "bare");
    bare.dir("proc").dir("proc/boot").dir("bin").dir("sbin");
    bare.file("bin/ksh").file("bin/slogger2");
    bare.file("sbin/devb-umass").file("sbin/io-usb-otg");
    Report r2;
    a->describe(bare.tree(), r2);
    EXPECT_TRUE(has_code(r2.diagnostics, "platform-qnx-no-security-policy"));
}

TEST(PlatformQnx, ResourceManagersAloneIdentifyIt) {
    // devb- block drivers, devc- character drivers and io- stacks are named
    // that way on QNX and nowhere else; a tree with nothing but those is still
    // recognisable.
    Fs fs;
    fs.dir("sbin").file("sbin/devb-umass").file("sbin/io-pkt-v6-hc").file("sbin/devc-ser8250");
    auto a = AnalyzerRegistry::instance().create(Platform::Qnx);
    EXPECT_GT(a->detect(fs.tree()), 0u);

    // And a Linux sbin does not accidentally look like one.
    Fs lin;
    lin.dir("sbin").file("sbin/init").file("sbin/ifconfig").file("sbin/iptables");
    EXPECT_EQ(a->detect(lin.tree()), 0u);
}

// ----------------------------------------------------------------- Android
//
// Built against the documented Android layout, not against evidence: no
// Android image was reachable when these were written. They pin the model's
// own logic -- precedence, partition role, the security properties -- and not
// that the markers match a real device. See the AndroidAnalyzer file comment.

TEST(PlatformAndroid, OutranksLinuxBecauseAndroidIsLinux) {
    const TempDir tmp;
    const Fs fs = android_system(tmp.path());
    auto lin = AnalyzerRegistry::instance().create(Platform::Linux);
    auto droid = AnalyzerRegistry::instance().create(Platform::Android);
    ASSERT_NE(droid, nullptr) << "the Android analyzer must be registered and linked in";
    EXPECT_GT(droid->rank(), lin->rank());

    const FilesystemEntries filesystems{{"n000001", fs.entries()}};
    Survey s;
    ASSERT_TRUE(survey(filesystems, s));
    ASSERT_EQ(s.reports.size(), 1u);
    EXPECT_EQ(s.reports[0].platform, Platform::Android);
}

TEST(PlatformAndroid, ReadsTheBuildProperties) {
    const TempDir tmp;
    const Fs fs = android_system(tmp.path());
    auto a = AnalyzerRegistry::instance().create(Platform::Android);
    Report r;
    a->describe(fs.tree(), r);
    ASSERT_NE(fact(r, "os.version"), nullptr);
    EXPECT_EQ(fact(r, "os.version")->value, "13");
    ASSERT_NE(fact(r, "os.sdk"), nullptr);
    EXPECT_EQ(fact(r, "os.sdk")->value, "33");
    // How far behind the device is on patches is a fact an examiner acts on;
    // it is reported, never judged, because the library does not read a clock.
    ASSERT_NE(fact(r, "os.security_patch"), nullptr);
    EXPECT_EQ(fact(r, "os.security_patch")->value, "2023-08-05");
    ASSERT_NE(fact(r, "device.model"), nullptr);
    EXPECT_EQ(fact(r, "device.model")->value, "Pixel 4 XL");
    ASSERT_NE(fact(r, "os.pretty_name"), nullptr);
    EXPECT_EQ(fact(r, "os.pretty_name")->value, "google Pixel 4 XL (Android 13)");
    ASSERT_NE(fact(r, "android.partition"), nullptr);
    EXPECT_EQ(fact(r, "android.partition")->value, "system");
}

TEST(PlatformAndroid, ALockedReleaseBuildRaisesNothing) {
    const TempDir tmp;
    const Fs fs = android_system(tmp.path());
    auto a = AnalyzerRegistry::instance().create(Platform::Android);
    Report r;
    a->describe(fs.tree(), r);
    EXPECT_FALSE(has_code(r.diagnostics, "platform-android-debuggable"));
    EXPECT_FALSE(has_code(r.diagnostics, "platform-android-insecure"));
}

TEST(PlatformAndroid, AnEngineeringBuildSaysSo) {
    const TempDir tmp;
    Fs fs = android_system(tmp.path());
    fs.file("build.prop",
            "ro.product.model=Test\nro.debuggable=1\nro.secure=0\n"
            "ro.boot.verifiedbootstate=orange\n");
    auto a = AnalyzerRegistry::instance().create(Platform::Android);
    Report r;
    a->describe(fs.tree(), r);
    // These three decide whether an examiner can simply ask the device.
    EXPECT_TRUE(has_code(r.diagnostics, "platform-android-debuggable"));
    EXPECT_TRUE(has_code(r.diagnostics, "platform-android-insecure"));
    EXPECT_TRUE(has_code(r.diagnostics, "platform-android-unverified-boot"));
}

TEST(PlatformAndroid, TellsOnePartitionFromAnother) {
    // A device is several partitions and they are not interchangeable: user
    // data is not firmware, and a report that called both "android" would lose
    // the distinction an examiner cares about most.
    auto a = AnalyzerRegistry::instance().create(Platform::Android);
    const TempDir tmp;

    Fs data(tmp.path() / "data");
    data.dir("system").dir("data").dir("data/com.example").dir("misc/wifi");
    data.file("system/packages.xml", "<packages/>").file("system/users/userlist.xml", "<users/>");
    data.dir("system/users").dir("system/users/0").dir("system/users/10");
    Report rd;
    ASSERT_GT(a->detect(data.tree()), 0u);
    a->describe(data.tree(), rd);
    ASSERT_NE(fact(rd, "android.partition"), nullptr);
    EXPECT_EQ(fact(rd, "android.partition")->value, "data");
    ASSERT_NE(fact(rd, "users.count"), nullptr);
    EXPECT_EQ(fact(rd, "users.count")->value, "2") << "two numbered profile directories";

    Fs vendor(tmp.path() / "vendor");
    vendor.dir("lib/hw").dir("firmware").dir("etc/permissions");
    vendor.file("vendor/build.prop", "ro.product.model=V\n");
    Report rv;
    a->describe(vendor.tree(), rv);
    ASSERT_NE(fact(rv, "android.partition"), nullptr);
    EXPECT_EQ(fact(rv, "android.partition")->value, "vendor");
}

TEST(PlatformAndroid, ATreeWithOneWeakMarkerIsNotAndroid) {
    // The rule the QNX model had to learn: `app/` and `etc/` are not Android.
    Fs fs;
    fs.dir("app").dir("etc").dir("framework").file("bin/sh");
    auto a = AnalyzerRegistry::instance().create(Platform::Android);
    EXPECT_EQ(a->detect(fs.tree()), 0u);
}

// The Linux model gained the same threshold. A tree that merely has the
// directories a Linux system also has is not a Linux system.
TEST(PlatformLinux, DirectoriesAloneAreNotASystem) {
    Fs fs;
    fs.dir("proc").dir("sys").dir("usr/lib").dir("var/log").file("etc/hosts");
    auto a = AnalyzerRegistry::instance().create(Platform::Linux);
    EXPECT_EQ(a->detect(fs.tree()), 0u);
}
