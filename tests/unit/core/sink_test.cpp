// sink_test.cpp — normalize_entry_path, DiskSink (POSIX) and ListingSink.
//
// DiskSink tests run under a fresh directory beneath $OMNITRACE_TEST_TMPDIR
// (falling back to the system temp dir) and remove it afterwards.
#include "omnitrace/core/Sink.h"

#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace omnitrace {
namespace {

namespace fs = std::filesystem;

const char kHelloSha256[] = "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447";
const char kHelloMd5[] = "6f5902ac237024bdd0c176cb93063dc4";

std::span<const std::uint8_t> bytes_of(const std::string& s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

std::string slurp(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.compare(0, prefix.size(), prefix) == 0;
}

bool has_code(const std::vector<Diagnostic>& d, const std::string& code) {
    for (const Diagnostic& x : d)
        if (x.code == code) return true;
    return false;
}

// A unique scratch directory per test, removed on teardown.
class TempDir {
   public:
    TempDir() {
        fs::path base;
        if (const char* env = std::getenv("OMNITRACE_TEST_TMPDIR"))
            base = env;
        else
            base = fs::temp_directory_path();
        static int counter = 0;
        path_ = base /
                ("omnitrace-sink-" + std::to_string(::getpid()) + "-" + std::to_string(counter++));
        fs::remove_all(path_);
        fs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    const fs::path& path() const { return path_; }

   private:
    fs::path path_;
};

FileMeta regular(const std::string& path, std::uint32_t mode = 0644) {
    FileMeta m;
    m.path = path;
    m.kind = EntryKind::Regular;
    m.mode = mode;
    return m;
}

std::unique_ptr<DiskSink> open_sink(const fs::path& root, DiskSink::Options opts = {}) {
    std::unique_ptr<DiskSink> sink;
    const Status s = DiskSink::open(root.string(), opts, sink);
    EXPECT_TRUE(s.ok) << s.error;
    return sink;
}

// ---------------------------------------------------------------------------
// normalize_entry_path
// ---------------------------------------------------------------------------

TEST(NormalizePath, Accepts) {
    std::string out;
    EXPECT_TRUE(normalize_entry_path("a/b", out));
    EXPECT_EQ(out, "a/b");
    EXPECT_TRUE(normalize_entry_path("a//b", out));
    EXPECT_EQ(out, "a/b");
    EXPECT_TRUE(normalize_entry_path("a/./b", out));
    EXPECT_EQ(out, "a/b");
    EXPECT_TRUE(normalize_entry_path("./a", out));
    EXPECT_EQ(out, "a");
    EXPECT_TRUE(normalize_entry_path("a/b/", out));
    EXPECT_EQ(out, "a/b");
    EXPECT_TRUE(normalize_entry_path("a\\b\\c", out));
    EXPECT_EQ(out, "a/b/c");
    EXPECT_TRUE(normalize_entry_path("..a/b..", out));
    EXPECT_EQ(out, "..a/b..");
    EXPECT_TRUE(normalize_entry_path("...", out));
    EXPECT_EQ(out, "...");
    // Look-alikes of reserved names are fine.
    EXPECT_TRUE(normalize_entry_path("console", out));
    EXPECT_TRUE(normalize_entry_path("COM0", out));
    EXPECT_TRUE(normalize_entry_path("COM10", out));
    EXPECT_TRUE(normalize_entry_path("nullify.txt", out));
    EXPECT_TRUE(normalize_entry_path("lpt", out));
    EXPECT_TRUE(
        normalize_entry_path("ab:cd", out));  // not a drive prefix: two chars before the colon
    // Non-ASCII bytes pass through untouched.
    EXPECT_TRUE(normalize_entry_path("caf\xc3\xa9/\xe6\x97\xa5", out));
    EXPECT_EQ(out, "caf\xc3\xa9/\xe6\x97\xa5");
}

TEST(NormalizePath, Rejects) {
    std::string out, why;
    const char* bad[] = {
        "../x",
        "a/../b",
        "a/..",
        "..",
        "/etc/passwd",
        "//server/share",
        "\\\\server\\share",
        "\\x",
        "C:\\x",
        "c:/x",
        "C:x",
        "a:b",
        "a/C:/x",
        "",
        ".",
        "./",
        "././",
        "CON",
        "con",
        "CON.txt",
        "Con.tar.gz",
        "PRN",
        "AUX",
        "NUL",
        "nul.log",
        "COM1",
        "com9.dat",
        "LPT1",
        "lpt9",
        "dir/COM3/x",
        "NUL ",
        "..\\x",
    };
    for (const char* p : bad) {
        why.clear();
        EXPECT_FALSE(normalize_entry_path(p, out, &why)) << p;
        EXPECT_FALSE(why.empty()) << p;
        EXPECT_TRUE(out.empty()) << p;
    }
    EXPECT_FALSE(normalize_entry_path(std::string("a/b\0c", 5), out, &why));
    EXPECT_NE(why.find("NUL"), std::string::npos);
    // why is optional
    EXPECT_FALSE(normalize_entry_path("../x", out, nullptr));
}

TEST(NormalizePath, AbsurdLengthDoesNotCrash) {
    std::string out;
    std::string huge(1u << 20, 'a');
    EXPECT_TRUE(normalize_entry_path(huge, out));
    EXPECT_EQ(out.size(), huge.size());
    std::string deep;
    for (int i = 0; i < 10000; ++i) deep += "d/";
    EXPECT_TRUE(normalize_entry_path(deep, out));
    EXPECT_EQ(out.size(), 10000u * 2 - 1);
    deep += "../";
    EXPECT_FALSE(normalize_entry_path(deep, out));
}

#ifndef _WIN32

// ---------------------------------------------------------------------------
// DiskSink
// ---------------------------------------------------------------------------

TEST(DiskSink, WritesFileWithBytesHashModeAndTime) {
    TempDir tmp;
    auto sink = open_sink(tmp.path());
    ASSERT_TRUE(sink);
    EXPECT_EQ(sink->root(), tmp.path().string());

    FileMeta meta = regular("etc/motd", 04755);  // setuid must be dropped
    meta.mtime = 1234567890;
    meta.mtime_nsec = 500;
    EntryResult r;
    const Status s = sink->file(meta, bytes_of("hello world\n"), r);
    ASSERT_TRUE(s.ok) << s.error;
    EXPECT_TRUE(r.written);
    EXPECT_FALSE(r.truncated);
    EXPECT_EQ(r.meta.path, "etc/motd");
    EXPECT_EQ(r.host_path, (tmp.path() / "etc/motd").string());
    EXPECT_EQ(r.digests.sha256, kHelloSha256);
    EXPECT_EQ(r.digests.md5, kHelloMd5);
    EXPECT_EQ(r.digests.bytes, 12u);
    EXPECT_EQ(slurp(tmp.path() / "etc/motd"), "hello world\n");
    EXPECT_EQ(sink->files_emitted(), 1u);
    EXPECT_EQ(sink->bytes_emitted(), 12u);

    struct stat st{};
    ASSERT_EQ(::lstat(r.host_path.c_str(), &st), 0);
    EXPECT_TRUE(S_ISREG(st.st_mode));
    EXPECT_EQ(st.st_mode & 07777, 0755u);
    EXPECT_EQ(st.st_mtim.tv_sec, 1234567890);
    EXPECT_EQ(st.st_mtim.tv_nsec, 500);
}

TEST(DiskSink, OptionsOff) {
    TempDir tmp;
    DiskSink::Options o;
    o.hash = false;
    o.preserve_mode = false;
    o.preserve_times = false;
    auto sink = open_sink(tmp.path(), o);
    FileMeta meta = regular("f", 0777);
    meta.mtime = 1000;
    EntryResult r;
    ASSERT_TRUE(sink->file(meta, bytes_of("x"), r).ok);
    EXPECT_TRUE(r.digests.empty());
    struct stat st{};
    ASSERT_EQ(::stat(r.host_path.c_str(), &st), 0);
    EXPECT_NE(st.st_mtim.tv_sec, 1000);
    EXPECT_EQ(st.st_mode & 0777, 0600u);
}

TEST(DiskSink, StreamingWritesConcatenate) {
    TempDir tmp;
    auto sink = open_sink(tmp.path());
    ASSERT_TRUE(sink->begin_file(regular("big.bin")).ok);
    std::string all;
    for (int i = 0; i < 100; ++i) {
        std::string chunk(1000, static_cast<char>('a' + i % 26));
        all += chunk;
        ASSERT_TRUE(sink->write(bytes_of(chunk)).ok);
    }
    ASSERT_TRUE(sink->write({}).ok);
    EntryResult r;
    ASSERT_TRUE(sink->end_file(r).ok);
    EXPECT_EQ(slurp(r.host_path), all);
    EXPECT_EQ(r.digests.sha256, Hasher::of(bytes_of(all)).sha256);
    EXPECT_EQ(sink->bytes_emitted(), 100000u);
}

TEST(DiskSink, RefusesTraversalAndAbsolute) {
    TempDir tmp;
    const fs::path outside =
        tmp.path().parent_path() / (tmp.path().filename().string() + "-outside");
    fs::create_directories(outside);
    auto sink = open_sink(tmp.path() / "root");
    const char* bad[] = {"../x", "a/../../x", "/etc/passwd", "C:\\x", "CON", "..\\x"};
    for (const char* p : bad) {
        const Status s = sink->begin_file(regular(p));
        EXPECT_FALSE(s.ok) << p;
        EXPECT_TRUE(starts_with(s.error, "sink-unsafe-path")) << s.error;
        EntryResult r;
        EXPECT_FALSE(sink->write(bytes_of("x")).ok);  // nothing is open
        EXPECT_FALSE(sink->end_file(r).ok);
    }
    EntryResult r;
    FileMeta d;
    d.path = "../escaped-dir";
    d.kind = EntryKind::Directory;
    EXPECT_FALSE(sink->entry(d, r).ok);
    EXPECT_FALSE(sink->begin_file(regular(std::string("a\0b", 3))).ok);

    EXPECT_TRUE(fs::is_empty(outside));
    EXPECT_FALSE(fs::exists(tmp.path() / "x"));
    EXPECT_FALSE(fs::exists(tmp.path() / "escaped-dir"));
    EXPECT_EQ(sink->files_emitted(), 0u);
    fs::remove_all(outside);
}

TEST(DiskSink, RefusesWritingThroughPlantedSymlink) {
    TempDir tmp;
    const fs::path root = tmp.path() / "root";
    const fs::path outside = tmp.path() / "outside";
    fs::create_directories(root);
    fs::create_directories(outside);
    // Planted before the sink opens (e.g. by a previous run).
    fs::create_directory_symlink(outside, root / "lnk");
    auto sink = open_sink(root);

    Status s = sink->begin_file(regular("lnk/evil"));
    EXPECT_FALSE(s.ok);
    EXPECT_TRUE(starts_with(s.error, "sink-symlink-component")) << s.error;
    EXPECT_TRUE(fs::is_empty(outside));

    // A symlink the image itself supplies is stored verbatim...
    FileMeta link;
    link.path = "usr/lib/escape";
    link.kind = EntryKind::Symlink;
    link.link_target = "../../../outside";
    EntryResult r;
    ASSERT_TRUE(sink->entry(link, r).ok);
    EXPECT_TRUE(r.written);
    EXPECT_EQ(fs::read_symlink(root / "usr/lib/escape").string(), "../../../outside");
    // ...and never followed by a later entry.
    s = sink->begin_file(regular("usr/lib/escape/evil"));
    EXPECT_FALSE(s.ok);
    EXPECT_TRUE(starts_with(s.error, "sink-symlink-component")) << s.error;
    EXPECT_TRUE(fs::is_empty(outside));

    // A file where a directory is needed is refused too.
    ASSERT_TRUE(sink->file(regular("plain"), bytes_of("x"), r).ok);
    s = sink->begin_file(regular("plain/child"));
    EXPECT_FALSE(s.ok);
    EXPECT_TRUE(starts_with(s.error, "sink-not-directory")) << s.error;
    EXPECT_EQ(slurp(root / "plain"), "x");
}

TEST(DiskSink, SymlinkLeafIsNotOverwrittenOrFollowed) {
    TempDir tmp;
    const fs::path outside = tmp.path() / "outside";
    fs::create_directories(outside);
    fs::create_directories(tmp.path() / "root");
    fs::create_symlink(outside / "target", tmp.path() / "root/leaf");
    auto sink = open_sink(tmp.path() / "root");
    EntryResult r;
    ASSERT_TRUE(sink->file(regular("leaf"), bytes_of("data"), r).ok);
    EXPECT_TRUE(has_code(r.diagnostics, "sink-duplicate-path"));
    EXPECT_EQ(fs::path(r.host_path).filename().string(), "leaf~1");
    EXPECT_FALSE(fs::exists(outside / "target"));
    EXPECT_TRUE(fs::is_symlink(tmp.path() / "root/leaf"));
}

TEST(DiskSink, DuplicatePathsGetSuffixes) {
    TempDir tmp;
    auto sink = open_sink(tmp.path());
    EntryResult a, b, c;
    ASSERT_TRUE(sink->file(regular("d/f"), bytes_of("1"), a).ok);
    ASSERT_TRUE(sink->file(regular("d/f"), bytes_of("2"), b).ok);
    ASSERT_TRUE(sink->file(regular("d//f"), bytes_of("3"), c).ok);
    EXPECT_TRUE(a.diagnostics.empty());
    EXPECT_TRUE(has_code(b.diagnostics, "sink-duplicate-path"));
    EXPECT_TRUE(has_code(c.diagnostics, "sink-duplicate-path"));
    EXPECT_EQ(a.host_path, (tmp.path() / "d/f").string());
    EXPECT_EQ(b.host_path, (tmp.path() / "d/f~1").string());
    EXPECT_EQ(c.host_path, (tmp.path() / "d/f~2").string());
    EXPECT_EQ(slurp(a.host_path), "1");
    EXPECT_EQ(slurp(b.host_path), "2");
    EXPECT_EQ(slurp(c.host_path), "3");
    EXPECT_EQ(a.meta.path, "d/f");
    EXPECT_EQ(b.meta.path, "d/f");  // logical path is unchanged
    EXPECT_EQ(sink->files_emitted(), 3u);

    // Directory then file of the same name: file gets a suffix, dir survives.
    FileMeta d;
    d.path = "both";
    d.kind = EntryKind::Directory;
    EntryResult r;
    ASSERT_TRUE(sink->entry(d, r).ok);
    ASSERT_TRUE(sink->file(regular("both"), bytes_of("f"), r).ok);
    EXPECT_TRUE(fs::is_directory(tmp.path() / "both"));
    EXPECT_EQ(slurp(tmp.path() / "both~1"), "f");
    // Symlink duplicate as well.
    FileMeta l;
    l.path = "both";
    l.kind = EntryKind::Symlink;
    l.link_target = "x";
    ASSERT_TRUE(sink->entry(l, r).ok);
    EXPECT_TRUE(has_code(r.diagnostics, "sink-duplicate-path"));
    EXPECT_TRUE(fs::is_symlink(tmp.path() / "both~2"));
}

TEST(DiskSink, LimitMaxFiles) {
    TempDir tmp;
    DiskSink::Options o;
    o.limits.max_files = 2;
    auto sink = open_sink(tmp.path(), o);
    EntryResult r;
    ASSERT_TRUE(sink->file(regular("a"), bytes_of("1"), r).ok);
    FileMeta d;
    d.path = "dir";
    d.kind = EntryKind::Directory;
    ASSERT_TRUE(sink->entry(d, r).ok);
    Status s = sink->begin_file(regular("c"));
    EXPECT_FALSE(s.ok);
    EXPECT_TRUE(starts_with(s.error, "sink-limit-files")) << s.error;
    s = sink->entry(d, r);
    EXPECT_TRUE(starts_with(s.error, "sink-limit-files")) << s.error;
    EXPECT_FALSE(fs::exists(tmp.path() / "c"));
    EXPECT_EQ(sink->files_emitted(), 2u);
}

TEST(DiskSink, LimitMaxFileBytesTruncates) {
    TempDir tmp;
    DiskSink::Options o;
    o.limits.max_file_bytes = 4;
    auto sink = open_sink(tmp.path(), o);
    ASSERT_TRUE(sink->begin_file(regular("t")).ok);
    Status s = sink->write(bytes_of("ab"));
    EXPECT_TRUE(s.ok);
    s = sink->write(bytes_of("cdefgh"));
    EXPECT_FALSE(s.ok);
    EXPECT_TRUE(starts_with(s.error, "sink-limit-file-bytes")) << s.error;
    EXPECT_FALSE(sink->write(bytes_of("more")).ok);
    EntryResult r;
    ASSERT_TRUE(sink->end_file(r).ok);
    EXPECT_TRUE(r.truncated);
    EXPECT_TRUE(r.written);
    EXPECT_TRUE(has_code(r.diagnostics, "sink-limit-file-bytes"));
    EXPECT_EQ(slurp(r.host_path), "abcd");
    EXPECT_EQ(r.digests.bytes, 4u);
    EXPECT_EQ(r.digests.sha256, Hasher::of(bytes_of("abcd")).sha256);
    EXPECT_EQ(sink->bytes_emitted(), 4u);

    // Sink::file reports the limit but still hands back the result.
    s = sink->file(regular("u"), bytes_of("0123456789"), r);
    EXPECT_FALSE(s.ok);
    EXPECT_TRUE(starts_with(s.error, "sink-limit-file-bytes")) << s.error;
    EXPECT_TRUE(r.truncated);
    EXPECT_EQ(slurp(r.host_path), "0123");
}

TEST(DiskSink, LimitMaxBytesAcrossFiles) {
    TempDir tmp;
    DiskSink::Options o;
    o.limits.max_bytes = 6;
    auto sink = open_sink(tmp.path(), o);
    EntryResult r;
    ASSERT_TRUE(sink->file(regular("a"), bytes_of("1234"), r).ok);
    Status s = sink->file(regular("b"), bytes_of("5678"), r);
    EXPECT_FALSE(s.ok);
    EXPECT_TRUE(starts_with(s.error, "sink-limit-bytes")) << s.error;
    EXPECT_TRUE(r.truncated);
    EXPECT_EQ(slurp(r.host_path), "56");
    EXPECT_EQ(sink->bytes_emitted(), 6u);
    // Further data is refused outright; zero-length files still succeed.
    s = sink->file(regular("c"), bytes_of("9"), r);
    EXPECT_TRUE(starts_with(s.error, "sink-limit-bytes")) << s.error;
    EXPECT_EQ(slurp(r.host_path), "");
    EXPECT_TRUE(sink->file(regular("empty"), {}, r).ok);
    EXPECT_FALSE(r.truncated);
}

TEST(DiskSink, VersionsDirectoryLayout) {
    TempDir tmp;
    auto sink = open_sink(tmp.path());
    EntryResult live, old, gone;
    ASSERT_TRUE(sink->file(regular("etc/passwd"), bytes_of("new"), live).ok);
    FileMeta m = regular("etc/passwd");
    m.superseded = true;
    m.version = 3;
    ASSERT_TRUE(sink->file(m, bytes_of("old"), old).ok);
    FileMeta g = regular("etc/shadow");
    g.deleted = true;
    g.version = 0;
    ASSERT_TRUE(sink->file(g, bytes_of("gone"), gone).ok);

    EXPECT_EQ(live.host_path, (tmp.path() / "etc/passwd").string());
    EXPECT_EQ(old.host_path, (tmp.path() / ".omnitrace-versions/etc/passwd/v3").string());
    EXPECT_EQ(gone.host_path, (tmp.path() / ".omnitrace-versions/etc/shadow/v0").string());
    EXPECT_EQ(slurp(live.host_path), "new");
    EXPECT_EQ(slurp(old.host_path), "old");
    EXPECT_EQ(slurp(gone.host_path), "gone");
    EXPECT_EQ(old.meta.path, "etc/passwd");
    EXPECT_TRUE(old.meta.superseded);
    EXPECT_TRUE(old.diagnostics.empty());
    // Same version twice: deduped, not clobbered.
    ASSERT_TRUE(sink->file(m, bytes_of("dup"), old).ok);
    EXPECT_EQ(old.host_path, (tmp.path() / ".omnitrace-versions/etc/passwd/v3~1").string());
    // A superseded directory lands there too.
    FileMeta d;
    d.path = "var/log";
    d.kind = EntryKind::Directory;
    d.superseded = true;
    d.version = 7;
    ASSERT_TRUE(sink->entry(d, old).ok);
    EXPECT_TRUE(fs::is_directory(tmp.path() / ".omnitrace-versions/var/log/v7"));
}

TEST(DiskSink, VersionsDisabled) {
    TempDir tmp;
    DiskSink::Options o;
    o.write_versions = false;
    auto sink = open_sink(tmp.path(), o);
    FileMeta m = regular("f");
    m.deleted = true;
    m.version = 2;
    EntryResult r;
    ASSERT_TRUE(sink->file(m, bytes_of("hello world\n"), r).ok);
    EXPECT_FALSE(r.written);
    EXPECT_TRUE(r.host_path.empty());
    EXPECT_EQ(r.digests.sha256, kHelloSha256);  // still hashed and recorded
    EXPECT_TRUE(has_code(r.diagnostics, "sink-version-skipped"));
    EXPECT_FALSE(fs::exists(tmp.path() / ".omnitrace-versions"));
    EXPECT_FALSE(fs::exists(tmp.path() / "f"));
    EXPECT_EQ(sink->files_emitted(), 1u);
    EXPECT_EQ(sink->bytes_emitted(), 0u);
}

TEST(DiskSink, DirectoriesAndSpecialEntries) {
    TempDir tmp;
    auto sink = open_sink(tmp.path());
    EntryResult r;
    FileMeta d;
    d.path = "a/b/c";
    d.kind = EntryKind::Directory;
    d.mode = 0555;
    ASSERT_TRUE(sink->entry(d, r).ok);
    EXPECT_TRUE(r.written);
    EXPECT_TRUE(fs::is_directory(tmp.path() / "a/b/c"));
    EXPECT_EQ(r.host_path, (tmp.path() / "a/b/c").string());
    // Owner keeps write so extraction can continue beneath it.
    ASSERT_TRUE(sink->file(regular("a/b/c/inside"), bytes_of("x"), r).ok);
    struct stat st{};
    ASSERT_EQ(::stat((tmp.path() / "a/b/c").c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0755u);
    // Re-declaring an existing directory is fine (tar does this constantly).
    ASSERT_TRUE(sink->entry(d, r).ok);

    const EntryKind specials[] = {EntryKind::CharDevice, EntryKind::BlockDevice, EntryKind::Fifo,
                                  EntryKind::Socket, EntryKind::Unknown};
    int i = 0;
    for (EntryKind k : specials) {
        FileMeta s;
        s.path = "dev/node" + std::to_string(i++);
        s.kind = k;
        s.rdev_major = 1;
        s.rdev_minor = 3;
        ASSERT_TRUE(sink->entry(s, r).ok);
        EXPECT_FALSE(r.written);
        EXPECT_TRUE(r.host_path.empty());
        EXPECT_TRUE(has_code(r.diagnostics, "sink-special-skipped"));
        EXPECT_EQ(r.meta.rdev_minor, 3u);
        EXPECT_FALSE(fs::exists(tmp.path() / s.path));
    }
    EXPECT_FALSE(fs::exists(tmp.path() / "dev"));  // parents are not created for skipped entries
    EXPECT_EQ(sink->files_emitted(), 8u);

    // A regular file through entry() is an empty file.
    ASSERT_TRUE(sink->entry(regular("empty"), r).ok);
    EXPECT_TRUE(r.written);
    EXPECT_EQ(fs::file_size(tmp.path() / "empty"), 0u);
}

TEST(DiskSink, SymlinkTargetVerbatimWithTime) {
    TempDir tmp;
    auto sink = open_sink(tmp.path());
    FileMeta l;
    l.path = "bin/sh";
    l.kind = EntryKind::Symlink;
    l.link_target = "/absolute/../weird/./busybox";
    l.mtime = 86400;
    EntryResult r;
    ASSERT_TRUE(sink->entry(l, r).ok);
    EXPECT_EQ(fs::read_symlink(tmp.path() / "bin/sh").string(), "/absolute/../weird/./busybox");
    struct stat st{};
    ASSERT_EQ(::lstat((tmp.path() / "bin/sh").c_str(), &st), 0);
    EXPECT_TRUE(S_ISLNK(st.st_mode));
    EXPECT_EQ(st.st_mtim.tv_sec, 86400);
    EXPECT_EQ(r.meta.link_target, l.link_target);
}

TEST(DiskSink, ProtocolMisuse) {
    TempDir tmp;
    auto sink = open_sink(tmp.path());
    EntryResult r;
    EXPECT_TRUE(starts_with(sink->write(bytes_of("x")).error, "sink-protocol"));
    EXPECT_TRUE(starts_with(sink->end_file(r).error, "sink-protocol"));
    ASSERT_TRUE(sink->begin_file(regular("a")).ok);
    EXPECT_TRUE(starts_with(sink->begin_file(regular("b")).error, "sink-protocol"));
    FileMeta d;
    d.path = "d";
    d.kind = EntryKind::Directory;
    EXPECT_TRUE(starts_with(sink->entry(d, r).error, "sink-protocol"));
    ASSERT_TRUE(sink->end_file(r).ok);
    EXPECT_FALSE(fs::exists(tmp.path() / "b"));
    EXPECT_FALSE(fs::exists(tmp.path() / "d"));
    EXPECT_TRUE(fs::exists(tmp.path() / "a"));
}

TEST(DiskSink, HostileNamesFailCleanly) {
    TempDir tmp;
    auto sink = open_sink(tmp.path());
    EntryResult r;
    // A component longer than NAME_MAX: the OS refuses, we report, nothing crashes.
    const Status s = sink->file(regular(std::string(5000, 'n')), bytes_of("x"), r);
    EXPECT_FALSE(s.ok);
    EXPECT_TRUE(starts_with(s.error, "sink-io-error")) << s.error;
    // Deep nesting is handled one fd at a time.
    std::string deep;
    for (int i = 0; i < 200; ++i) deep += "d/";
    deep += "leaf";
    ASSERT_TRUE(sink->file(regular(deep), bytes_of("deep"), r).ok);
    EXPECT_EQ(slurp(r.host_path), "deep");
    // Absurd declared size is irrelevant: only bytes actually written count.
    FileMeta m = regular("claimed-huge");
    m.size = ~0ull;
    ASSERT_TRUE(sink->file(m, bytes_of("tiny"), r).ok);
    EXPECT_EQ(r.digests.bytes, 4u);
    EXPECT_EQ(sink->files_emitted(), 2u);
}

TEST(DiskSink, OpenFailures) {
    TempDir tmp;
    std::unique_ptr<DiskSink> sink;
    // Root that is a file.
    std::ofstream(tmp.path() / "file").put('x');
    Status s = DiskSink::open((tmp.path() / "file").string(), {}, sink);
    EXPECT_FALSE(s.ok);
    EXPECT_TRUE(starts_with(s.error, "sink-root-invalid")) << s.error;
    EXPECT_FALSE(sink);
    // Missing root is created.
    s = DiskSink::open((tmp.path() / "fresh").string(), {}, sink);
    EXPECT_TRUE(s.ok) << s.error;
    EXPECT_TRUE(fs::is_directory(tmp.path() / "fresh"));
    EXPECT_FALSE(DiskSink::open("", {}, sink).ok);
}

TEST(DiskSink, OutputIsDeterministic) {
    // Two identical entry sequences produce identical trees and results.
    auto run = [](const fs::path& root) {
        auto sink = open_sink(root);
        std::vector<EntryResult> out;
        EntryResult r;
        sink->file(regular("x/a"), bytes_of("1"), r);
        out.push_back(r);
        sink->file(regular("x/a"), bytes_of("2"), r);
        out.push_back(r);
        FileMeta m = regular("x/a");
        m.superseded = true;
        m.version = 9;
        sink->file(m, bytes_of("3"), r);
        out.push_back(r);
        return out;
    };
    TempDir t1, t2;
    const auto a = run(t1.path());
    const auto b = run(t2.path());
    ASSERT_EQ(a.size(), b.size());
    for (std::size_t i = 0; i < a.size(); ++i) {
        EXPECT_EQ(fs::relative(a[i].host_path, t1.path()), fs::relative(b[i].host_path, t2.path()));
        EXPECT_EQ(a[i].digests.sha256, b[i].digests.sha256);
        EXPECT_EQ(a[i].diagnostics.size(), b[i].diagnostics.size());
    }
}

#endif  // !_WIN32

// ---------------------------------------------------------------------------
// ListingSink
// ---------------------------------------------------------------------------

TEST(ListingSink, RecordsWithoutWriting) {
    ListingSink sink(true);
    EntryResult r;
    FileMeta m = regular("./a//b.txt", 0644);
    m.mtime = 42;
    ASSERT_TRUE(sink.file(m, bytes_of("hello world\n"), r).ok);
    EXPECT_FALSE(r.written);
    EXPECT_TRUE(r.host_path.empty());
    EXPECT_EQ(r.meta.path, "a/b.txt");
    EXPECT_EQ(r.meta.mtime, 42);
    EXPECT_EQ(r.digests.sha256, kHelloSha256);
    EXPECT_EQ(r.digests.bytes, 12u);

    FileMeta d;
    d.path = "a";
    d.kind = EntryKind::Directory;
    ASSERT_TRUE(sink.entry(d, r).ok);
    FileMeta l;
    l.path = "l";
    l.kind = EntryKind::Symlink;
    l.link_target = "../../x";
    ASSERT_TRUE(sink.entry(l, r).ok);
    FileMeta dev;
    dev.path = "dev/null";
    dev.kind = EntryKind::CharDevice;
    ASSERT_TRUE(sink.entry(dev, r).ok);
    ASSERT_TRUE(sink.entry(regular("empty"), r).ok);
    EXPECT_TRUE(r.digests.bytes == 0);

    ASSERT_EQ(sink.entries().size(), 5u);
    EXPECT_EQ(sink.entries()[0].meta.path, "a/b.txt");
    EXPECT_EQ(sink.entries()[1].meta.kind, EntryKind::Directory);
    EXPECT_EQ(sink.entries()[2].meta.link_target, "../../x");
    EXPECT_EQ(sink.entries()[3].meta.kind, EntryKind::CharDevice);
    EXPECT_EQ(sink.entries()[4].meta.path, "empty");
    EXPECT_EQ(sink.files_emitted(), 5u);
    EXPECT_EQ(sink.bytes_emitted(), 12u);
}

TEST(ListingSink, HashingOff) {
    ListingSink sink(false);
    EntryResult r;
    ASSERT_TRUE(sink.file(regular("f"), bytes_of("hello world\n"), r).ok);
    EXPECT_TRUE(r.digests.empty());
    EXPECT_EQ(r.digests.bytes, 0u);
    EXPECT_EQ(sink.bytes_emitted(), 12u);
    EXPECT_EQ(sink.entries().size(), 1u);
}

TEST(ListingSink, RefusesUnsafePathsAndEnforcesLimits) {
    Limits lim;
    lim.max_files = 2;
    lim.max_file_bytes = 3;
    ListingSink sink(true, lim);
    EXPECT_EQ(sink.limits().max_files, 2u);
    EntryResult r;
    Status s = sink.begin_file(regular("../x"));
    EXPECT_TRUE(starts_with(s.error, "sink-unsafe-path")) << s.error;
    s = sink.file(regular("big"), bytes_of("abcdef"), r);
    EXPECT_TRUE(starts_with(s.error, "sink-limit-file-bytes")) << s.error;
    EXPECT_TRUE(r.truncated);
    EXPECT_EQ(r.digests.sha256, Hasher::of(bytes_of("abc")).sha256);
    EXPECT_EQ(r.digests.bytes, 3u);
    ASSERT_TRUE(sink.file(regular("ok"), bytes_of("ab"), r).ok);
    s = sink.begin_file(regular("third"));
    EXPECT_TRUE(starts_with(s.error, "sink-limit-files")) << s.error;
    FileMeta d;
    d.path = "d";
    d.kind = EntryKind::Directory;
    EXPECT_TRUE(starts_with(sink.entry(d, r).error, "sink-limit-files"));
    EXPECT_EQ(sink.entries().size(), 2u);
    EXPECT_EQ(sink.files_emitted(), 2u);
    EXPECT_EQ(sink.bytes_emitted(), 5u);
    EXPECT_TRUE(starts_with(sink.write(bytes_of("x")).error, "sink-protocol"));
}

TEST(ListingSink, MaxBytesTotal) {
    Limits lim;
    lim.max_bytes = 5;
    ListingSink sink(false, lim);
    EntryResult r;
    ASSERT_TRUE(sink.file(regular("a"), bytes_of("123"), r).ok);
    const Status s = sink.file(regular("b"), bytes_of("456"), r);
    EXPECT_TRUE(starts_with(s.error, "sink-limit-bytes")) << s.error;
    EXPECT_TRUE(r.truncated);
    EXPECT_TRUE(has_code(r.diagnostics, "sink-limit-bytes"));
    EXPECT_EQ(sink.bytes_emitted(), 5u);
}

}  // namespace
}  // namespace omnitrace
