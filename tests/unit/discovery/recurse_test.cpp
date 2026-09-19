// recurse_test.cpp — analyze(): an in-memory image with an MBR and a SquashFS
// (real, via mksquashfs, when available; a synthetic superblock otherwise)
// becomes the expected evidence graph; a test-supplied reader exercises the
// extraction path into a temp case directory; hostile inputs degrade into
// diagnostics, never crashes.
//
// test_discovery links only the discovery and core libraries, so the real
// SquashFS reader and the YAML round trip (output library) are not reachable
// here; `omnitrace analyze` performs the round-trip check itself after writing
// manifest.yaml, and docs/CLI.md describes the end-to-end smoke.
#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>

#include "helpers.h"
#include "omnitrace/core/Hash.h"
#include "omnitrace/discovery/Recurse.h"

using namespace omnitrace;
using namespace omnitrace::discovery;
using test::Bytes;

namespace {

namespace fsys = std::filesystem;

constexpr std::uint64_t kMiB = 1u << 20;

// ------------------------------------------------------------- image build

void mbr_entry(Bytes& b, std::size_t base, int i, std::uint8_t status, std::uint8_t type,
               std::uint32_t lba, std::uint32_t n) {
    const std::size_t o = base + 446 + static_cast<std::size_t>(i) * 16;
    b[o] = status;
    b[o + 4] = type;
    test::put_u32le(b, o + 8, lba);
    test::put_u32le(b, o + 12, n);
}

// A SquashFS 4.0 superblock that passes the validator without any payload.
Bytes synthetic_squashfs(std::uint64_t bytes_used = 200000) {
    Bytes b(4096, 0);
    test::put_bytes(b, 0, "hsqs");
    test::put_u32le(b, 4, 20);
    test::put_u32le(b, 8, 1700000000);
    test::put_u32le(b, 12, 131072);
    test::put_u32le(b, 16, 1);
    test::put_u16le(b, 20, 1);  // gzip
    test::put_u16le(b, 22, 17);
    test::put_u16le(b, 24, 0xC0);
    test::put_u16le(b, 26, 1);
    test::put_u16le(b, 28, 4);
    test::put_u16le(b, 30, 0);
    test::put_u64le(b, 32, 0);
    test::put_u64le(b, 40, bytes_used);
    test::put_u64le(b, 48, bytes_used - 8);
    test::put_u64le(b, 56, ~0ull);
    test::put_u64le(b, 64, bytes_used - 700);
    test::put_u64le(b, 72, bytes_used - 400);
    test::put_u64le(b, 80, bytes_used - 100);
    test::put_u64le(b, 88, ~0ull);
    return b;
}

fsys::path temp_dir(const char* tag) {
    static std::mt19937_64 rng{std::random_device{}()};
    const fsys::path p = fsys::temp_directory_path() /
                         ("omnitrace-recurse-" + std::string(tag) + "-" + std::to_string(rng()));
    fsys::create_directories(p);
    return p;
}

struct TempDir {
    fsys::path path;
    explicit TempDir(const char* tag) : path(temp_dir(tag)) {}
    ~TempDir() {
        std::error_code ec;
        fsys::remove_all(path, ec);
    }
};

bool have_mksquashfs() {
#ifdef _WIN32
    return false;
#else
    return std::system("command -v mksquashfs >/dev/null 2>&1") == 0;
#endif
}

// Real image built by mksquashfs (uncompressed so no stray magics appear in
// the payload); empty when the tool is missing or fails.
Bytes real_squashfs() {
    if (!have_mksquashfs()) return {};
    TempDir t("mksq");
    const fsys::path src = t.path / "root";
    fsys::create_directories(src / "etc");
    std::ofstream(src / "etc" / "hostname") << "router\n";
    std::ofstream(src / "etc" / "passwd") << "root:x:0:0:root:/root:/bin/sh\n";
    const fsys::path img = t.path / "fs.sqsh";
    const std::string cmd =
        "mksquashfs '" + src.string() + "' '" + img.string() +
        "' -noappend -no-progress -quiet -noI -noD -noF -noX -all-root >/dev/null 2>&1";
    if (std::system(cmd.c_str()) != 0) return {};
    std::ifstream f(img, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

// 6 MiB image: MBR at 0 with p1 = [1 MiB, 5 MiB) (0x83, bootable) and
// p2 = [5 MiB, 5.5 MiB) (0x0c); a SquashFS at 1 MiB inside p1.
struct Layout {
    Bytes bytes;
    std::uint64_t sq_offset = kMiB;
    bool real = false;
};

Layout build_image() {
    Layout l;
    l.bytes.assign(static_cast<std::size_t>(6 * kMiB), 0);
    l.bytes[510] = 0x55;
    l.bytes[511] = 0xAA;
    test::put_u32le(l.bytes, 440, 0x12345678);
    mbr_entry(l.bytes, 0, 0, 0x80, 0x83, 2048, 8192);
    mbr_entry(l.bytes, 0, 1, 0x00, 0x0C, 10240, 1024);
    Bytes sq = real_squashfs();
    l.real = !sq.empty() && sq.size() <= 4 * kMiB;
    if (!l.real) sq = synthetic_squashfs();
    std::copy(sq.begin(), sq.end(), l.bytes.begin() + static_cast<std::ptrdiff_t>(l.sq_offset));
    return l;
}

std::shared_ptr<const Source> source_of(Bytes b, const char* label = "img") {
    return std::make_shared<MemorySource>(std::move(b), label);
}

// ------------------------------------------------------------- fake reader

// Stands in for a filesystem reader: accepts anything starting with "hsqs"
// and emits a small fixed tree through the Sink, exactly like a real reader.
struct FakeBehaviour {
    bool open_fails = false;
    bool unsafe_path = false;
    std::uint64_t extra_files = 0;  // additional regular files, for limit tests
};

class FakeReader final : public fs::FilesystemReader {
   public:
    explicit FakeReader(FakeBehaviour b) : b_(b) {}
    std::string format() const override { return "squashfs"; }
    Status open(const Span& span) override {
        static const std::uint8_t magic[4] = {'h', 's', 'q', 's'};
        if (b_.open_fails) return Status::fail("fake-open-refused");
        if (!span.matches_at(0, std::span<const std::uint8_t>(magic, 4)))
            return Status::fail("fake-bad-magic");
        span_ = span;
        return Status::success();
    }
    fs::FilesystemInfo info() const override {
        fs::FilesystemInfo i;
        i.format = "squashfs";
        i.label = "fake";
        i.block_size = 4096;
        i.compression = "none";
        i.size = span_.size();
        return i;
    }
    Status walk(Sink& sink, const fs::WalkOptions& opts, fs::WalkResult& out) override {
        auto emit = [&](const FileMeta& meta, const std::string& data) {
            EntryResult r;
            Status s;
            if (meta.kind == EntryKind::Regular) {
                std::vector<std::uint8_t> bytes(data.begin(), data.end());
                if (opts.extract_data) {
                    s = sink.file(meta, std::span<const std::uint8_t>(bytes.data(), bytes.size()),
                                  r);
                } else {
                    s = sink.begin_file(meta);
                    if (s) s = sink.end_file(r);
                }
            } else {
                s = sink.entry(meta, r);
            }
            if (!s) {
                out.diagnostics.push_back({Severity::Warning, "fake-entry-refused", s.error});
                if (s.error.find("sink-limit") != std::string::npos) {
                    out.truncated = true;
                    return false;
                }
                return true;
            }
            ++out.entries;
            if (meta.kind == EntryKind::Regular)
                ++out.files;
            else if (meta.kind == EntryKind::Directory)
                ++out.dirs;
            else if (meta.kind == EntryKind::Symlink)
                ++out.symlinks;
            else
                ++out.others;
            out.bytes += r.meta.size;
            out.entries_out.push_back(std::move(r));
            return true;
        };
        FileMeta d;
        d.path = "etc";
        d.kind = EntryKind::Directory;
        d.mode = 0755;
        d.mtime = 1700000000;
        if (!emit(d, "")) return Status::success();
        FileMeta f;
        f.path = "etc/passwd";
        f.kind = EntryKind::Regular;
        f.mode = 0644;
        f.size = 11;
        f.mtime = 1700000001;
        f.inode = 2;
        if (!emit(f, "root:x:0:0\n")) return Status::success();
        FileMeta l;
        l.path = "bin/sh";
        l.kind = EntryKind::Symlink;
        l.mode = 0777;
        l.link_target = "busybox";
        if (!emit(l, "")) return Status::success();
        if (b_.unsafe_path) {
            FileMeta u;
            u.path = "../escape";
            u.kind = EntryKind::Regular;
            u.size = 4;
            emit(u, "pwnd");
        }
        for (std::uint64_t i = 0; i < b_.extra_files; ++i) {
            FileMeta x;
            x.path = "extra/f" + std::to_string(i);
            x.kind = EntryKind::Regular;
            x.size = 1;
            if (!emit(x, "x")) break;
        }
        return Status::success();
    }

   private:
    FakeBehaviour b_;
    Span span_;
};

ReaderLookup fake_lookup(FakeBehaviour b = {}) {
    return [b](const std::string& format) -> std::unique_ptr<fs::FilesystemReader> {
        if (format != "squashfs") return nullptr;
        return std::make_unique<FakeReader>(b);
    };
}

// ----------------------------------------------------------------- helpers

const Node* node_at(const Manifest& m, NodeKind kind, std::uint64_t offset,
                    const std::string& format = {}) {
    for (const Node& n : m.nodes())
        if (n.kind == kind && n.location.offset == offset && (format.empty() || n.format == format))
            return &n;
    return nullptr;
}

bool has_diag(const std::vector<Diagnostic>& ds, const char* code) {
    for (const Diagnostic& d : ds)
        if (d.code == code) return true;
    return false;
}

const Coverage* coverage_for(const Manifest& m, const std::string& format) {
    for (const Coverage& c : m.coverage)
        if (c.format == format) return &c;
    return nullptr;
}

// A stable text rendering of the graph for determinism checks.
std::string dump(const Manifest& m) {
    std::string s;
    for (const Node& n : m.nodes()) {
        s += n.id + "|" + n.parent_id + "|" + node_kind_name(n.kind) + "|" + n.name + "|" +
             n.format + "|" + std::to_string(n.location.offset) + "+" +
             std::to_string(n.location.length) + "|" + std::to_string(n.confidence) + "|" +
             n.digests.sha256 + "|";
        for (const auto& [k, v] : n.attrs) s += k + "=" + v + ",";
        for (const Diagnostic& d : n.diagnostics) s += d.code + ";";
        if (n.file) s += n.file->path;
        s += "\n";
    }
    for (const Coverage& c : m.coverage) s += c.format + ":" + c.status + ":" + c.detail + "\n";
    return s;
}

std::string read_file(const fsys::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

}  // namespace

// ------------------------------------------------------------------- graph

TEST(Analyze, GraphFromMbrAndSquashfsWithoutReader) {
    const Layout l = build_image();
    const auto src = source_of(l.bytes);
    AnalyzeOptions opts;
    opts.extract = false;
    Manifest m;
    Listings listings;
    const Status st = analyze(src, "/evidence/router.bin", opts, m, listings);
    ASSERT_TRUE(st) << st.error;

    // Evidence + image node.
    ASSERT_EQ(m.evidence.size(), 1u);
    EXPECT_EQ(m.evidence[0].id, "e1");
    EXPECT_EQ(m.evidence[0].path, "/evidence/router.bin");
    EXPECT_EQ(m.evidence[0].size, 6 * kMiB);
    const Digests want = Hasher::of(std::span<const std::uint8_t>(l.bytes.data(), l.bytes.size()));
    EXPECT_EQ(m.evidence[0].digests.sha256, want.sha256);
    EXPECT_EQ(m.evidence[0].digests.md5, want.md5);
    ASSERT_GE(m.nodes().size(), 7u);
    const Node& img = m.nodes()[0];
    EXPECT_EQ(img.id, "n000001");
    EXPECT_EQ(img.kind, NodeKind::Image);
    EXPECT_EQ(img.name, "router.bin");
    EXPECT_EQ(img.location.source_id, "mem:img");
    EXPECT_EQ(img.location.length, 6 * kMiB);
    EXPECT_EQ(img.digests.sha256, want.sha256);

    // Partition table and its entries, nested and in byte order.
    const Node& table = m.nodes()[1];
    EXPECT_EQ(table.kind, NodeKind::Partition);
    EXPECT_EQ(table.format, "mbr");
    EXPECT_EQ(table.parent_id, "n000001");
    EXPECT_EQ(table.attrs.at("role"), "table");
    EXPECT_EQ(table.attrs.at("disk_signature"), "0x12345678");
    EXPECT_EQ(table.attrs.at("table"), "mbr-primary");
    // The table finding is the boot sector (validator contract); an older
    // validator sized it to the disk it describes.
    EXPECT_TRUE(table.location.length == 512 || table.location.length == 5 * kMiB + 512 * 1024)
        << table.location.length;
    const Node& p1 = m.nodes()[2];
    EXPECT_EQ(p1.kind, NodeKind::Partition);
    EXPECT_EQ(p1.parent_id, table.id);
    EXPECT_EQ(p1.name, "p1");
    EXPECT_EQ(p1.location.offset, kMiB);
    EXPECT_EQ(p1.location.length, 4 * kMiB);
    EXPECT_EQ(p1.attrs.at("type"), "0x83");
    EXPECT_EQ(p1.attrs.at("type_byte"), "0x83");
    EXPECT_EQ(p1.attrs.at("boot"), "true");
    EXPECT_EQ(p1.attrs.at("index"), "p1");
    EXPECT_EQ(p1.attrs.at("table"), "mbr-primary");
    const Node& p2 = m.nodes()[3];
    EXPECT_EQ(p2.location.offset, 5 * kMiB);
    EXPECT_EQ(p2.location.length, 512 * 1024);
    EXPECT_EQ(p2.attrs.at("type"), "0x0c");
    EXPECT_EQ(p2.attrs.count("boot"), 0u);

    // Gap between the MBR sector and p1, then the filesystem, then the tail gap.
    const Node& gap1 = m.nodes()[4];
    EXPECT_EQ(gap1.kind, NodeKind::Region);
    EXPECT_EQ(gap1.location.offset, 512u);
    EXPECT_EQ(gap1.location.length, kMiB - 512);
    EXPECT_EQ(gap1.parent_id, "n000001");
    EXPECT_EQ(gap1.attrs.at("fill"), "0x00");
    EXPECT_TRUE(has_diag(gap1.diagnostics, "region-unidentified"));

    const Node* sq = node_at(m, NodeKind::Filesystem, kMiB, "squashfs");
    ASSERT_NE(sq, nullptr);
    EXPECT_EQ(sq->id, "n000006");
    EXPECT_EQ(sq->parent_id, p1.id) << "the filesystem sits inside p1";
    EXPECT_EQ(sq->attrs.at("version"), "4.0");
    EXPECT_EQ(sq->attrs.at("signature"), "squashfs-le");
    EXPECT_GE(sq->confidence, 60);
    EXPECT_TRUE(has_diag(sq->diagnostics, "analyze-no-reader"));

    const Node* tail = node_at(m, NodeKind::Region, 5 * kMiB + 512 * 1024);
    ASSERT_NE(tail, nullptr);
    EXPECT_EQ(tail->location.length, 512 * 1024u);
    EXPECT_EQ(tail->parent_id, "n000001");

    // No reader: coverage says so, nothing is listed.
    const Coverage* cov = coverage_for(m, "squashfs");
    ASSERT_NE(cov, nullptr);
    EXPECT_EQ(cov->status, "unsupported");
    EXPECT_EQ(cov->detail, "no reader registered");
    EXPECT_TRUE(listings.empty());
    EXPECT_EQ(m.count(NodeKind::File), 0u);
    EXPECT_EQ(m.count(NodeKind::Partition), 3u);

    // Unclaimed space inside a partition is a Region under that partition:
    // the rest of p1 after the squashfs, and the whole of (empty) p2.
    EXPECT_EQ(m.count(NodeKind::Region), 4u);
    const Node* p1_tail = node_at(m, NodeKind::Region, kMiB + sq->location.length);
    ASSERT_NE(p1_tail, nullptr);
    EXPECT_EQ(p1_tail->parent_id, p1.id);
    EXPECT_EQ(p1_tail->location.length, 4 * kMiB - sq->location.length);
    const Node* p2_all = node_at(m, NodeKind::Region, 5 * kMiB);
    ASSERT_NE(p2_all, nullptr);
    EXPECT_EQ(p2_all->parent_id, p2.id);
    EXPECT_EQ(p2_all->location.length, 512 * 1024u);
    EXPECT_EQ(p2_all->attrs.at("fill"), "0x00");

    // child_ids agree with parent_id links.
    EXPECT_EQ(table.child_ids, (std::vector<std::string>{p1.id, p2.id}));
    EXPECT_EQ(m.find(p1.id)->child_ids, (std::vector<std::string>{sq->id, p1_tail->id}));
    EXPECT_EQ(m.find(p2.id)->child_ids, std::vector<std::string>{p2_all->id});
}

TEST(Analyze, ContainerWithoutReaderIsCoveredNotSilent) {
    // Rule 7: a recognised container that is not opened (no container reader
    // yet) must leave a Coverage row and a Diagnostic, never a bare node.
    Bytes b(64 * 1024, 0);
    const std::uint8_t gz[] = {0x1F, 0x8B, 0x08, 0x00, 0,
                               0,    0,    0,    0x00, 0x03};  // gzip member header, OS unix
    std::copy(std::begin(gz), std::end(gz), b.begin() + 16 * 1024);
    AnalyzeOptions opts;
    opts.extract = false;
    Manifest m;
    Listings listings;
    const Status st = analyze(source_of(b), "img.bin", opts, m, listings);
    ASSERT_TRUE(st) << st.error;
    const Node* gzn = node_at(m, NodeKind::Container, 16 * 1024, "gzip");
    ASSERT_NE(gzn, nullptr);
    EXPECT_TRUE(has_diag(gzn->diagnostics, "analyze-no-reader"));
    const Coverage* cov = coverage_for(m, "gzip");
    ASSERT_NE(cov, nullptr);
    EXPECT_EQ(cov->status, "unsupported");
    EXPECT_EQ(cov->detail, "no container reader registered");
}

// -------------------------------------------------------------- extraction

TEST(Analyze, WalksFilesystemToDisk) {
    const Layout l = build_image();
    const auto src = source_of(l.bytes);
    TempDir out("extract");
    AnalyzeOptions opts;
    opts.out_dir = out.path.string();
    opts.open_reader = fake_lookup();
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(src, "router.bin", opts, m, listings));

    const Node* sq = node_at(m, NodeKind::Filesystem, kMiB, "squashfs");
    ASSERT_NE(sq, nullptr);
    EXPECT_EQ(sq->attrs.at("label"), "fake");
    EXPECT_EQ(sq->attrs.at("entries"), "3");
    EXPECT_EQ(sq->attrs.at("files"), "1");
    EXPECT_EQ(sq->attrs.at("dirs"), "1");
    EXPECT_EQ(sq->attrs.at("symlinks"), "1");
    EXPECT_EQ(sq->attrs.count("truncated"), 0u);
    EXPECT_EQ(sq->name, "squashfs");

    // Files landed under <out>/filesystems/<id>/files.
    const fsys::path root = out.path / "filesystems" / sq->id / "files";
    EXPECT_TRUE(fsys::is_directory(root / "etc"));
    EXPECT_EQ(read_file(root / "etc" / "passwd"), "root:x:0:0\n");
    EXPECT_TRUE(fsys::is_symlink(root / "bin" / "sh"));

    // One File node per entry, parented to the filesystem.
    const auto files = m.children_of(sq->id);
    ASSERT_EQ(files.size(), 3u);
    EXPECT_EQ(files[0]->file->path, "etc");
    EXPECT_EQ(files[0]->name, "etc");
    EXPECT_EQ(files[1]->file->path, "etc/passwd");
    EXPECT_EQ(files[1]->name, "passwd");
    EXPECT_EQ(files[1]->kind, NodeKind::File);
    EXPECT_EQ(files[1]->location.offset, sq->location.offset);
    EXPECT_EQ(files[1]->location.length, sq->location.length);
    const std::string content = "root:x:0:0\n";
    const Digests want = Hasher::of(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(content.data()), content.size()));
    EXPECT_EQ(files[1]->digests.sha256, want.sha256);
    EXPECT_EQ(files[1]->file->mode, 0644u);
    EXPECT_EQ(files[2]->file->link_target, "busybox");
    EXPECT_EQ(m.count(NodeKind::File), 3u);

    ASSERT_EQ(listings.size(), 1u);
    EXPECT_EQ(listings[0].first, sq->id);
    ASSERT_EQ(listings[0].second.size(), 3u);
    EXPECT_TRUE(listings[0].second[1].written);
    EXPECT_FALSE(listings[0].second[1].host_path.empty());
    EXPECT_EQ(listings[0].second[1].digests.sha256, want.sha256);

    const Coverage* cov = coverage_for(m, "squashfs");
    ASSERT_NE(cov, nullptr);
    EXPECT_EQ(cov->status, "supported");
}

TEST(Analyze, ListingOnlyWritesNothing) {
    const Layout l = build_image();
    TempDir out("listing");
    AnalyzeOptions opts;
    opts.out_dir = out.path.string();
    opts.extract = false;
    opts.open_reader = fake_lookup();
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(l.bytes), "router.bin", opts, m, listings));
    EXPECT_FALSE(fsys::exists(out.path / "filesystems"));
    ASSERT_EQ(listings.size(), 1u);
    ASSERT_EQ(listings[0].second.size(), 3u);
    EXPECT_FALSE(listings[0].second[1].written);
    EXPECT_TRUE(listings[0].second[1].host_path.empty());
    EXPECT_EQ(m.count(NodeKind::File), 3u);
    EXPECT_EQ(coverage_for(m, "squashfs")->status, "supported");
}

TEST(Analyze, Deterministic) {
    const Layout l = build_image();
    TempDir a("det-a");
    TempDir b("det-b");
    std::string dumps[2];
    for (int i = 0; i < 2; ++i) {
        AnalyzeOptions opts;
        opts.out_dir = (i == 0 ? a : b).path.string();
        opts.open_reader = fake_lookup();
        Manifest m;
        Listings listings;
        ASSERT_TRUE(analyze(source_of(l.bytes), "router.bin", opts, m, listings));
        dumps[i] = dump(m);
    }
    EXPECT_EQ(dumps[0], dumps[1]);
    EXPECT_NE(dumps[0].find("n000006|n000003|filesystem|squashfs|squashfs|1048576+"),
              std::string::npos)
        << dumps[0];
}

// ----------------------------------------------------------------- hostile

TEST(Analyze, CallerErrors) {
    Manifest m;
    Listings listings;
    AnalyzeOptions opts;
    EXPECT_FALSE(analyze(nullptr, "x", opts, m, listings));
    EXPECT_TRUE(m.nodes().empty());
    opts.extract = true;
    opts.out_dir.clear();
    EXPECT_FALSE(analyze(source_of(Bytes(4096, 0)), "x", opts, m, listings));
    EXPECT_TRUE(m.nodes().empty());
}

TEST(Analyze, EmptyAndTinyImages) {
    AnalyzeOptions opts;
    opts.extract = false;
    {
        Manifest m;
        Listings listings;
        ASSERT_TRUE(analyze(source_of(Bytes{}, "empty"), "empty.bin", opts, m, listings));
        ASSERT_EQ(m.nodes().size(), 1u);
        EXPECT_EQ(m.nodes()[0].kind, NodeKind::Image);
        EXPECT_EQ(m.nodes()[0].location.length, 0u);
        EXPECT_TRUE(has_diag(m.nodes()[0].diagnostics, "analyze-empty-image"));
        EXPECT_EQ(m.evidence[0].digests.bytes, 0u);
    }
    {
        // 100 erased bytes: below the region threshold by default...
        Manifest m;
        Listings listings;
        ASSERT_TRUE(analyze(source_of(Bytes(100, 0xFF), "ff"), "ff.bin", opts, m, listings));
        EXPECT_EQ(m.nodes().size(), 1u);
        // ...and one erased Region when the threshold allows it.
        AnalyzeOptions small = opts;
        small.min_region_bytes = 1;
        Manifest m2;
        ASSERT_TRUE(analyze(source_of(Bytes(100, 0xFF), "ff"), "ff.bin", small, m2, listings));
        ASSERT_EQ(m2.nodes().size(), 2u);
        EXPECT_EQ(m2.nodes()[1].kind, NodeKind::Region);
        EXPECT_EQ(m2.nodes()[1].location.length, 100u);
        EXPECT_EQ(m2.nodes()[1].attrs.at("fill"), "0xff");
    }
}

TEST(Analyze, PartitionPastEndIsClamped) {
    Bytes b(512 * 64, 0);
    b[510] = 0x55;
    b[511] = 0xAA;
    mbr_entry(b, 0, 0, 0x00, 0x83, 8, 0xFFFFFFF0u);  // 2 TiB claimed in a 32 KiB image
    AnalyzeOptions opts;
    opts.extract = false;
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(b), "trunc.bin", opts, m, listings));
    const Node* p1 = node_at(m, NodeKind::Partition, 8 * 512);
    ASSERT_NE(p1, nullptr);
    EXPECT_EQ(p1->location.length, b.size() - 8 * 512);
    EXPECT_EQ(p1->attrs.at("claimed_size"), std::to_string(0xFFFFFFF0ull * 512));
    EXPECT_TRUE(has_diag(p1->diagnostics, "partition-truncated"));
    // The 3.5 KiB before p1 is under the threshold: no region there. The
    // clamped partition itself is empty, so it holds one zero-filled Region.
    EXPECT_EQ(m.count(NodeKind::Region), 1u);
    const Node* inside = node_at(m, NodeKind::Region, 8 * 512);
    ASSERT_NE(inside, nullptr);
    EXPECT_EQ(inside->parent_id, p1->id);
    EXPECT_EQ(inside->location.length, p1->location.length);
    EXPECT_EQ(m.count(NodeKind::Partition), 2u);
}

TEST(Analyze, ReaderThatRefusesToOpen) {
    const Layout l = build_image();
    TempDir out("refuse");
    AnalyzeOptions opts;
    opts.out_dir = out.path.string();
    opts.open_reader = fake_lookup({true, false, 0});
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(l.bytes), "router.bin", opts, m, listings));
    const Node* sq = node_at(m, NodeKind::Filesystem, kMiB, "squashfs");
    ASSERT_NE(sq, nullptr);
    EXPECT_TRUE(has_diag(sq->diagnostics, "analyze-open-failed"));
    EXPECT_EQ(m.count(NodeKind::File), 0u);
    EXPECT_TRUE(listings.empty());
    const Coverage* cov = coverage_for(m, "squashfs");
    ASSERT_NE(cov, nullptr);
    EXPECT_EQ(cov->status, "partial");
    EXPECT_NE(cov->detail.find("fake-open-refused"), std::string::npos);
    EXPECT_FALSE(fsys::exists(out.path / "filesystems" / sq->id / "files"));
}

TEST(Analyze, UnsafeEntryPathNeverEscapesTheCaseDirectory) {
    const Layout l = build_image();
    TempDir out("escape");
    AnalyzeOptions opts;
    opts.out_dir = out.path.string();
    opts.open_reader = fake_lookup({false, true, 0});
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(l.bytes), "router.bin", opts, m, listings));
    const Node* sq = node_at(m, NodeKind::Filesystem, kMiB, "squashfs");
    ASSERT_NE(sq, nullptr);
    EXPECT_FALSE(fsys::exists(out.path / "escape"));
    EXPECT_FALSE(fsys::exists(out.path / "filesystems" / "escape"));
    EXPECT_FALSE(fsys::exists(out.path / "filesystems" / sq->id / "escape"));
    EXPECT_TRUE(has_diag(sq->diagnostics, "fake-entry-refused"));
    EXPECT_EQ(m.count(NodeKind::File), 3u);
}

TEST(Analyze, RunWideFileLimitSpansFilesystems) {
    // Two squashfs instances (one per partition); max_files = 4 lets the first
    // walk finish (3 entries) and stops the second after one.
    Layout l = build_image();
    const Bytes sq = synthetic_squashfs();
    std::copy(sq.begin(), sq.end(), l.bytes.begin() + static_cast<std::ptrdiff_t>(5 * kMiB));
    TempDir out("limit");
    AnalyzeOptions opts;
    opts.out_dir = out.path.string();
    opts.open_reader = fake_lookup();
    opts.limits.max_files = 4;
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(l.bytes), "router.bin", opts, m, listings));
    const Node* first = node_at(m, NodeKind::Filesystem, kMiB, "squashfs");
    const Node* second = node_at(m, NodeKind::Filesystem, 5 * kMiB, "squashfs");
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(first->attrs.at("entries"), "3");
    EXPECT_EQ(first->attrs.count("truncated"), 0u);
    EXPECT_EQ(second->attrs.at("entries"), "1");
    EXPECT_EQ(second->attrs.at("truncated"), "true");
    EXPECT_EQ(m.count(NodeKind::File), 4u);
    EXPECT_EQ(coverage_for(m, "squashfs")->status, "partial");
    ASSERT_EQ(listings.size(), 2u);

    // With the budget already spent, a third filesystem is not walked at all.
    AnalyzeOptions none = opts;
    none.limits.max_files = 3;
    Manifest m2;
    Listings l2;
    TempDir out2("limit2");
    none.out_dir = out2.path.string();
    ASSERT_TRUE(analyze(source_of(l.bytes), "router.bin", none, m2, l2));
    const Node* s2 = node_at(m2, NodeKind::Filesystem, 5 * kMiB, "squashfs");
    ASSERT_NE(s2, nullptr);
    EXPECT_TRUE(has_diag(s2->diagnostics, "analyze-limit-files"));
    EXPECT_EQ(m2.count(NodeKind::File), 3u);
    EXPECT_EQ(l2.size(), 1u);
}

TEST(Analyze, DepthLimitZeroStillAnalyzesTheImage) {
    const Layout l = build_image();
    AnalyzeOptions opts;
    opts.extract = false;
    opts.limits.max_depth = 0;  // the image itself is depth 0
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(l.bytes), "router.bin", opts, m, listings));
    EXPECT_NE(node_at(m, NodeKind::Filesystem, kMiB, "squashfs"), nullptr);
    EXPECT_FALSE(has_diag(m.diagnostics, "analyze-limit-depth"));
}

TEST(Analyze, RealSquashfsFixtureWhenAvailable) {
    const Layout l = build_image();
    if (!l.real) GTEST_SKIP() << "mksquashfs not available; synthetic superblock used elsewhere";
    AnalyzeOptions opts;
    opts.extract = false;
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(l.bytes), "router.bin", opts, m, listings));
    const Node* sq = node_at(m, NodeKind::Filesystem, kMiB, "squashfs");
    ASSERT_NE(sq, nullptr);
    EXPECT_GE(sq->confidence, 85) << "a real image should be at least Consistent";
    EXPECT_GT(sq->location.length, 0u);
    EXPECT_LE(sq->location.length, 4 * kMiB);
    EXPECT_EQ(sq->attrs.at("compression"), "gzip");
}

// ---------------------------------------------------------- partitions/GPT

namespace {

// Mixed-endian GUID bytes for "aabbccdd-eeff-0011-2233-445566778899".
void put_guid(Bytes& b, std::size_t off, const std::string& text) {
    std::string h;
    for (const char ch : text)
        if (ch != '-') h.push_back(ch);
    ASSERT_EQ(h.size(), 32u);
    std::uint8_t raw[16];
    for (std::size_t i = 0; i < 16; ++i)
        raw[i] = static_cast<std::uint8_t>(std::stoul(h.substr(2 * i, 2), nullptr, 16));
    static const std::size_t order[16] = {3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15};
    for (std::size_t i = 0; i < 16; ++i) b[off + i] = raw[order[i]];
}

void put_utf16(Bytes& b, std::size_t off, const std::string& ascii) {
    for (std::size_t i = 0; i < ascii.size() && i < 36; ++i)
        test::put_u16le(b, off + 2 * i, static_cast<std::uint16_t>(ascii[i]));
}

struct GptPart {
    std::string type_guid, unique_guid, label;
    std::uint64_t first_lba = 0, last_lba = 0;
};

const char* kRootfsType = "0fc63daf-8483-4772-8e79-3d69d8477de4";
const char* kDataType = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
const char* kDiskGuid = "6f1a2c3e-0001-4d5e-8f90-0123456789ab";

// Protective MBR at LBA 0, primary header at LBA 1 + entries at LBA 2, backup
// entries at (last-32) and backup header at the last LBA. CRCs are real.
void write_gpt(Bytes& b, const std::vector<GptPart>& parts) {
    const std::uint64_t sectors = b.size() / 512;
    const std::uint64_t last = sectors - 1;
    b[510] = 0x55;
    b[511] = 0xAA;
    mbr_entry(b, 0, 0, 0x00, 0xEE, 1, static_cast<std::uint32_t>(last));

    auto write_entries = [&](std::size_t off) {
        for (std::size_t i = 0; i < parts.size(); ++i) {
            const std::size_t eo = off + i * 128;
            put_guid(b, eo, parts[i].type_guid);
            put_guid(b, eo + 16, parts[i].unique_guid);
            test::put_u64le(b, eo + 32, parts[i].first_lba);
            test::put_u64le(b, eo + 40, parts[i].last_lba);
            put_utf16(b, eo + 56, parts[i].label);
        }
    };
    auto write_header = [&](std::size_t off, std::uint64_t my, std::uint64_t alt,
                            std::uint64_t entry_lba) {
        test::put_bytes(b, off, "EFI PART");
        test::put_u32le(b, off + 8, 0x00010000);
        test::put_u32le(b, off + 12, 92);
        test::put_u64le(b, off + 24, my);
        test::put_u64le(b, off + 32, alt);
        test::put_u64le(b, off + 40, 34);
        test::put_u64le(b, off + 48, last - 33);
        put_guid(b, off + 56, kDiskGuid);
        test::put_u64le(b, off + 72, entry_lba);
        test::put_u32le(b, off + 80, 128);
        test::put_u32le(b, off + 84, 128);
        test::put_u32le(b, off + 88,
                        test::crc_zlib(b, static_cast<std::size_t>(entry_lba * 512), 128 * 128));
        test::put_u32le(b, off + 16, 0);
        test::put_u32le(b, off + 16, test::crc_zlib(b, off, 92));
    };
    write_entries(2 * 512);
    write_entries(static_cast<std::size_t>((last - 32) * 512));
    write_header(512, 1, last, 2);
    write_header(static_cast<std::size_t>(last * 512), last, 1, last - 32);
}

// 8 MiB GPT disk: p1 "rootfs" [1 MiB, 5 MiB) holding a real squashfs (empty
// when mksquashfs is missing), p2 "data" [5 MiB, 7 MiB) empty.
struct GptLayout {
    Bytes bytes;
    Bytes squash;  // the image placed at 1 MiB (empty: synthetic superblock used)
    bool real = false;
};

GptLayout build_gpt_image() {
    GptLayout l;
    l.bytes.assign(static_cast<std::size_t>(8 * kMiB), 0);
    write_gpt(l.bytes,
              {{kRootfsType, "6f1a2c3e-1001-4d5e-8f90-0123456789ab", "rootfs", 2048, 10239},
               {kDataType, "6f1a2c3e-1002-4d5e-8f90-0123456789ab", "data", 10240, 14335}});
    l.squash = real_squashfs();
    l.real = !l.squash.empty() && l.squash.size() <= 4 * kMiB;
    if (!l.real) l.squash = synthetic_squashfs();
    std::copy(l.squash.begin(), l.squash.end(),
              l.bytes.begin() + static_cast<std::ptrdiff_t>(kMiB));
    return l;
}

// The validator contract this driver codes against (partition-table findings
// sized to the table, attrs "table", never absorbing the findings inside).
// The builtin scan is normalised to it so the test holds whether or not the
// validator work has landed in this checkout.
Scanner contract_scanner() {
    return [](const Span& span) {
        std::vector<Finding> out = scan(span, SignatureSet::builtin());
        std::vector<Finding> hoisted;
        for (Finding& f : out) {
            if (f.category != "partition-table") continue;
            for (Finding& alt : f.also_matched) hoisted.push_back(std::move(alt));
            f.also_matched.clear();
            if (f.attrs.count("table")) continue;
            if (f.format == "mbr") {
                f.attrs["table"] = "mbr-primary";
                f.size = 512;
            } else if (f.attrs.count("backup")) {
                f.attrs["table"] = "gpt-backup";
            } else {
                f.attrs["table"] = "gpt-primary";
                f.size = 2 * 512 + 128 * 128;
            }
        }
        for (Finding& h : hoisted) out.push_back(std::move(h));
        std::stable_sort(out.begin(), out.end(),
                         [](const Finding& a, const Finding& b) { return a.offset < b.offset; });
        return out;
    };
}

Digests sha_of(const Bytes& b, std::uint64_t off, std::uint64_t len) {
    return Hasher::of(std::span<const std::uint8_t>(b.data() + off, static_cast<std::size_t>(len)));
}

const Node* node_named(const Manifest& m, NodeKind kind, const std::string& name) {
    for (const Node& n : m.nodes())
        if (n.kind == kind && n.name == name) return &n;
    return nullptr;
}

}  // namespace

TEST(Analyze, GptPartitionsNamedFromLabelsAndCarved) {
    const GptLayout l = build_gpt_image();
    TempDir out("gpt");
    AnalyzeOptions opts;
    opts.out_dir = out.path.string();
    opts.open_reader = fake_lookup();
    opts.scanner = contract_scanner();
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(l.bytes), "emmc.bin", opts, m, listings));

    // One table node per used table: the protective MBR and the primary GPT
    // (the backup is folded into the primary).
    const Node* gpt = nullptr;
    const Node* mbr = nullptr;
    for (const Node& n : m.nodes()) {
        if (n.kind != NodeKind::Partition || n.attrs.count("role") == 0) continue;
        if (n.format == "gpt") gpt = &n;
        if (n.format == "mbr") mbr = &n;
    }
    ASSERT_NE(gpt, nullptr);
    ASSERT_NE(mbr, nullptr);
    EXPECT_EQ(gpt->attrs.at("table"), "gpt-primary");
    EXPECT_EQ(gpt->attrs.at("backup_lba"), std::to_string(8 * kMiB / 512 - 1));
    EXPECT_EQ(gpt->attrs.at("backup_header"), "ok");
    EXPECT_EQ(mbr->attrs.at("table"), "mbr-primary");
    EXPECT_EQ(m.count(NodeKind::Partition), 5u);  // 2 tables, 1 protective, 2 entries

    const Node* prot = node_at(m, NodeKind::Partition, 512, "mbr");
    ASSERT_NE(prot, nullptr);
    EXPECT_EQ(prot->attrs.at("protective"), "true");
    EXPECT_EQ(prot->attrs.count("carved_path"), 0u) << "a protective entry is not a partition";

    const Node* rootfs = node_named(m, NodeKind::Partition, "rootfs");
    const Node* data = node_named(m, NodeKind::Partition, "data");
    ASSERT_NE(rootfs, nullptr);
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(rootfs->parent_id, gpt->id);
    EXPECT_EQ(rootfs->location.offset, kMiB);
    EXPECT_EQ(rootfs->location.length, 4 * kMiB);
    EXPECT_EQ(rootfs->attrs.at("type_guid"), kRootfsType);
    EXPECT_EQ(rootfs->attrs.at("unique_guid"), "6f1a2c3e-1001-4d5e-8f90-0123456789ab");
    EXPECT_EQ(rootfs->attrs.at("index"), "p1");
    EXPECT_EQ(rootfs->attrs.at("table"), "gpt-primary");
    EXPECT_EQ(rootfs->attrs.at("label"), "rootfs");
    EXPECT_EQ(data->location.offset, 5 * kMiB);
    EXPECT_EQ(data->location.length, 2 * kMiB);
    EXPECT_EQ(data->attrs.at("type_guid"), kDataType);

    // The filesystem is nested under its partition and was walked.
    const Node* sq = node_at(m, NodeKind::Filesystem, kMiB, "squashfs");
    ASSERT_NE(sq, nullptr);
    EXPECT_EQ(sq->parent_id, rootfs->id);
    EXPECT_EQ(sq->attrs.at("entries"), "3");
    EXPECT_EQ(sq->attrs.at("carved_in"), "partitions/p1-rootfs.bin");
    EXPECT_EQ(sq->attrs.count("carved_path"), 0u) << "the partition file is its carve";

    // Carved files: GPT label names, streamed bytes, digests on the node.
    const fsys::path pdir = out.path / "partitions";
    EXPECT_EQ(rootfs->attrs.at("carved_path"), "partitions/p1-rootfs.bin");
    EXPECT_EQ(data->attrs.at("carved_path"), "partitions/p2-data.bin");
    ASSERT_TRUE(fsys::is_regular_file(pdir / "p1-rootfs.bin"));
    ASSERT_TRUE(fsys::is_regular_file(pdir / "p2-data.bin"));
    EXPECT_EQ(fsys::file_size(pdir / "p1-rootfs.bin"), 4 * kMiB);
    EXPECT_EQ(fsys::file_size(pdir / "p2-data.bin"), 2 * kMiB);
    const Digests want1 = sha_of(l.bytes, kMiB, 4 * kMiB);
    const Digests want2 = sha_of(l.bytes, 5 * kMiB, 2 * kMiB);
    EXPECT_EQ(rootfs->digests.sha256, want1.sha256);
    EXPECT_EQ(rootfs->digests.md5, want1.md5);
    EXPECT_EQ(rootfs->digests.bytes, 4 * kMiB);
    EXPECT_EQ(data->digests.sha256, want2.sha256);
    Digests on_disk;
    ASSERT_TRUE(hash_file((pdir / "p1-rootfs.bin").string(), on_disk));
    EXPECT_EQ(on_disk.sha256, want1.sha256);
    const std::string p1_head = read_file(pdir / "p1-rootfs.bin").substr(0, 4);
    EXPECT_EQ(p1_head, "hsqs");

    // mount.sh lists the partition whose first byte is a squashfs, typed.
    const std::string script = read_file(pdir / "mount.sh");
    EXPECT_NE(script.find("PARTITION_NAMES=(\"p1-rootfs.bin\")"), std::string::npos) << script;
    EXPECT_NE(script.find("PARTITION_TYPES=(\"squashfs\")"), std::string::npos) << script;
    EXPECT_EQ(script.find("p2-data.bin\""), std::string::npos)
        << "empty partition is not mountable";
    EXPECT_NE(script.find("getopts 'muht'"), std::string::npos);
    EXPECT_EQ(script, mount_script_text(m));

    const Coverage* cov = coverage_for(m, "carve");
    ASSERT_NE(cov, nullptr);
    EXPECT_EQ(cov->status, "supported");

    // Empty p2 became one Region under it; nothing else was invented.
    const Node* p2_gap = node_at(m, NodeKind::Region, 5 * kMiB);
    ASSERT_NE(p2_gap, nullptr);
    EXPECT_EQ(p2_gap->parent_id, data->id);
}

TEST(Analyze, MaxCarveBytesSkipsLargePartitionsVisibly) {
    const GptLayout l = build_gpt_image();
    TempDir out("carve-limit");
    AnalyzeOptions opts;
    opts.out_dir = out.path.string();
    opts.extract = false;
    opts.scanner = contract_scanner();
    opts.max_carve_bytes = 3 * kMiB;  // p1 is 4 MiB, p2 is 2 MiB
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(l.bytes), "emmc.bin", opts, m, listings));
    const Node* rootfs = node_named(m, NodeKind::Partition, "rootfs");
    const Node* data = node_named(m, NodeKind::Partition, "data");
    ASSERT_NE(rootfs, nullptr);
    ASSERT_NE(data, nullptr);
    EXPECT_FALSE(fsys::exists(out.path / "partitions" / "p1-rootfs.bin"));
    EXPECT_TRUE(fsys::exists(out.path / "partitions" / "p2-data.bin"));
    EXPECT_EQ(rootfs->attrs.count("carved_path"), 0u);
    EXPECT_TRUE(rootfs->digests.empty());
    EXPECT_TRUE(has_diag(rootfs->diagnostics, "carve-limit-bytes"));
    EXPECT_EQ(rootfs->attrs.at("carve_skipped"), "max-carve-bytes");
    EXPECT_EQ(data->attrs.at("carved_path"), "partitions/p2-data.bin");
    const Coverage* cov = coverage_for(m, "carve");
    ASSERT_NE(cov, nullptr);
    EXPECT_EQ(cov->status, "partial");
    EXPECT_NE(cov->detail.find("p1-rootfs.bin skipped: 4194304 exceeds --max-carve-bytes"),
              std::string::npos)
        << cov->detail;
    // The skipped partition is not in mount.sh either.
    const std::string script = read_file(out.path / "partitions" / "mount.sh");
    EXPECT_EQ(script.find("p1-rootfs.bin"), std::string::npos);
}

TEST(Analyze, NoTableNestedFindIsCarvedByOffsetAndFormat) {
    Bytes b(static_cast<std::size_t>(4 * kMiB), 0);
    Bytes sq = real_squashfs();
    if (sq.empty() || sq.size() > 2 * kMiB) sq = synthetic_squashfs();
    std::copy(sq.begin(), sq.end(), b.begin() + static_cast<std::ptrdiff_t>(kMiB));
    TempDir out("notable");
    AnalyzeOptions opts;
    opts.out_dir = out.path.string();
    opts.extract = false;
    opts.open_reader = fake_lookup();
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(b), "spi.bin", opts, m, listings));
    EXPECT_EQ(m.count(NodeKind::Partition), 0u);
    const Node* fsn = node_at(m, NodeKind::Filesystem, kMiB, "squashfs");
    ASSERT_NE(fsn, nullptr);
    EXPECT_EQ(fsn->parent_id, m.nodes()[0].id);
    EXPECT_EQ(fsn->attrs.at("carved_path"), "partitions/0x00100000-squashfs.bin");
    const fsys::path file = out.path / "partitions" / "0x00100000-squashfs.bin";
    ASSERT_TRUE(fsys::is_regular_file(file));
    EXPECT_EQ(fsys::file_size(file), fsn->location.length);
    const Digests want = sha_of(b, kMiB, fsn->location.length);
    EXPECT_EQ(fsn->digests.sha256, want.sha256);
    const std::string script = read_file(out.path / "partitions" / "mount.sh");
    EXPECT_NE(script.find("PARTITION_NAMES=(\"0x00100000-squashfs.bin\")"), std::string::npos)
        << script;
    EXPECT_NE(script.find("PARTITION_TYPES=(\"squashfs\")"), std::string::npos);
}

TEST(Analyze, CarveModes) {
    // MBR image with the squashfs at p1's first byte plus a second squashfs
    // nested deeper inside p1: `all` carves both partitions and the nested
    // find, `table` only the partitions, `none` nothing.
    Layout l = build_image();
    const Bytes sq = synthetic_squashfs();
    std::copy(sq.begin(), sq.end(), l.bytes.begin() + static_cast<std::ptrdiff_t>(3 * kMiB));
    struct Case {
        Carve carve;
        bool dir, p1, nested;
    };
    for (const Case cs : {Case{Carve::All, true, true, true}, Case{Carve::Table, true, true, false},
                          Case{Carve::None, false, false, false}}) {
        TempDir out("modes");
        AnalyzeOptions opts;
        opts.out_dir = out.path.string();
        opts.extract = false;
        opts.carve = cs.carve;
        Manifest m;
        Listings listings;
        ASSERT_TRUE(analyze(source_of(l.bytes), "router.bin", opts, m, listings));
        const fsys::path pdir = out.path / "partitions";
        EXPECT_EQ(fsys::exists(pdir), cs.dir) << carve_name(cs.carve);
        EXPECT_EQ(fsys::exists(pdir / "p1.bin"), cs.p1) << carve_name(cs.carve);
        EXPECT_EQ(fsys::exists(pdir / "p2.bin"), cs.p1) << carve_name(cs.carve);
        EXPECT_EQ(fsys::exists(pdir / "0x00300000-squashfs.bin"), cs.nested)
            << carve_name(cs.carve);
        EXPECT_EQ(fsys::exists(pdir / "mount.sh"), cs.dir) << carve_name(cs.carve);
        const Node* nested = node_at(m, NodeKind::Filesystem, 3 * kMiB, "squashfs");
        ASSERT_NE(nested, nullptr);
        EXPECT_EQ(nested->parent_id, node_at(m, NodeKind::Partition, kMiB)->id);
        EXPECT_EQ(nested->attrs.count("carved_path"), cs.nested ? 1u : 0u);
        if (cs.carve == Carve::None) {
            EXPECT_EQ(coverage_for(m, "carve"), nullptr);
        }
    }
}

TEST(Analyze, BackupOnlyGptRecoversPartitionsAndFlagsTheImage) {
    // Hand-made findings per the validator contract: only a gpt-backup table
    // (LBA 1 wiped), describing one partition at 1 MiB.
    Bytes b(static_cast<std::size_t>(4 * kMiB), 0);
    const Bytes sq = synthetic_squashfs();
    std::copy(sq.begin(), sq.end(), b.begin() + static_cast<std::ptrdiff_t>(kMiB));
    AnalyzeOptions opts;
    opts.extract = false;
    opts.scanner = [](const Span& span) {
        std::vector<Finding> out = scan(span, SignatureSet::builtin());
        if (span.size() != 4 * kMiB) return out;  // a partition re-scan
        Finding t;
        t.offset = 4 * kMiB - 512;
        t.size = 512;
        t.format = "gpt";
        t.category = "partition-table";
        t.signature = "gpt";
        t.confidence = Confidence::Verified;
        t.evidence = "backup GPT header, CRC ok";
        t.attrs["table"] = "gpt-backup";
        t.attrs["disk_guid"] = kDiskGuid;
        t.attrs["disk_offset"] = "0";
        t.attrs["disk_size"] = std::to_string(4 * kMiB);
        t.attrs["sector_size"] = "512";
        t.attrs["my_lba"] = std::to_string(4 * kMiB / 512 - 1);
        t.attrs["partitions"] = std::string("p1:1048576:2097152:") + kRootfsType +
                                ":6f1a2c3e-1001-4d5e-8f90-0123456789ab:system";
        t.diagnostics.push_back({Severity::Warning, "gpt-primary-missing",
                                 "no primary GPT header at LBA 1; backup used"});
        out.push_back(std::move(t));
        std::stable_sort(out.begin(), out.end(),
                         [](const Finding& x, const Finding& y) { return x.offset < y.offset; });
        return out;
    };
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(b), "emmc.bin", opts, m, listings));
    EXPECT_TRUE(has_diag(m.nodes()[0].diagnostics, "gpt-primary-missing"));
    const Node* table = node_at(m, NodeKind::Partition, 4 * kMiB - 512, "gpt");
    ASSERT_NE(table, nullptr);
    EXPECT_EQ(table->attrs.at("table"), "gpt-backup");
    EXPECT_EQ(table->attrs.at("role"), "table");
    const Node* system = node_named(m, NodeKind::Partition, "system");
    ASSERT_NE(system, nullptr);
    EXPECT_EQ(system->parent_id, table->id);
    EXPECT_EQ(system->location.offset, kMiB);
    EXPECT_EQ(system->location.length, 2 * kMiB);
    EXPECT_EQ(system->attrs.at("table"), "gpt-backup");
    const Node* fsn = node_at(m, NodeKind::Filesystem, kMiB, "squashfs");
    ASSERT_NE(fsn, nullptr);
    EXPECT_EQ(fsn->parent_id, system->id);
}

TEST(Analyze, PartitionRescanFindsFilesystemAtItsStart) {
    // The whole-image scan "misses" the squashfs (the test scanner drops it at
    // the top level); the partition re-scan must find it at the partition start.
    const Layout l = build_image();
    AnalyzeOptions opts;
    opts.extract = false;
    opts.scanner = [](const Span& span) {
        std::vector<Finding> out = scan(span, SignatureSet::builtin());
        if (span.size() != 6 * kMiB) return out;
        std::erase_if(out, [](const Finding& f) { return f.format == "squashfs"; });
        return out;
    };
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(l.bytes), "router.bin", opts, m, listings));
    const Node* sq = node_at(m, NodeKind::Filesystem, kMiB, "squashfs");
    ASSERT_NE(sq, nullptr);
    EXPECT_EQ(sq->parent_id, node_at(m, NodeKind::Partition, kMiB)->id);
    EXPECT_TRUE(has_diag(sq->diagnostics, "partition-rescan"));
    EXPECT_EQ(sq->attrs.at("signature"), "squashfs-le");
    // Only one squashfs node: the rescan never duplicates.
    EXPECT_EQ(m.count(NodeKind::Filesystem), 1u);
}

TEST(Analyze, CarvedNamesAreHostSafe) {
    Bytes b(static_cast<std::size_t>(2 * kMiB), 0);
    TempDir out("names");
    AnalyzeOptions opts;
    opts.out_dir = out.path.string();
    opts.extract = false;
    opts.scanner = [](const Span& span) -> std::vector<Finding> {
        if (span.size() != 2 * kMiB) return {};
        Finding t;
        t.offset = 0;
        t.size = 512;
        t.format = "gpt";
        t.category = "partition-table";
        t.signature = "gpt";
        t.confidence = Confidence::Verified;
        t.attrs["table"] = "gpt-primary";
        t.attrs["disk_guid"] = kDiskGuid;
        t.attrs["sector_size"] = "512";
        t.attrs["entry_count"] = "2";
        t.attrs["entry_size"] = "128";
        t.attrs["partitions"] = std::string("p1:65536:65536:") + kRootfsType +
                                ":6f1a2c3e-1001-4d5e-8f90-0123456789ab:../etc/pass wd;" +
                                "p2:131072:65536:" + kDataType +
                                ":6f1a2c3e-1002-4d5e-8f90-0123456789ab:CON";
        return {t};
    };
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(b), "emmc.bin", opts, m, listings));
    std::vector<std::string> files;
    for (const auto& e : fsys::directory_iterator(out.path / "partitions"))
        files.push_back(e.path().filename().string());
    std::sort(files.begin(), files.end());
    EXPECT_EQ(files, (std::vector<std::string>{"mount.sh", "p1-.._etc_pass_wd.bin", "p2-CON.bin"}))
        << "names never contain separators or escape the directory";
    EXPECT_FALSE(fsys::exists(out.path / "etc"));
}

TEST(MountScript, TypesAndMtdBlock) {
    Manifest m;
    Node img;
    img.kind = NodeKind::Image;
    img.name = "x.bin";
    const std::string image_id = m.add_node(img).id;
    auto part = [&](const char* file, std::uint64_t off, const char* fsfmt) {
        Node p;
        p.kind = NodeKind::Partition;
        p.parent_id = image_id;
        p.format = "gpt";
        p.location = {"mem:x", off, 4096};
        p.attrs["carved_path"] = std::string("partitions/") + file;
        const std::string pid = m.add_node(p).id;
        if (fsfmt) {
            Node f;
            f.kind = NodeKind::Filesystem;
            f.parent_id = pid;
            f.format = fsfmt;
            f.location = {"mem:x", off, 4096};
            m.add_node(f);
        }
    };
    part("p1-boot.bin", 0, "fat");
    part("p2-root.bin", 4096, "ext4");
    part("p3-empty.bin", 8192, nullptr);
    part("p4-cfg.bin", 12288, "jffs2");
    part("p5-app.bin", 16384, "qnx6");
    part("p6-ubi.bin", 20480, "ubifs");
    const std::string s = mount_script_text(m);
    EXPECT_NE(s.find("PARTITION_NAMES=(\"p1-boot.bin\" \"p2-root.bin\" \"p5-app.bin\")"),
              std::string::npos)
        << s;
    EXPECT_NE(s.find("PARTITION_TYPES=(\"vfat\" \"ext4\" \"qnx6\")"), std::string::npos) << s;
    EXPECT_NE(s.find("#   p4-cfg.bin: jffs2"), std::string::npos);
    EXPECT_NE(s.find("#   p6-ubi.bin: ubifs"), std::string::npos);
    EXPECT_NE(s.find("mtdram"), std::string::npos);
    EXPECT_NE(s.find("nandsim"), std::string::npos);
    EXPECT_EQ(s.find("p3-empty"), std::string::npos);
    EXPECT_EQ(s.rfind("#!/bin/bash\n", 0), 0u);
    EXPECT_EQ(mount_type_for("ext2"), "ext4");
    EXPECT_EQ(mount_type_for("ntfs"), "ntfs3");
    EXPECT_EQ(mount_type_for("yaffs2"), "");
    EXPECT_EQ(mount_script_text(m), s) << "deterministic";
}

TEST(Analyze, GptFixtureWhenAvailable) {
    // tests/fixtures/out/gpt.img: boot (fat32) at 1 MiB and rootfs (squashfs-xz)
    // at 34 MiB, per gpt.expected.yaml.
    if (!test::fixture_exists("gpt.img")) GTEST_SKIP() << "fixture gpt.img not built";
    std::shared_ptr<MappedFile> file;
    ASSERT_TRUE(MappedFile::open(test::fixture_path("gpt.img"), file));
    TempDir out("gptfix");
    AnalyzeOptions opts;
    opts.out_dir = out.path.string();
    opts.extract = false;
    opts.scanner = contract_scanner();
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(file, "gpt.img", opts, m, listings));
    const Node* boot = node_named(m, NodeKind::Partition, "boot");
    const Node* rootfs = node_named(m, NodeKind::Partition, "rootfs");
    ASSERT_NE(boot, nullptr);
    ASSERT_NE(rootfs, nullptr);
    EXPECT_EQ(boot->location.offset, 1048576u);
    EXPECT_EQ(boot->location.length, 34603008u);
    EXPECT_EQ(rootfs->location.offset, 35651584u);
    EXPECT_EQ(rootfs->location.length, 319488u);
    EXPECT_EQ(boot->attrs.at("type_guid"), "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7");
    EXPECT_EQ(rootfs->attrs.at("unique_guid"), "6f1a2c3e-1002-4d5e-8f90-0123456789ab");
    EXPECT_EQ(boot->digests.sha256,
              "b32ed975fe0883d3a9722ab4102e80c44c291afe4d7c433242490a6126ae8630");
    EXPECT_EQ(rootfs->digests.sha256,
              "b335c23ac76343ed3a7f731d0d9d9d6fb5e679bd461d1d7b59c7506eff784157");
    EXPECT_TRUE(fsys::exists(out.path / "partitions" / "p1-boot.bin"));
    EXPECT_TRUE(fsys::exists(out.path / "partitions" / "p2-rootfs.bin"));
    const Node* sq = node_at(m, NodeKind::Filesystem, 35651584u, "squashfs");
    ASSERT_NE(sq, nullptr);
    EXPECT_EQ(sq->parent_id, rootfs->id);
    const std::string script = read_file(out.path / "partitions" / "mount.sh");
    EXPECT_NE(script.find("\"p2-rootfs.bin\""), std::string::npos) << script;
}

TEST(Analyze, UnknownSizeFindingParentsNothingAndSplitsNoGap) {
    // auto-emmc.bin: a magic-only zip (size 0) once "held" every later find,
    // so the squashfs and ext4 were nested under zip -> xz and hidden from
    // --carve all. An unknown extent parents nothing and claims no bytes.
    Bytes b(static_cast<std::size_t>(4 * kMiB), 0);
    const Bytes sq = synthetic_squashfs();
    std::copy(sq.begin(), sq.end(), b.begin() + static_cast<std::ptrdiff_t>(2 * kMiB));
    AnalyzeOptions opts;
    opts.extract = false;
    opts.open_reader = fake_lookup();
    opts.scanner = [](const Span& span) {
        std::vector<Finding> out = scan(span, SignatureSet::builtin());
        Finding zip;
        zip.offset = 0x1000;
        zip.size = 0;
        zip.format = "zip";
        zip.category = "container";
        zip.signature = "zip";
        zip.confidence = Confidence::Magic;
        zip.evidence = "magic only";
        out.insert(out.begin(), std::move(zip));
        return out;
    };
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(b), "emmc.bin", opts, m, listings));
    const std::string image = m.nodes()[0].id;
    const Node* zip = node_at(m, NodeKind::Container, 0x1000, "zip");
    ASSERT_NE(zip, nullptr);
    EXPECT_EQ(zip->parent_id, image);
    const Node* sqn = node_at(m, NodeKind::Filesystem, 2 * kMiB, "squashfs");
    ASSERT_NE(sqn, nullptr);
    EXPECT_EQ(sqn->parent_id, image);
    const Node* gap = node_at(m, NodeKind::Region, 0);
    ASSERT_NE(gap, nullptr);
    EXPECT_EQ(gap->location.length, 2 * kMiB);
    EXPECT_EQ(node_at(m, NodeKind::Region, 0x1000), nullptr);
}

TEST(Analyze, PartitionTableInsideAPartitionIsNotExpanded) {
    // qnx-example: MBR sectors stored as file data inside the 14 GiB `storage`
    // GPT partition were expanded into a second partition map with truncated
    // entries. A table inside another table's entry is kept, not expanded.
    const Layout l = build_image();
    AnalyzeOptions opts;
    opts.extract = false;
    opts.open_reader = fake_lookup();
    opts.scanner = [](const Span& span) {
        std::vector<Finding> out = scan(span, SignatureSet::builtin());
        std::size_t table = out.size();
        for (std::size_t i = 0; i < out.size(); ++i)
            if (out[i].category == "partition-table" && out[i].offset == 0) table = i;
        if (table == out.size()) return out;
        Finding nested = out[table];
        nested.offset = 3 * kMiB;  // inside p1 [1 MiB, 5 MiB)
        nested.also_matched.clear();
        out.push_back(std::move(nested));
        return out;
    };
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(l.bytes), "emmc.bin", opts, m, listings));
    const Node* p1 = node_at(m, NodeKind::Partition, kMiB);
    ASSERT_NE(p1, nullptr);
    const Node* nested = node_at(m, NodeKind::Partition, 3 * kMiB, "mbr");
    ASSERT_NE(nested, nullptr);
    EXPECT_EQ(nested->parent_id, p1->id);
    EXPECT_EQ(nested->attrs.at("nested"), "true");
    EXPECT_TRUE(has_diag(nested->diagnostics, "partition-table-nested"));
    EXPECT_EQ(m.count(NodeKind::Partition), 4u);  // table, p1, p2, nested table
}

TEST(Analyze, GptLabelCannotInjectPartitionAttrs) {
    // A partition name is evidence bytes. "protective=true" or
    // "carved_path=x" as a label must stay a label (and a file name), never
    // become an attr that hides the entry from carving or forges a carve.
    Bytes b(static_cast<std::size_t>(2 * kMiB), 0);
    TempDir out("inject");
    AnalyzeOptions opts;
    opts.out_dir = out.path.string();
    opts.extract = false;
    opts.scanner = [](const Span& span) -> std::vector<Finding> {
        if (span.size() != 2 * kMiB) return {};
        Finding t;
        t.offset = 0;
        t.size = 512;
        t.format = "gpt";
        t.category = "partition-table";
        t.signature = "gpt";
        t.confidence = Confidence::Verified;
        t.attrs["table"] = "gpt-primary";
        t.attrs["disk_guid"] = kDiskGuid;
        t.attrs["sector_size"] = "512";
        t.attrs["entry_count"] = "2";
        t.attrs["entry_size"] = "128";
        t.attrs["partitions"] = std::string("p1:65536:65536:") + kRootfsType +
                                ":6f1a2c3e-1001-4d5e-8f90-0123456789ab:protective=true;" +
                                "p2:131072:65536:" + kDataType +
                                ":6f1a2c3e-1002-4d5e-8f90-0123456789ab:carved_path=../x:attrs=0x4" +
                                ":role=table";
        return {t};
    };
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(b), "emmc.bin", opts, m, listings));
    const Node* p1 = node_at(m, NodeKind::Partition, 65536);
    const Node* p2 = node_at(m, NodeKind::Partition, 131072);
    ASSERT_NE(p1, nullptr);
    ASSERT_NE(p2, nullptr);
    EXPECT_EQ(p1->attrs.at("label"), "protective=true");
    EXPECT_EQ(p1->attrs.count("protective"), 0u);
    EXPECT_EQ(p1->attrs.at("carved_path"), "partitions/p1-protective=true.bin");
    EXPECT_EQ(p2->attrs.at("label"), "carved_path=../x");
    EXPECT_EQ(p2->attrs.at("gpt_attributes"), "0x4");
    EXPECT_EQ(p2->attrs.count("role"), 0u);
    EXPECT_EQ(p2->attrs.at("carved_path"), "partitions/p2-carved_path=.._x.bin");
    EXPECT_TRUE(fsys::exists(out.path / "partitions" / "p1-protective=true.bin"));
    EXPECT_TRUE(fsys::exists(out.path / "partitions" / "p2-carved_path=.._x.bin"));
    EXPECT_FALSE(fsys::exists(out.path / "x"));
}

TEST(Analyze, BackupOnlyGptLeavesACoverageRow) {
    Bytes b(static_cast<std::size_t>(2 * kMiB), 0);
    AnalyzeOptions opts;
    opts.extract = false;
    opts.scanner = [](const Span& span) -> std::vector<Finding> {
        if (span.size() != 2 * kMiB) return {};
        Finding t;
        t.offset = 2 * kMiB - 512;
        t.size = 512;
        t.format = "gpt";
        t.category = "partition-table";
        t.signature = "gpt";
        t.confidence = Confidence::Verified;
        t.attrs["table"] = "gpt-backup";
        t.attrs["disk_guid"] = kDiskGuid;
        t.attrs["disk_offset"] = "0";
        t.attrs["sector_size"] = "512";
        t.attrs["primary"] = "mismatch";
        t.attrs["partitions"] = std::string("p1:65536:65536:") + kRootfsType +
                                ":6f1a2c3e-1001-4d5e-8f90-0123456789ab:old";
        return {t};
    };
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(b), "emmc.bin", opts, m, listings));
    const Coverage* cov = coverage_for(m, "gpt");
    ASSERT_NE(cov, nullptr);
    EXPECT_EQ(cov->status, "partial");
    EXPECT_NE(cov->detail.find("stale backup"), std::string::npos) << cov->detail;
    // The primary exists and disagrees: never claim it is missing.
    EXPECT_FALSE(has_diag(m.nodes()[0].diagnostics, "gpt-primary-missing"));
    EXPECT_TRUE(has_diag(m.nodes()[0].diagnostics, "gpt-backup-mismatch"));
}
