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
    EXPECT_EQ(table.location.length, 5 * kMiB + 512 * 1024);
    const Node& p1 = m.nodes()[2];
    EXPECT_EQ(p1.kind, NodeKind::Partition);
    EXPECT_EQ(p1.parent_id, table.id);
    EXPECT_EQ(p1.name, "p1");
    EXPECT_EQ(p1.location.offset, kMiB);
    EXPECT_EQ(p1.location.length, 4 * kMiB);
    EXPECT_EQ(p1.attrs.at("type"), "0x83");
    EXPECT_EQ(p1.attrs.at("boot"), "true");
    EXPECT_EQ(p1.attrs.at("index"), "p1");
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
    EXPECT_EQ(m.count(NodeKind::Region), 2u);

    // child_ids agree with parent_id links.
    EXPECT_EQ(table.child_ids, (std::vector<std::string>{p1.id, p2.id}));
    EXPECT_EQ(m.find(p1.id)->child_ids, std::vector<std::string>{sq->id});
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
    // The 3.5 KiB before p1 is under the threshold: no region there.
    EXPECT_EQ(m.count(NodeKind::Region), 0u);
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
