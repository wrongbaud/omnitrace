// swap_recurse_test.cpp — analyze() on a word-swapped image: detection at the
// extension point, the Image node's diagnostic and attrs, the coverage row,
// nodes located in the "<image>|swap32" view, and carved files that hold the
// corrected bytes under a "-swap32" name. Raw images and a caller-supplied
// image_view hook leave detection out. Corpus image when present.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>

#include "helpers.h"
#include "omnitrace/core/Swap.h"
#include "omnitrace/discovery/Recurse.h"

using namespace omnitrace;
using namespace omnitrace::discovery;
using test::Bytes;

namespace {

namespace fsys = std::filesystem;

constexpr std::uint64_t kMiB = 1u << 20;

fsys::path temp_dir(const char* tag) {
    static std::mt19937_64 rng{std::random_device{}()};
    const fsys::path p = fsys::temp_directory_path() /
                         ("omnitrace-swap-" + std::string(tag) + "-" + std::to_string(rng()));
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

Bytes read_file(const fsys::path& p) {
    std::ifstream f(p, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

Bytes swap32(Bytes b) {
    const std::size_t whole = b.size() - b.size() % 4;
    for (std::size_t i = 0; i < whole; i += 4)
        std::reverse(b.begin() + static_cast<std::ptrdiff_t>(i),
                     b.begin() + static_cast<std::ptrdiff_t>(i + 4));
    return b;
}

void mbr_entry(Bytes& b, int i, std::uint8_t status, std::uint8_t type, std::uint32_t lba,
               std::uint32_t n) {
    const std::size_t o = 446 + static_cast<std::size_t>(i) * 16;
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

// 6 MiB firmware: MBR at 0 (p1 = [1 MiB, 5 MiB) holding a SquashFS, p2 =
// [5 MiB, 5.5 MiB)), then a bootloader-like blob at 5.5 MiB: an ARM vector
// table, NOP padding, an ELF header and banner strings. Erased flash around.
constexpr std::uint64_t kSq = kMiB;
constexpr std::uint64_t kBoot = 5 * kMiB + kMiB / 2;

Bytes build_raw_image() {
    Bytes b(static_cast<std::size_t>(6 * kMiB), 0xFF);
    std::fill(b.begin(), b.begin() + 512, 0);
    b[510] = 0x55;
    b[511] = 0xAA;
    test::put_u32le(b, 440, 0x12345678);
    mbr_entry(b, 0, 0x80, 0x83, 2048, 8192);
    mbr_entry(b, 1, 0x00, 0x0C, 10240, 1024);
    const Bytes sq = synthetic_squashfs();
    std::copy(sq.begin(), sq.end(), b.begin() + static_cast<std::ptrdiff_t>(kSq));
    const std::size_t boot = static_cast<std::size_t>(kBoot);
    for (std::size_t i = 0; i < 8; ++i)
        test::put_u32le(b, boot + i * 4, 0xEA000000u | static_cast<std::uint32_t>(0x20 + i));
    for (std::size_t i = 8; i < 64; ++i) test::put_u32le(b, boot + i * 4, 0xE1A00000u);
    test::put_bytes(b, boot + 0x1000,
                    "\x7f"
                    "ELF");
    b[boot + 0x1004] = 1;
    b[boot + 0x1005] = 1;
    b[boot + 0x1006] = 1;
    test::put_bytes(b, boot + 0x2000, "U-Boot 2020.10 (Sep 19 2026 - 09:00:00 +0000)");
    test::put_bytes(b, boot + 0x2100, "[Preloader 1st Image empty]");
    test::put_bytes(b, boot + 0x2200, "Copyright (C) 2026 Example Vendor. All Rights Reserved.");
    return b;
}

std::shared_ptr<const Source> source_of(Bytes b, const char* label = "img") {
    return std::make_shared<MemorySource>(std::move(b), label);
}

const Node* node_at(const Manifest& m, NodeKind kind, std::uint64_t offset,
                    const std::string& format = {}) {
    for (const Node& n : m.nodes())
        if (n.kind == kind && n.location.offset == offset && (format.empty() || n.format == format))
            return &n;
    return nullptr;
}

const Diagnostic* diag(const std::vector<Diagnostic>& ds, const char* code) {
    for (const Diagnostic& d : ds)
        if (d.code == code) return &d;
    return nullptr;
}

const Coverage* coverage_for(const Manifest& m, const std::string& format) {
    for (const Coverage& c : m.coverage)
        if (c.format == format) return &c;
    return nullptr;
}

std::string attr(const Node& n, const char* key) {
    const auto it = n.attrs.find(key);
    return it == n.attrs.end() ? std::string{} : it->second;
}

std::string dump(const Manifest& m) {
    std::string s;
    for (const Node& n : m.nodes()) {
        s += n.id + "|" + n.parent_id + "|" + node_kind_name(n.kind) + "|" + n.name + "|" +
             n.format + "|" + n.location.source_id + "|" + std::to_string(n.location.offset) + "+" +
             std::to_string(n.location.length) + "|" + n.digests.sha256 + "|";
        for (const auto& [k, v] : n.attrs) s += k + "=" + v + ",";
        for (const Diagnostic& d : n.diagnostics) s += d.code + ";";
        s += "\n";
    }
    for (const Coverage& c : m.coverage) s += c.format + ":" + c.status + ":" + c.detail + "\n";
    return s;
}

std::string corpus_path(const char* rel) {
    return std::string(OMNITRACE_SOURCE_DIR) + "/corpus/" + rel;
}

}  // namespace

// ------------------------------------------------------------- swapped image

TEST(AnalyzeSwap, SwappedImageIsAnalysedOnTheCorrectedView) {
    const Bytes raw = build_raw_image();
    const Bytes stored = swap32(raw);
    TempDir t("case");
    AnalyzeOptions opts;
    opts.extract = false;
    opts.out_dir = t.path.string();
    opts.carve = Carve::All;
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(stored), "/evidence/MX25L165D.bin", opts, m, listings));

    // The Image node is the evidence as given: raw id, raw hash, and the verdict.
    ASSERT_FALSE(m.nodes().empty());
    const Node& img = m.nodes()[0];
    ASSERT_EQ(img.kind, NodeKind::Image);
    EXPECT_EQ(img.location.source_id, "mem:img");
    EXPECT_EQ(attr(img, "word_swap"), "swap32");
    EXPECT_FALSE(attr(img, "word_swap_confidence").empty());
    EXPECT_GE(std::stoi(attr(img, "word_swap_confidence")), 60);
    const Diagnostic* d = diag(img.diagnostics, "image-word-swapped");
    ASSERT_NE(d, nullptr);
    EXPECT_EQ(d->severity, Severity::Warning);
    EXPECT_NE(d->message.find("swap32"), std::string::npos) << d->message;
    EXPECT_NE(d->message.find("magics"), std::string::npos) << d->message;
    EXPECT_EQ(diag(img.diagnostics, "image-word-swap-tail"), nullptr);  // 6 MiB % 4 == 0
    EXPECT_EQ(m.evidence.size(), 1u);
    EXPECT_EQ(m.evidence[0].digests.sha256, img.digests.sha256);

    const Coverage* cov = coverage_for(m, "word-swap");
    ASSERT_NE(cov, nullptr);
    EXPECT_EQ(cov->status, "supported");
    EXPECT_EQ(cov->detail, "swap32 applied");

    // Findings come from the corrected view and say so in location.source.
    const Node* table = node_at(m, NodeKind::Partition, 0, "mbr");
    ASSERT_NE(table, nullptr);
    EXPECT_EQ(table->location.source_id, "mem:img|swap32");
    const Node* p1 = node_at(m, NodeKind::Partition, kSq, "mbr");
    ASSERT_NE(p1, nullptr);
    EXPECT_EQ(p1->location.source_id, "mem:img|swap32");
    const Node* sq = node_at(m, NodeKind::Filesystem, kSq, "squashfs");
    ASSERT_NE(sq, nullptr) << dump(m);
    EXPECT_EQ(sq->location.source_id, "mem:img|swap32");
    EXPECT_EQ(sq->parent_id, p1->id);
    for (const Node& n : m.nodes()) {
        if (n.kind != NodeKind::Image) {
            EXPECT_EQ(n.location.source_id, "mem:img|swap32") << n.id;
        }
    }

    // Carves hold the corrected bytes and carry the -swap32 suffix.
    EXPECT_EQ(attr(*p1, "carved_path"), "partitions/p1-swap32.bin");
    const Bytes p1_bytes = read_file(t.path / "partitions" / "p1-swap32.bin");
    ASSERT_EQ(p1_bytes.size(), 4 * kMiB);
    EXPECT_TRUE(std::equal(p1_bytes.begin(), p1_bytes.end(),
                           raw.begin() + static_cast<std::ptrdiff_t>(kSq)));
    EXPECT_EQ(attr(*sq, "carved_in"), "partitions/p1-swap32.bin");
    const Node* p2 = node_at(m, NodeKind::Partition, 5 * kMiB, "mbr");
    ASSERT_NE(p2, nullptr);
    EXPECT_EQ(attr(*p2, "carved_path"), "partitions/p2-swap32.bin");
    bool nested_suffix_ok = true;
    for (const Node& n : m.nodes()) {
        const std::string path = attr(n, "carved_path");
        if (path.empty()) continue;
        nested_suffix_ok = nested_suffix_ok && path.size() > 11 &&
                           path.compare(path.size() - 11, 11, "-swap32.bin") == 0;
        const Bytes got = read_file(t.path / path);
        ASSERT_EQ(got.size(), n.location.length) << path;
        EXPECT_TRUE(std::equal(got.begin(), got.end(),
                               raw.begin() + static_cast<std::ptrdiff_t>(n.location.offset)))
            << path << " does not hold the corrected bytes";
    }
    EXPECT_TRUE(nested_suffix_ok);
    EXPECT_TRUE(fsys::exists(t.path / "partitions" / "mount.sh"));
    const Bytes script = read_file(t.path / "partitions" / "mount.sh");
    const std::string script_text(script.begin(), script.end());
    EXPECT_NE(script_text.find("\"p1-swap32.bin\""), std::string::npos);

    // Deterministic: the same evidence yields the same graph.
    Manifest again;
    Listings again_l;
    TempDir t2("case2");
    AnalyzeOptions opts2 = opts;
    opts2.out_dir = t2.path.string();
    ASSERT_TRUE(analyze(source_of(stored), "/evidence/MX25L165D.bin", opts2, again, again_l));
    EXPECT_EQ(dump(again), dump(m));
}

TEST(AnalyzeSwap, OddSizedSwappedImageNotesThePartialTail) {
    Bytes raw = build_raw_image();
    raw.push_back(0x11);
    raw.push_back(0x22);
    raw.push_back(0x33);
    const Bytes stored = swap32(raw);
    AnalyzeOptions opts;
    opts.extract = false;
    opts.carve = Carve::None;
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(stored), "odd.bin", opts, m, listings));
    const Node& img = m.nodes()[0];
    ASSERT_NE(diag(img.diagnostics, "image-word-swapped"), nullptr);
    const Diagnostic* tail = diag(img.diagnostics, "image-word-swap-tail");
    ASSERT_NE(tail, nullptr);
    EXPECT_EQ(tail->severity, Severity::Info);
    EXPECT_NE(tail->message.find("3 byte(s)"), std::string::npos) << tail->message;
    // The tail is readable through the view, unswapped.
    const Node* sq = node_at(m, NodeKind::Filesystem, kSq, "squashfs");
    ASSERT_NE(sq, nullptr);
    const SwappedSource view(source_of(stored), SwapKind::Swap32);
    std::uint8_t last[3];
    ASSERT_EQ(view.read(view.size() - 3, last), 3u);
    EXPECT_EQ(last[0], 0x11);
    EXPECT_EQ(last[2], 0x33);
}

// ----------------------------------------------------------------- raw image

TEST(AnalyzeSwap, RawImageIsLeftAlone) {
    const Bytes raw = build_raw_image();
    AnalyzeOptions opts;
    opts.extract = false;
    opts.carve = Carve::None;
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(raw), "raw.bin", opts, m, listings));
    const Node& img = m.nodes()[0];
    EXPECT_EQ(diag(img.diagnostics, "image-word-swapped"), nullptr);
    EXPECT_EQ(attr(img, "word_swap"), "");
    EXPECT_EQ(coverage_for(m, "word-swap"), nullptr);
    const Node* sq = node_at(m, NodeKind::Filesystem, kSq, "squashfs");
    ASSERT_NE(sq, nullptr);
    EXPECT_EQ(sq->location.source_id, "mem:img");
}

TEST(AnalyzeSwap, RandomImageIsLeftAlone) {
    std::mt19937_64 rng(42);
    Bytes b(static_cast<std::size_t>(2 * kMiB));
    for (auto& x : b) x = static_cast<std::uint8_t>(rng());
    AnalyzeOptions opts;
    opts.extract = false;
    opts.carve = Carve::None;
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(b), "random.bin", opts, m, listings));
    EXPECT_EQ(diag(m.nodes()[0].diagnostics, "image-word-swapped"), nullptr);
    EXPECT_EQ(coverage_for(m, "word-swap"), nullptr);
}

// ------------------------------------------------------------------- the hook

TEST(AnalyzeSwap, CallerHookReplacesDetection) {
    const Bytes stored = swap32(build_raw_image());
    AnalyzeOptions opts;
    opts.extract = false;
    opts.carve = Carve::None;
    int calls = 0;
    // A hook that keeps the image as is: no detection, no diagnostic.
    opts.image_view = [&](const std::shared_ptr<const Source>& image, Node& n) {
        ++calls;
        n.attrs["hook"] = "seen";
        return image;
    };
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(source_of(stored), "hooked.bin", opts, m, listings));
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(attr(m.nodes()[0], "hook"), "seen");
    EXPECT_EQ(diag(m.nodes()[0].diagnostics, "image-word-swapped"), nullptr);
    EXPECT_EQ(coverage_for(m, "word-swap"), nullptr);
    EXPECT_EQ(node_at(m, NodeKind::Filesystem, kSq, "squashfs"), nullptr);

    // A hook that installs the view itself: the analysis runs on it.
    opts.image_view = [](const std::shared_ptr<const Source>& image, Node&) {
        return std::make_shared<SwappedSource>(image, SwapKind::Swap32);
    };
    Manifest m2;
    Listings l2;
    ASSERT_TRUE(analyze(source_of(stored), "hooked.bin", opts, m2, l2));
    const Node* sq = node_at(m2, NodeKind::Filesystem, kSq, "squashfs");
    ASSERT_NE(sq, nullptr);
    EXPECT_EQ(sq->location.source_id, "mem:img|swap32");
}

// -------------------------------------------------------------------- corpus

TEST(AnalyzeSwap, CorpusMx25l165d) {
    const std::string path = corpus_path("auto-ivi-example/flash/MX25L165D.bin");
    if (!fsys::exists(path)) GTEST_SKIP() << "corpus image missing: " << path;
    std::shared_ptr<MappedFile> file;
    ASSERT_TRUE(MappedFile::open(path, file));
    AnalyzeOptions opts;
    opts.extract = false;
    opts.carve = Carve::None;
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(file, path, opts, m, listings));
    const Node& img = m.nodes()[0];
    EXPECT_EQ(attr(img, "word_swap"), "swap32");
    const Diagnostic* d = diag(img.diagnostics, "image-word-swapped");
    ASSERT_NE(d, nullptr);
    EXPECT_NE(d->message.find("swap32"), std::string::npos) << d->message;
    const Coverage* cov = coverage_for(m, "word-swap");
    ASSERT_NE(cov, nullptr);
    EXPECT_EQ(cov->detail, "swap32 applied");
    for (const Node& n : m.nodes()) {
        if (n.kind != NodeKind::Image) {
            EXPECT_EQ(n.location.source_id, path + "|swap32") << n.id;
        }
    }
}

TEST(AnalyzeSwap, CorpusRouterIsNotSwapped) {
    const std::string path = corpus_path("router-example/flash/router.bin");
    if (!fsys::exists(path)) GTEST_SKIP() << "corpus image missing: " << path;
    std::shared_ptr<MappedFile> file;
    ASSERT_TRUE(MappedFile::open(path, file));
    AnalyzeOptions opts;
    opts.extract = false;
    opts.carve = Carve::None;
    Manifest m;
    Listings listings;
    ASSERT_TRUE(analyze(file, path, opts, m, listings));
    EXPECT_EQ(attr(m.nodes()[0], "word_swap"), "");
    EXPECT_EQ(coverage_for(m, "word-swap"), nullptr);
}
