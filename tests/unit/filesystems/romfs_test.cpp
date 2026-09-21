// romfs_test.cpp — the romfs reader.
//
// romfs is small enough to build in the test, which is what these do: a
// writer here emits the same layout genromfs does, so every case below is an
// image whose expected tree is written three lines above it. That matters
// more than usual for this format, because the whole filesystem is a graph of
// raw offsets: the interesting cases are the ones where those offsets lie.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/filesystems/Filesystem.h"

using namespace omnitrace;
using namespace omnitrace::fs;

namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::uint32_t kHardLink = 0, kDirectory = 1, kRegular = 2, kSymlink = 3, kBlockDev = 4,
                        kCharDev = 5, kSocket = 6, kFifo = 7;
constexpr std::uint32_t kExec = 0x8;

std::size_t align16(std::size_t n) {
    return (n + 15) & ~static_cast<std::size_t>(15);
}

void put_be32(Bytes& b, std::size_t at, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i) b[at + i] = static_cast<std::uint8_t>(v >> (24 - 8 * i));
}

void append_be32(Bytes& b, std::uint32_t v) {
    for (int i = 3; i >= 0; --i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}

// A name field: the bytes, a NUL, then padding to 16.
void append_name(Bytes& b, const std::string& s) {
    for (const char c : s) b.push_back(static_cast<std::uint8_t>(c));
    b.push_back(0);
    while (b.size() % 16 != 0) b.push_back(0);
}

// One entry to place. `spec` means what the type says it means; for a
// directory the writer fills it in with the first child's offset.
struct Entry {
    std::string name;
    std::uint32_t type = kRegular;
    Bytes data;
    bool executable = false;
    std::uint32_t spec = 0;
    std::vector<Entry> children;
    // Set after layout so a test can assert on, or corrupt, a known offset.
    mutable std::size_t offset = 0;
};

Entry file(std::string name, std::string data, bool exec = false) {
    Entry e;
    e.name = std::move(name);
    e.type = kRegular;
    e.data.assign(data.begin(), data.end());
    e.executable = exec;
    return e;
}

Entry dir(std::string name, std::vector<Entry> children) {
    Entry e;
    e.name = std::move(name);
    e.type = kDirectory;
    e.children = std::move(children);
    return e;
}

Entry sym(std::string name, std::string target) {
    Entry e;
    e.name = std::move(name);
    e.type = kSymlink;
    e.data.assign(target.begin(), target.end());
    return e;
}

Entry special(std::string name, std::uint32_t type, std::uint32_t spec = 0) {
    Entry e;
    e.name = std::move(name);
    e.type = type;
    e.spec = spec;
    return e;
}

std::size_t record_bytes(const Entry& e) {
    return 16 + align16(e.name.size() + 1) + align16(e.data.size());
}

// Writes the image. Every directory gets "." and ".." as hard links first,
// the way genromfs does, so the reader's skipping of them is exercised by
// every single case here rather than by one dedicated test.
class Writer {
   public:
    explicit Writer(std::string volume) : volume_(std::move(volume)) {}

    Bytes build(std::vector<Entry>& root) {
        const std::size_t first = 16 + align16(volume_.size() + 1);
        std::size_t pos = first;
        layout(root, pos, /*self=*/0, /*parent=*/0);

        Bytes out;
        for (const char c : std::string("-rom1fs-")) out.push_back(static_cast<std::uint8_t>(c));
        append_be32(out, 0);  // size, patched below
        append_be32(out, 0);  // checksum, patched below
        append_name(out, volume_);
        emit(out, root);

        put_be32(out, 8, static_cast<std::uint32_t>(out.size()));
        // The one checksum the kernel verifies: the u32 words of the first
        // 512 bytes sum to zero.
        const std::size_t covered = std::min<std::size_t>(512, out.size()) & ~std::size_t{3};
        std::uint32_t sum = 0;
        for (std::size_t i = 0; i + 4 <= covered; i += 4)
            sum += (static_cast<std::uint32_t>(out[i]) << 24) |
                   (static_cast<std::uint32_t>(out[i + 1]) << 16) |
                   (static_cast<std::uint32_t>(out[i + 2]) << 8) | out[i + 3];
        put_be32(out, 12, 0u - sum);
        while (out.size() % 1024 != 0) out.push_back(0);
        return out;
    }

   private:
    // Assigns every header an offset, depth first, and prepends . and .. .
    void layout(std::vector<Entry>& children, std::size_t& pos, std::size_t self,
                std::size_t parent) {
        std::vector<Entry> full;
        full.push_back(special(".", kHardLink, static_cast<std::uint32_t>(self)));
        full.push_back(special("..", kHardLink, static_cast<std::uint32_t>(parent)));
        for (Entry& e : children) full.push_back(std::move(e));
        children = std::move(full);
        for (Entry& e : children) {
            e.offset = pos;
            pos += record_bytes(e);
        }
        for (Entry& e : children)
            if (e.type == kDirectory) layout(e.children, pos, e.offset, self);
    }

    void emit(Bytes& out, const std::vector<Entry>& children) {
        for (std::size_t i = 0; i < children.size(); ++i) {
            const Entry& e = children[i];
            const std::uint32_t next =
                i + 1 < children.size() ? static_cast<std::uint32_t>(children[i + 1].offset) : 0;
            std::uint32_t spec = e.spec;
            if (e.type == kDirectory)
                spec = e.children.empty() ? 0 : static_cast<std::uint32_t>(e.children[0].offset);
            const std::size_t start = out.size();
            append_be32(out, next | e.type | (e.executable ? kExec : 0));
            append_be32(out, spec);
            append_be32(out, static_cast<std::uint32_t>(e.data.size()));
            append_be32(out, 0);
            append_name(out, e.name);
            out.insert(out.end(), e.data.begin(), e.data.end());
            while (out.size() % 16 != 0) out.push_back(0);
            (void)start;
        }
        for (const Entry& e : children)
            if (e.type == kDirectory) emit(out, e.children);
    }

    std::string volume_;
};

std::unique_ptr<FilesystemReader> make() {
    return FilesystemRegistry::instance().create("romfs");
}

Span span_of(const Bytes& b, std::shared_ptr<const Source>& keep) {
    keep = std::make_shared<MemorySource>(b, "t");
    return Span::whole(keep);
}

// open + walk into a ListingSink, with the entries left in `out.entries_out`.
WalkResult walk_image(const Bytes& img, std::unique_ptr<FilesystemReader>& reader,
                      std::shared_ptr<const Source>& keep, Status& open_status,
                      bool extract = true) {
    reader = make();
    WalkResult r;
    open_status = reader->open(span_of(img, keep));
    if (!open_status) return r;
    ListingSink sink(extract, Limits{});
    WalkOptions opts;
    opts.extract_data = extract;
    reader->walk(sink, opts, r);
    return r;
}

std::vector<std::string> paths_of(const WalkResult& r) {
    std::vector<std::string> out;
    out.reserve(r.entries_out.size());
    for (const EntryResult& e : r.entries_out) out.push_back(e.meta.path);
    std::sort(out.begin(), out.end());
    return out;
}

const EntryResult* find(const WalkResult& r, const std::string& path) {
    for (const EntryResult& e : r.entries_out)
        if (e.meta.path == path) return &e;
    return nullptr;
}

bool has_code(const std::vector<Diagnostic>& d, const std::string& code) {
    for (const Diagnostic& x : d)
        if (x.code == code) return true;
    return false;
}

}  // namespace

TEST(Romfs, RegistryHasTheReader) {
    const auto formats = FilesystemRegistry::instance().formats();
    EXPECT_NE(std::find(formats.begin(), formats.end(), "romfs"), formats.end());
    ASSERT_NE(make(), nullptr);
    EXPECT_EQ(make()->format(), "romfs");
}

TEST(Romfs, WalksTheTreeAndReadsEveryKind) {
    std::vector<Entry> root{
        dir("etc",
            {file("passwd", "root:x:0:0:root:/root:/bin/sh\n"), file("hostname", "romfs-test\n")}),
        dir("bin",
            {file("sh", "#!/bin/sh\nexit 0\n", /*exec=*/true), sym("link", "../etc/passwd")}),
        dir("dev", {special("console", kCharDev, (5u << 16) | 1u), special("pipe", kFifo),
                    special("sock", kSocket)}),
        dir("empty", {}),
    };
    const Bytes img = Writer("testvol").build(root);

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st);
    ASSERT_TRUE(st) << st.error;

    const FilesystemInfo info = reader->info();
    EXPECT_EQ(info.format, "romfs");
    EXPECT_EQ(info.label, "testvol");
    EXPECT_EQ(info.endian, Endian::Big);
    EXPECT_EQ(info.attrs.at("checksum"), "ok");

    // "." and ".." are in every directory of the image and in none of the output.
    EXPECT_EQ(paths_of(r), (std::vector<std::string>{"bin", "bin/link", "bin/sh", "dev",
                                                     "dev/console", "dev/pipe", "dev/sock", "empty",
                                                     "etc", "etc/hostname", "etc/passwd"}));
    EXPECT_EQ(r.dirs, 4u);
    EXPECT_EQ(r.files, 3u);
    EXPECT_EQ(r.symlinks, 1u);
    EXPECT_EQ(r.others, 3u);
    EXPECT_FALSE(r.truncated);

    const EntryResult* sh = find(r, "bin/sh");
    ASSERT_NE(sh, nullptr);
    EXPECT_EQ(sh->meta.kind, EntryKind::Regular);
    EXPECT_EQ(sh->meta.size, 17u);
    EXPECT_EQ(sh->meta.mode, 0755u) << "the executable bit is the only mode romfs stores";
    EXPECT_EQ(sh->digests.bytes, 17u);

    const EntryResult* passwd = find(r, "etc/passwd");
    ASSERT_NE(passwd, nullptr);
    EXPECT_EQ(passwd->meta.mode, 0644u);

    const EntryResult* link = find(r, "bin/link");
    ASSERT_NE(link, nullptr);
    EXPECT_EQ(link->meta.kind, EntryKind::Symlink);
    EXPECT_EQ(link->meta.link_target, "../etc/passwd");

    const EntryResult* con = find(r, "dev/console");
    ASSERT_NE(con, nullptr);
    EXPECT_EQ(con->meta.kind, EntryKind::CharDevice);
    EXPECT_EQ(con->meta.rdev_major, 5u);
    EXPECT_EQ(con->meta.rdev_minor, 1u);

    // The mode is synthesised, and the entry says so rather than letting an
    // examiner read 0644 as something the image recorded.
    EXPECT_NE(passwd->meta.extra.find("mode_source"), passwd->meta.extra.end());
}

// A file longer than one alignment unit, to prove the data offset is the
// header plus its padded name and not a guess.
TEST(Romfs, FileDataIsWholeAndContiguous) {
    const std::string big(40000, 'B');
    std::vector<Entry> root{file("big", big), file("after", "sentinel")};
    const Bytes img = Writer("v").build(root);

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st);
    ASSERT_TRUE(st);
    const EntryResult* b = find(r, "big");
    ASSERT_NE(b, nullptr);
    EXPECT_EQ(b->meta.size, big.size());
    EXPECT_EQ(b->digests.bytes, big.size());
    // The entry after it is still found, so `big`'s padding was accounted for.
    EXPECT_NE(find(r, "after"), nullptr);
}

TEST(Romfs, OpenRejectsWhatIsNotRomfs) {
    std::shared_ptr<const Source> keep;
    EXPECT_FALSE(make()->open(span_of(Bytes(64, 0), keep)));
    EXPECT_FALSE(make()->open(span_of(Bytes{}, keep)));

    Bytes almost(1024, 0);
    const std::string magic = "-rom1fs-";
    std::copy(magic.begin(), magic.end(), almost.begin());
    // A volume name with no terminator inside the image.
    std::fill(almost.begin() + 16, almost.end(), 0x41);
    const Status st = make()->open(span_of(almost, keep));
    EXPECT_FALSE(st);
    EXPECT_NE(st.error.find("romfs-bad-name"), std::string::npos) << st.error;
}

TEST(Romfs, WalkBeforeOpenFails) {
    auto reader = make();
    ListingSink sink(false, Limits{});
    WalkResult r;
    const Status st = reader->walk(sink, WalkOptions{}, r);
    EXPECT_FALSE(st);
    EXPECT_NE(st.error.find("romfs-not-open"), std::string::npos);
}

// The format is a graph of raw offsets, so a directory can name itself as its
// own first child. The walk has to stop rather than recurse until a limit.
TEST(Romfs, ADirectoryThatContainsItselfIsCutNotFollowed) {
    std::vector<Entry> root{dir("d", {file("x", "z")})};
    Bytes img = Writer("hostile").build(root);
    // root is [., .., d]; point d's first child at d itself.
    const std::size_t d_at = root[2].offset;
    put_be32(img, d_at + 4, static_cast<std::uint32_t>(d_at));

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st);
    ASSERT_TRUE(st);
    EXPECT_TRUE(has_code(r.diagnostics, "romfs-cycle"));
    EXPECT_TRUE(r.truncated);
    EXPECT_NE(find(r, "d"), nullptr);    // the directory itself is still reported
    EXPECT_EQ(find(r, "d/d"), nullptr);  // and it does not contain itself
}

// A sibling list that loops back on itself is the other shape of the same bug.
TEST(Romfs, ASiblingListThatLoopsIsCut) {
    std::vector<Entry> root{file("a", "1"), file("b", "2")};
    Bytes img = Writer("loop").build(root);
    const std::size_t a_at = root[2].offset, b_at = root[3].offset;
    // b's next -> a, so the list never ends.
    const std::uint32_t type = kRegular;
    put_be32(img, b_at, static_cast<std::uint32_t>(a_at) | type);

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st);
    ASSERT_TRUE(st);
    EXPECT_TRUE(has_code(r.diagnostics, "romfs-cycle"));
    EXPECT_NE(find(r, "a"), nullptr);
    EXPECT_NE(find(r, "b"), nullptr);
}

TEST(Romfs, AnEntryClaimingMoreThanTheImageHoldsIsTruncatedNotTrusted) {
    std::vector<Entry> root{file("big", std::string(32, 'q'))};
    Bytes img = Writer("oob").build(root);
    put_be32(img, root[2].offset + 8, 0x7FFFFFFFu);

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st);
    ASSERT_TRUE(st);
    EXPECT_TRUE(has_code(r.diagnostics, "romfs-truncated-entry"));
    EXPECT_TRUE(r.truncated);
    const EntryResult* b = find(r, "big");
    ASSERT_NE(b, nullptr);
    // What was actually there is still emitted.
    EXPECT_LE(b->digests.bytes, img.size());
    EXPECT_GT(b->digests.bytes, 0u);
}

TEST(Romfs, AHardLinkPointingNowhereIsSkippedNotFollowed) {
    std::vector<Entry> root{file("real", "data"), special("bad", kHardLink, 0xFFFFFF0u)};
    Bytes img = Writer("hl").build(root);

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st);
    ASSERT_TRUE(st);
    EXPECT_TRUE(has_code(r.diagnostics, "romfs-bad-link"));
    EXPECT_NE(find(r, "real"), nullptr);
    EXPECT_EQ(find(r, "bad"), nullptr);
}

// A hard link that resolves gets the target's bytes under its own name, which
// is what an examiner expects to find on disk.
TEST(Romfs, AResolvableHardLinkCarriesTheTargetsBytes) {
    std::vector<Entry> root{file("real", "shared-content"), special("alias", kHardLink, 0)};
    Bytes img = Writer("hl2").build(root);
    put_be32(img, root[3].offset + 4, static_cast<std::uint32_t>(root[2].offset));

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st);
    ASSERT_TRUE(st);
    const EntryResult* a = find(r, "alias");
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(a->meta.kind, EntryKind::Regular);
    EXPECT_EQ(a->digests.bytes, std::string("shared-content").size());
    EXPECT_NE(a->meta.extra.find("hard_link_to"), a->meta.extra.end());
}

TEST(Romfs, ABrokenSuperblockChecksumIsReportedNotFatal) {
    std::vector<Entry> root{file("a", "1")};
    Bytes img = Writer("crc").build(root);
    img[12] ^= 0xFF;

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st);
    ASSERT_TRUE(st) << "a bad checksum is evidence of damage, not a reason to refuse the image";
    EXPECT_EQ(reader->info().attrs.at("checksum"), "mismatch");
    EXPECT_TRUE(has_code(r.diagnostics, "romfs-checksum-mismatch"));
    EXPECT_NE(find(r, "a"), nullptr);
}

TEST(Romfs, NoExtractStillListsEveryEntry) {
    std::vector<Entry> root{dir("etc", {file("passwd", "x")})};
    const Bytes img = Writer("v").build(root);

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st, /*extract=*/false);
    ASSERT_TRUE(st);
    EXPECT_EQ(paths_of(r), (std::vector<std::string>{"etc", "etc/passwd"}));
    const EntryResult* p = find(r, "etc/passwd");
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->meta.size, 1u);  // the size is still reported
    EXPECT_EQ(p->digests.bytes, 0u);
}

TEST(Romfs, MaxNodesStopsTheWalk) {
    std::vector<Entry> root;
    for (int i = 0; i < 40; ++i) root.push_back(file("f" + std::to_string(i), "x"));
    const Bytes img = Writer("many").build(root);

    auto reader = make();
    std::shared_ptr<const Source> keep;
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    ListingSink sink(true, Limits{});
    WalkOptions opts;
    opts.limits.max_nodes_per_fs = 10;
    WalkResult r;
    ASSERT_TRUE(reader->walk(sink, opts, r));
    EXPECT_TRUE(has_code(r.diagnostics, "romfs-limit-nodes"));
    EXPECT_TRUE(r.truncated);
    EXPECT_LE(r.entries, 10u);
}

// `-rom1fs-` appears inside blkid's compiled magic table, between `XFSB` and
// `iso9660`, and the audio corpus image has one. The reader has to refuse it:
// accepting it once meant `info()` returned a size read out of noise, the
// node took a 1.87 GB extent from it, and two gigabytes of unrelated image
// were carved to disk as a filesystem.
TEST(Romfs, TheMagicInsideAStringTableIsRefused) {
    // The bytes around the hit in corpus/audio-example, which is a table of
    // filesystem magics rather than a filesystem.
    const Bytes table{'-',  'r',  'o',  'm',  '1',  'f',  's',  '-',  0x78, 0x00, 0x13, 0x62,
                      0x28, 0x00, 0x41, 0xce, 0xfa, 0x7b, 0x1b, 0xb8, 0x08, 0x21, 0x72, 0x61,
                      0x29, 0x00, 0x41, 0x45, 0x3d, 0xcd, 0x28, 0x48, 0x08, 0x30, 0x6e, 0x78,
                      0x34, 0x08, 0x00, 0xb2, 'Q',  'N',  'X',  '4',  'F',  'S',  0x00, 0x00};
    Bytes img = table;
    img.resize(4096, 0);

    std::shared_ptr<const Source> keep;
    const Status st = make()->open(span_of(img, keep));
    EXPECT_FALSE(st) << "a volume name of raw bytes is the magic inside other data";
    EXPECT_NE(st.error.find("romfs-bad-name"), std::string::npos) << st.error;
}

// The size field is the one the node's extent comes from, so a value that
// cannot even hold the header it follows must not be accepted.
TEST(Romfs, ASizeTooSmallForItsOwnHeaderIsRefused) {
    std::vector<Entry> root{file("a", "1")};
    Bytes img = Writer("vol").build(root);
    put_be32(img, 8, 16u);

    std::shared_ptr<const Source> keep;
    const Status st = make()->open(span_of(img, keep));
    EXPECT_FALSE(st);
    EXPECT_NE(st.error.find("romfs-bad-size"), std::string::npos) << st.error;
}
