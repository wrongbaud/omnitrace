// yaffs2_test.cpp — the YAFFS2 reader and the chunk-grid parser under it.
//
// The fixtures (tests/fixtures/out/yaffs2*.img) are mkyaffs2 output in both
// spare layouts, and the conformance suite covers the live tree and the
// history against their ground truth. What is left, and what this file builds
// chunk by chunk, is everything mkyaffs2 does not emit: a different page and
// spare size, the tag form a running device uses that carries the object's
// summary alongside the header, a chunk whose tag checksum is broken, a hole,
// a hard link to an object that is not there, and a directory that is its own
// ancestor.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "omnitrace/core/Hash.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/core/Yaffs.h"
#include "omnitrace/discovery/Signature.h"
#include "omnitrace/filesystems/Filesystem.h"

using namespace omnitrace;
using namespace omnitrace::fs;

namespace {

using Bytes = std::vector<std::uint8_t>;

// Deliberately not the fixtures' 2048 + 64: the reader takes the geometry
// from the image, so a test that uses the same one proves less. 4096 + 128 is
// a layout real large-page NAND has.
constexpr std::uint32_t kPage = 4096;
constexpr std::uint32_t kSpare = 128;
constexpr std::uint32_t kRoot = 1;
constexpr std::uint32_t kDeletedParent = 4;
// `enum yaffs_obj_type`.
constexpr std::uint32_t kFile = 1, kSymlink = 2, kDirectory = 3, kHardlink = 4, kSpecial = 5;
// `struct yaffs_obj_hdr` offsets.
constexpr std::size_t kOffName = 10, kOffMode = 268, kOffUid = 272, kOffGid = 276,
                      kOffAtime = 280, kOffSizeLow = 292, kOffEquiv = 296, kOffAlias = 300,
                      kOffRdev = 460, kOffSizeHigh = 496;

std::unique_ptr<FilesystemReader> make_yaffs2() {
    return FilesystemRegistry::instance().create("yaffs2");
}

Span span_of(const Bytes& b, std::shared_ptr<const Source>& keep) {
    keep = std::make_shared<MemorySource>(b, "t");
    return Span::whole(keep);
}

void put_le32(Bytes& b, std::size_t at, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i) b[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
}

/// A YAFFS2 image, chunk by chunk. `tags_offset` picks the spare layout.
class Image {
   public:
    explicit Image(std::uint32_t tags_offset = 2) : tags_offset_(tags_offset) {}

    /// One chunk: `page_bytes` padded out to a page, then the packed tags and
    /// the checksum over them, everything else 0xFF as mkyaffs2 leaves it.
    std::size_t chunk(const Bytes& page_bytes, std::uint32_t seq, std::uint32_t obj_id,
                      std::uint32_t chunk_id, std::uint32_t n_bytes) {
        const std::size_t at = b_.size();
        b_.resize(at + kPage + kSpare, 0xFF);
        std::copy(page_bytes.begin(), page_bytes.end(),
                  b_.begin() + static_cast<std::ptrdiff_t>(at));
        const std::size_t t = at + kPage + tags_offset_;
        put_le32(b_, t, seq);
        put_le32(b_, t + 4, obj_id);
        put_le32(b_, t + 8, chunk_id);
        put_le32(b_, t + 12, n_bytes);
        const yaffs::Ecc e =
            yaffs::ecc_of(std::span<const std::uint8_t>(b_.data() + t, yaffs::kTagsSize));
        b_[t + 16] = e.col_parity;
        put_le32(b_, t + 20, e.line_parity);
        put_le32(b_, t + 24, e.line_parity_prime);
        return at;
    }

    /// An entirely unwritten chunk, the way erased flash reads.
    void erased() { b_.resize(b_.size() + kPage + kSpare, 0xFF); }

    /// A `yaffs_obj_hdr` page.
    static Bytes header(std::uint32_t type, std::uint32_t parent, const std::string& name,
                        std::uint32_t mode, std::uint64_t size = 0, std::int32_t equiv = -1,
                        const std::string& alias = {}, std::uint32_t rdev = 0) {
        // Both mkyaffs2 and the kernel memset the header to 0xFF and then
        // fill in the fields, which is why `sum_no_longer_used` at offset 8
        // reads 0xFFFF -- and why the signature can match on it.
        Bytes h(yaffs::kObjHeaderSize, 0xFF);
        put_le32(h, 0, type);
        put_le32(h, 4, parent);
        std::fill(h.begin() + kOffName, h.begin() + kOffName + 256, 0);
        std::fill(h.begin() + kOffAlias, h.begin() + kOffAlias + 160, 0);
        for (std::size_t i = 0; i < name.size() && i < 255; ++i)
            h[kOffName + i] = static_cast<std::uint8_t>(name[i]);
        put_le32(h, kOffMode, mode);
        put_le32(h, kOffUid, 1000);
        put_le32(h, kOffGid, 100);
        for (std::size_t k = 0; k < 3; ++k) put_le32(h, kOffAtime + 4 * k, 1700000000);
        put_le32(h, kOffSizeLow, static_cast<std::uint32_t>(size));
        put_le32(h, kOffSizeHigh, 0xFFFFFFFFu);  // unused: all ones, not zero
        put_le32(h, kOffEquiv, static_cast<std::uint32_t>(equiv));
        for (std::size_t i = 0; i < alias.size() && i < 159; ++i)
            h[kOffAlias + i] = static_cast<std::uint8_t>(alias[i]);
        put_le32(h, kOffRdev, rdev);
        return h;
    }

    /// The header chunk a running device writes: the tags carry the object's
    /// parent and type as well, packed into chunk_id and obj_id.
    std::size_t header_chunk_with_summary(const Bytes& page_bytes, std::uint32_t seq,
                                          std::uint32_t obj_id, std::uint32_t parent,
                                          std::uint32_t type, std::uint32_t size) {
        const std::uint32_t packed_chunk = yaffs::kExtraHeaderInfoFlag | parent;
        const std::uint32_t packed_obj = obj_id | (type << yaffs::kExtraObjectTypeShift);
        return chunk(page_bytes, seq, packed_obj, packed_chunk, size);
    }

    /// Flip one bit of the tags. A whole-byte flip can leave the checksum
    /// unchanged -- 0x10 and 0xEF have the same column parity and the same
    /// bit parity, so neither half of it moves -- whereas a single-bit error
    /// is exactly what this code is built to catch.
    void break_tags(std::size_t chunk_at) { b_[chunk_at + kPage + tags_offset_ + 4] ^= 0x01; }

    const Bytes& bytes() const { return b_; }

   private:
    Bytes b_;
    std::uint32_t tags_offset_;
};

Bytes data_page(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

struct Walked {
    WalkResult r;
    Status st = Status::success();
};

Walked walk_it(FilesystemReader& reader, bool history = false) {
    Walked w;
    const Limits lim;
    ListingSink sink(true, lim);
    WalkOptions opts;
    opts.limits = lim;
    opts.history = history;
    w.st = reader.walk(sink, opts, w.r);
    return w;
}

const EntryResult* entry_named(const WalkResult& r, const std::string& path) {
    for (const EntryResult& e : r.entries_out) {
        if (e.meta.path == path) return &e;
    }
    return nullptr;
}

bool has_code(const std::vector<Diagnostic>& ds, const std::string& code) {
    for (const Diagnostic& d : ds) {
        if (d.code == code) return true;
    }
    return false;
}

std::string sha256_of(const std::vector<Bytes>& parts) {
    Hasher h;
    for (const Bytes& b : parts) h.update(std::span<const std::uint8_t>(b.data(), b.size()));
    return h.finish().sha256;
}

/// `/etc` holding `/etc/passwd` of one chunk, in the Linux MTD spare layout.
/// Chunks go down the way a live filesystem writes them: data first, then the
/// object header that records the new size.
Image one_file(std::uint32_t tags_offset = 2) {
    Image img(tags_offset);
    img.chunk(Image::header(kDirectory, kRoot, "etc", 040755), 4096, 257, 0, 0xFFFF);
    img.chunk(data_page("root:x:0:0\n"), 4096, 258, 1, 11);
    img.chunk(Image::header(kFile, 257, "passwd", 0100644, 11), 4096, 258, 0, 0xFFFF);
    return img;
}

}  // namespace

TEST(Yaffs2Reader, TheSignatureAndValidatorIdentifyIt) {
    // The magic is the object header of a directory whose parent is the root,
    // which is the one byte pattern every non-trivial image has; everything
    // about the grid is then worked out by the validator. Four written chunks
    // is the least it treats as an image rather than a coincidence.
    Image img = one_file();
    img.chunk(Image::header(kDirectory, kRoot, "var", 040755), 4096, 260, 0, 0xFFFF);
    std::shared_ptr<const Source> keep;
    const std::vector<discovery::Finding> found =
        discovery::scan(span_of(img.bytes(), keep), discovery::SignatureSet::builtin(), {});
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].format, "yaffs2");
    EXPECT_EQ(found[0].offset, 0u);
    EXPECT_EQ(found[0].confidence, Confidence::Verified);
    EXPECT_EQ(found[0].attrs.at("page_size"), std::to_string(kPage));
    EXPECT_EQ(found[0].attrs.at("spare_size"), std::to_string(kSpare));
    EXPECT_EQ(found[0].attrs.at("spare_layout"), "linux-mtd");
    EXPECT_EQ(found[0].size, img.bytes().size());
}

TEST(Yaffs2Reader, FindsTheGridAndReadsTheTree) {
    const Image img = one_file();
    std::shared_ptr<const Source> keep;
    auto reader = make_yaffs2();
    ASSERT_NE(reader, nullptr);
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));

    const FilesystemInfo info = reader->info();
    // Nothing in the image records these; they are worked out from it.
    EXPECT_EQ(info.attrs.at("page_size"), std::to_string(kPage));
    EXPECT_EQ(info.attrs.at("spare_size"), std::to_string(kSpare));
    EXPECT_EQ(info.attrs.at("tags_offset"), "2");
    EXPECT_EQ(info.attrs.at("spare_layout"), "linux-mtd");
    EXPECT_EQ(info.attrs.at("objects"), "2");

    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(w.r.entries, 2u);
    const EntryResult* f = entry_named(w.r, "etc/passwd");
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->meta.size, 11u);
    EXPECT_EQ(f->meta.mode, 0100644u);
    EXPECT_EQ(f->meta.uid, 1000u);
    EXPECT_EQ(f->digests.sha256, sha256_of({data_page("root:x:0:0\n")}));
}

TEST(Yaffs2Reader, ReadsTheOtherSpareLayoutToo) {
    const Image img = one_file(/*tags_offset=*/0);
    std::shared_ptr<const Source> keep;
    auto reader = make_yaffs2();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    EXPECT_EQ(reader->info().attrs.at("tags_offset"), "0");
    EXPECT_EQ(reader->info().attrs.at("spare_layout"), "yaffs");
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_NE(entry_named(w.r, "etc/passwd"), nullptr);
}

TEST(Yaffs2Reader, ReadsTheTagFormThatCarriesTheSummary) {
    // A running device packs the object's parent and type into the tags of a
    // header chunk, so chunk_id and obj_id both have to be unpacked before
    // they mean anything. mkyaffs2 never writes this form.
    Image img;
    img.header_chunk_with_summary(Image::header(kDirectory, kRoot, "etc", 040755), 4096, 257,
                                  kRoot, kDirectory, 0);
    img.chunk(data_page("hello"), 4096, 258, 1, 5);
    img.header_chunk_with_summary(Image::header(kFile, 257, "greeting", 0100600, 5), 4096, 258,
                                  257, kFile, 5);

    std::shared_ptr<const Source> keep;
    auto reader = make_yaffs2();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    const EntryResult* f = entry_named(w.r, "etc/greeting");
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->meta.mode, 0100600u);
    EXPECT_EQ(f->digests.sha256, sha256_of({data_page("hello")}));
}

TEST(Yaffs2Reader, AHoleReadsAsZeros) {
    Image img;
    img.chunk(Image::header(kDirectory, kRoot, "d", 040755), 4096, 257, 0, 0xFFFF);
    // Block 0 is never written, which is how YAFFS2 makes a hole.
    img.chunk(data_page("tail"), 4096, 258, 2, 4);
    img.chunk(Image::header(kFile, 257, "sparse", 0100644, kPage + 4), 4096, 258, 0, 0xFFFF);

    std::shared_ptr<const Source> keep;
    auto reader = make_yaffs2();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    const EntryResult* f = entry_named(w.r, "d/sparse");
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->digests.bytes, kPage + 4);
    EXPECT_EQ(f->digests.sha256, sha256_of({Bytes(kPage, 0), data_page("tail")}));
}

TEST(Yaffs2Reader, AChunkWithABrokenChecksumIsNotBelieved) {
    Image img;
    img.chunk(Image::header(kDirectory, kRoot, "d", 040755), 4096, 257, 0, 0xFFFF);
    img.chunk(data_page("original"), 4096, 258, 1, 8);
    img.chunk(Image::header(kFile, 257, "f", 0100644, 8), 4096, 258, 0, 0xFFFF);
    // A later chunk for the same block whose tags are damaged. Taking it
    // would put the wrong bytes in the file.
    const std::size_t bad = img.chunk(data_page("REPLACED"), 4097, 258, 1, 8);
    img.break_tags(bad);

    std::shared_ptr<const Source> keep;
    auto reader = make_yaffs2();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    EXPECT_EQ(reader->info().attrs.at("bad_chunks"), "1");
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(entry_named(w.r, "d/f")->digests.sha256, sha256_of({data_page("original")}));
    EXPECT_TRUE(has_code(w.r.diagnostics, "yaffs2-bad-chunk"));
    EXPECT_TRUE(w.r.truncated);
}

TEST(Yaffs2Reader, AHardLinkTakesItsTargetsContentAndCounts) {
    Image img;
    img.chunk(Image::header(kDirectory, kRoot, "bin", 040755), 4096, 257, 0, 0xFFFF);
    img.chunk(data_page("ELF..."), 4096, 258, 1, 6);
    img.chunk(Image::header(kFile, 257, "busybox", 0100755, 6), 4096, 258, 0, 0xFFFF);
    img.chunk(Image::header(kHardlink, 257, "ash", 0, 0, /*equiv=*/258), 4096, 259, 0, 0xFFFF);

    std::shared_ptr<const Source> keep;
    auto reader = make_yaffs2();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    const EntryResult* ash = entry_named(w.r, "bin/ash");
    const EntryResult* bb = entry_named(w.r, "bin/busybox");
    ASSERT_NE(ash, nullptr);
    ASSERT_NE(bb, nullptr);
    // The link carries the target's mode, size and bytes, and both names
    // report the same object so a listing can pair them.
    EXPECT_EQ(ash->meta.inode, bb->meta.inode);
    EXPECT_EQ(ash->meta.mode, 0100755u);
    EXPECT_EQ(ash->digests.sha256, bb->digests.sha256);
    EXPECT_EQ(ash->meta.extra.at("hardlink_to"), "258");
    // YAFFS2 stores no link count; it is the number of links that point here.
    EXPECT_EQ(bb->meta.nlink, 2u);
}

TEST(Yaffs2Reader, AHardLinkToNothingIsListedNotInvented) {
    Image img;
    img.chunk(Image::header(kDirectory, kRoot, "bin", 040755), 4096, 257, 0, 0xFFFF);
    img.chunk(Image::header(kHardlink, 257, "dangling", 0, 0, /*equiv=*/999), 4096, 259, 0,
              0xFFFF);

    std::shared_ptr<const Source> keep;
    auto reader = make_yaffs2();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    const EntryResult* e = entry_named(w.r, "bin/dangling");
    ASSERT_NE(e, nullptr);
    EXPECT_EQ(e->meta.size, 0u);
    EXPECT_TRUE(has_code(w.r.diagnostics, "yaffs2-broken-hardlink"));
}

TEST(Yaffs2Reader, SymlinksAndDevicesComeOutOfTheHeader) {
    Image img;
    img.chunk(Image::header(kDirectory, kRoot, "dev", 040755), 4096, 257, 0, 0xFFFF);
    img.chunk(Image::header(kSymlink, 257, "sh", 0120777, 0, -1, "busybox"), 4096, 258, 0,
              0xFFFF);
    // mknod's old dev_t: minor's low byte, then major, then minor's high bits.
    img.chunk(Image::header(kSpecial, 257, "null", 020666, 0, -1, {}, (1u << 8) | 3u), 4096, 259,
              0, 0xFFFF);

    std::shared_ptr<const Source> keep;
    auto reader = make_yaffs2();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    const EntryResult* sh = entry_named(w.r, "dev/sh");
    ASSERT_NE(sh, nullptr);
    EXPECT_EQ(sh->meta.kind, EntryKind::Symlink);
    EXPECT_EQ(sh->meta.link_target, "busybox");
    const EntryResult* null = entry_named(w.r, "dev/null");
    ASSERT_NE(null, nullptr);
    EXPECT_EQ(null->meta.kind, EntryKind::CharDevice);
    EXPECT_EQ(null->meta.rdev_major, 1u);
    EXPECT_EQ(null->meta.rdev_minor, 3u);
}

TEST(Yaffs2Reader, ObjectsInAParentCycleAreStillRecovered) {
    // A YAFFS2 object carries its own parent, so two directories can point at
    // each other. Nothing reachable from the root points into that pair, so
    // the live tree cannot show it -- and neither can a mount. The data is
    // still on the medium, and the history pass is what gets it back.
    Image img;
    img.chunk(Image::header(kDirectory, 258, "a", 040755), 4096, 257, 0, 0xFFFF);
    img.chunk(Image::header(kDirectory, 257, "b", 040755), 4096, 258, 0, 0xFFFF);
    img.chunk(data_page("stranded"), 4096, 259, 1, 8);
    img.chunk(Image::header(kFile, 257, "f", 0100644, 8), 4096, 259, 0, 0xFFFF);

    std::shared_ptr<const Source> keep;
    auto reader = make_yaffs2();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked live = walk_it(*reader);
    ASSERT_TRUE(live.st);
    EXPECT_EQ(live.r.entries, 0u);

    const Walked w = walk_it(*reader, /*history=*/true);
    ASSERT_TRUE(w.st);
    const EntryResult* f = entry_named(w.r, "lost+found/#259-f");
    ASSERT_NE(f, nullptr);
    EXPECT_TRUE(f->meta.deleted);
    EXPECT_EQ(f->meta.extra.at("name_lost"), "true");
    EXPECT_EQ(f->digests.sha256, sha256_of({data_page("stranded")}));
}

TEST(Yaffs2Reader, HistoryRecoversADeletedFileUnderItsOwnName) {
    Image img = one_file();
    // Deleting is writing the object's header again with the parent YAFFS2
    // reserves for deleted objects. The data chunks stay where they were.
    img.chunk(Image::header(kFile, kDeletedParent, "passwd", 0100644, 11), 4097, 258, 0, 0xFFFF);

    std::shared_ptr<const Source> keep;
    auto reader = make_yaffs2();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    Walked live = walk_it(*reader, /*history=*/false);
    ASSERT_TRUE(live.st);
    EXPECT_EQ(live.r.entries, 1u);  // only "etc"
    EXPECT_EQ(entry_named(live.r, "etc/passwd"), nullptr);

    const Walked w = walk_it(*reader, /*history=*/true);
    ASSERT_TRUE(w.st);
    EXPECT_GE(w.r.deleted, 1u);
    // The header before the deletion still says which directory it was in and
    // what it was called, so the entry keeps its real path.
    const EntryResult* gone = entry_named(w.r, "etc/passwd");
    ASSERT_NE(gone, nullptr);
    EXPECT_TRUE(gone->meta.deleted);
    EXPECT_EQ(gone->meta.extra.at("parent"), "deleted");
    EXPECT_EQ(gone->digests.sha256, sha256_of({data_page("root:x:0:0\n")}));
}

TEST(Yaffs2Reader, HistoryRecoversAnEarlierVersion) {
    Image img = one_file();
    img.chunk(data_page("rewritten!"), 4097, 258, 1, 10);
    img.chunk(Image::header(kFile, 257, "passwd", 0100644, 10), 4097, 258, 0, 0xFFFF);

    std::shared_ptr<const Source> keep;
    auto reader = make_yaffs2();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader, /*history=*/true);
    ASSERT_TRUE(w.st);
    const EntryResult* live = entry_named(w.r, "etc/passwd");
    ASSERT_NE(live, nullptr);
    EXPECT_EQ(live->meta.version, 0u);
    EXPECT_EQ(live->digests.sha256, sha256_of({data_page("rewritten!")}));

    const EntryResult* old_state = nullptr;
    for (const EntryResult& e : w.r.entries_out)
        if (e.meta.superseded && e.meta.path == "etc/passwd") old_state = &e;
    ASSERT_NE(old_state, nullptr);
    EXPECT_EQ(old_state->meta.version, 1u);
    EXPECT_EQ(old_state->meta.size, 11u);
    EXPECT_EQ(old_state->digests.sha256, sha256_of({data_page("root:x:0:0\n")}));
    EXPECT_EQ(w.r.superseded, 1u);
}

TEST(Yaffs2Reader, HistoryLeavesTheLiveTreeAlone) {
    Image img = one_file();
    img.chunk(data_page("rewritten!"), 4097, 258, 1, 10);
    img.chunk(Image::header(kFile, 257, "passwd", 0100644, 10), 4097, 258, 0, 0xFFFF);

    std::shared_ptr<const Source> keep;
    auto a = make_yaffs2();
    auto b = make_yaffs2();
    ASSERT_TRUE(a->open(span_of(img.bytes(), keep)));
    ASSERT_TRUE(b->open(span_of(img.bytes(), keep)));
    const Walked off = walk_it(*a, false);
    const Walked on = walk_it(*b, true);
    EXPECT_EQ(off.r.superseded, 0u);
    EXPECT_EQ(off.r.deleted, 0u);
    const EntryResult* l1 = entry_named(off.r, "etc/passwd");
    const EntryResult* l2 = entry_named(on.r, "etc/passwd");
    ASSERT_NE(l1, nullptr);
    ASSERT_NE(l2, nullptr);
    EXPECT_EQ(l1->meta.version, l2->meta.version);
    EXPECT_EQ(l1->digests.sha256, l2->digests.sha256);
}

TEST(Yaffs2Reader, OpenRejectsWhatIsNotAChunkGrid) {
    std::shared_ptr<const Source> keep;
    auto reader = make_yaffs2();

    const Bytes junk(64 * 1024, 0x5A);
    EXPECT_FALSE(reader->open(span_of(junk, keep)));

    const Bytes erased(64 * 1024, 0xFF);
    EXPECT_FALSE(reader->open(span_of(erased, keep)));

    EXPECT_FALSE(reader->open(span_of(Bytes{}, keep)));

    // A grid whose chunks verify but that holds no object header at all.
    Image only_data;
    for (int i = 0; i < 4; ++i) only_data.chunk(data_page("x"), 4096, 300, 1, 1);
    EXPECT_FALSE(reader->open(span_of(only_data.bytes(), keep)));
}

TEST(Yaffs2Ecc, MatchesTheValuesYaffsStores) {
    // The column parity is shifted right by two and masked to six bits before
    // it is stored, which an implementation that skips it gets wrong: these
    // are the bytes mkyaffs2 wrote for the first chunk of the fixture.
    const Bytes tags{0x00, 0x10, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00};
    const yaffs::Ecc e = yaffs::ecc_of(std::span<const std::uint8_t>(tags.data(), tags.size()));
    EXPECT_EQ(e.col_parity, 0x25u);
    EXPECT_EQ(e.line_parity, 0u);
    EXPECT_EQ(e.line_parity_prime, 0xFFFFFFFFu);
}
