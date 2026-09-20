// ubifs_test.cpp — the UBIFS reader, on the shapes the fixture cannot show.
//
// tests/fixtures/out/ubifs.img is a clean mkfs.ubifs image, so its journal is
// empty and nothing in it is damaged. The conformance suite
// (fixture_conformance_test.cpp) covers the live tree against that ground
// truth. What is left, and what this file builds node by node, is everything a
// dump from a running or a broken device has: writes that are in the journal
// and not yet in the index, an unlink that only the journal records, a torn
// node, an index branch that points into nothing, a directory that is its own
// ancestor, and a file with a hole.
#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "../../../src/discovery/crc32.h"
#include "omnitrace/core/Hash.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/filesystems/Filesystem.h"

using namespace omnitrace;
using namespace omnitrace::fs;

namespace {

using Bytes = std::vector<std::uint8_t>;

// A deliberately small geometry: the reader takes these from the superblock.
constexpr std::uint32_t kLebSize = 8192;
constexpr std::uint32_t kMinIo = 512;
constexpr std::uint32_t kLebCnt = 8;
constexpr std::uint32_t kLogLeb = 3, kBudLeb = 4, kLeafLeb = 6, kIdxLeb = 7;
constexpr std::uint32_t kNodeMagic = 0x06101831U;
constexpr std::uint32_t kRootIno = 1;
// Node types and key types, from fs/ubifs/ubifs-media.h.
constexpr std::uint8_t kTIno = 0, kTData = 1, kTDent = 2, kTSb = 6, kTMst = 7, kTRef = 8,
                       kTIdx = 9, kTCs = 10;
constexpr std::uint32_t kKIno = 0, kKData = 1, kKDent = 2;
// Directory entry types.
constexpr std::uint8_t kItReg = 0, kItDir = 1;

std::unique_ptr<FilesystemReader> make_ubifs() {
    return FilesystemRegistry::instance().create("ubifs");
}

Span span_of(const Bytes& b, std::shared_ptr<const Source>& keep) {
    keep = std::make_shared<MemorySource>(b, "t");
    return Span::whole(keep);
}

void put_le16(Bytes& b, std::size_t at, std::uint16_t v) {
    for (std::size_t i = 0; i < 2; ++i) b[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
}
void put_le32(Bytes& b, std::size_t at, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i) b[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
}
void put_le64(Bytes& b, std::size_t at, std::uint64_t v) {
    for (std::size_t i = 0; i < 8; ++i) b[at + i] = static_cast<std::uint8_t>(v >> (8 * i));
}

std::uint64_t align8(std::uint64_t v) {
    return (v + 7) & ~std::uint64_t{7};
}

// One UBIFS volume, built erase block by erase block.
class Image {
   public:
    Image() : b_(static_cast<std::size_t>(kLebCnt) * kLebSize, 0xFF) {}

    std::size_t at(std::uint32_t lnum, std::uint32_t offs = 0) const {
        return static_cast<std::size_t>(lnum) * kLebSize + offs;
    }

    // The 24-byte common header, and the crc32 over everything after it.
    void seal(std::size_t node, std::uint8_t type, std::uint32_t len, std::uint64_t sqnum) {
        put_le32(b_, node, kNodeMagic);
        put_le64(b_, node + 8, sqnum);
        put_le32(b_, node + 16, len);
        b_[node + 20] = type;
        b_[node + 21] = 0;
        b_[node + 22] = b_[node + 23] = 0;
        put_le32(b_, node + 4,
                 discovery::crc32_ubi(
                     std::span<const std::uint8_t>(b_.data() + node + 8, len - 8)));
    }

    void key(std::size_t node, std::uint32_t inum, std::uint32_t ktype, std::uint32_t extra = 0) {
        put_le32(b_, node + 24, inum);
        put_le32(b_, node + 28, (ktype << 29) | extra);
    }

    void superblock(std::uint32_t leb_cnt = kLebCnt) {
        const std::size_t n = at(0);
        for (std::size_t i = 0; i < 4096; ++i) b_[n + i] = 0;
        put_le32(b_, n + 32, kMinIo);
        put_le32(b_, n + 36, kLebSize);
        put_le32(b_, n + 40, leb_cnt);
        put_le32(b_, n + 44, leb_cnt);  // max_leb_cnt
        put_le32(b_, n + 56, 1);        // log_lebs
        put_le32(b_, n + 60, 1);        // lpt_lebs
        put_le32(b_, n + 64, 1);        // orph_lebs
        put_le32(b_, n + 72, 8);        // fanout
        put_le32(b_, n + 80, 4);        // fmt_version
        put_le16(b_, n + 84, 0);        // default compression: none
        seal(n, kTSb, 4096, 1);
    }

    /// Both master copies, naming the index root. `cmt` is the commit number.
    void master(std::uint32_t root_lnum, std::uint32_t root_offs, std::uint32_t root_len,
                std::uint64_t cmt = 7, std::uint32_t log_lnum = kLogLeb) {
        for (std::uint32_t lnum : {1U, 2U}) {
            const std::size_t n = at(lnum);
            for (std::size_t i = 0; i < 512; ++i) b_[n + i] = 0;
            put_le64(b_, n + 24, 200);  // highest_inum
            put_le64(b_, n + 32, cmt);
            put_le32(b_, n + 44, log_lnum);
            put_le32(b_, n + 48, root_lnum);
            put_le32(b_, n + 52, root_offs);
            put_le32(b_, n + 56, root_len);
            put_le32(b_, n + 164, kLebCnt);
            seal(n, kTMst, 512, 2);
        }
    }

    /// The commit-start node the log head must begin with.
    void log_start(std::uint64_t cmt = 7) {
        const std::size_t n = at(kLogLeb);
        for (std::size_t i = 0; i < 32; ++i) b_[n + i] = 0;
        put_le64(b_, n + 24, cmt);
        seal(n, kTCs, 32, 3);
        log_next_ = 32;
    }

    /// A reference node naming a bud, written after the commit-start node.
    void log_ref(std::uint32_t bud_lnum, std::uint32_t bud_offs, std::uint64_t sqnum) {
        const std::size_t n = at(kLogLeb, static_cast<std::uint32_t>(log_next_));
        for (std::size_t i = 0; i < 64; ++i) b_[n + i] = 0;
        put_le32(b_, n + 24, bud_lnum);
        put_le32(b_, n + 28, bud_offs);
        put_le32(b_, n + 32, 0);  // jhead
        seal(n, kTRef, 64, sqnum);
        log_next_ = align8(log_next_ + 64);
    }

    // --- leaf nodes. Each returns (lnum, offs, len) for an index branch. ---

    struct Where {
        std::uint32_t lnum = 0, offs = 0, len = 0;
    };

    Where inode(std::uint32_t lnum, std::uint32_t inum, std::uint32_t mode, std::uint64_t size,
                std::uint64_t sqnum, const std::string& inline_data = {}) {
        const std::uint32_t len = static_cast<std::uint32_t>(160 + inline_data.size());
        const std::size_t n = place(lnum, len);
        for (std::size_t i = 0; i < len; ++i) b_[n + i] = 0;
        key(n, inum, kKIno);
        put_le64(b_, n + 40, 1);     // creat_sqnum
        put_le64(b_, n + 48, size);  // size
        put_le64(b_, n + 56, 1700000001);
        put_le64(b_, n + 64, 1700000002);
        put_le64(b_, n + 72, 1700000003);
        put_le32(b_, n + 92, 1);     // nlink
        put_le32(b_, n + 96, 1000);  // uid
        put_le32(b_, n + 100, 100);  // gid
        put_le32(b_, n + 104, mode);
        put_le32(b_, n + 112, static_cast<std::uint32_t>(inline_data.size()));
        for (std::size_t i = 0; i < inline_data.size(); ++i)
            b_[n + 160 + i] = static_cast<std::uint8_t>(inline_data[i]);
        seal(n, kTIno, len, sqnum);
        return {lnum, static_cast<std::uint32_t>(n - at(lnum)), len};
    }

    Where dent(std::uint32_t lnum, std::uint32_t parent, const std::string& name,
               std::uint64_t child, std::uint8_t itype, std::uint64_t sqnum,
               std::uint32_t hash = 1) {
        const std::uint32_t len = static_cast<std::uint32_t>(56 + name.size());
        const std::size_t n = place(lnum, len);
        for (std::size_t i = 0; i < len; ++i) b_[n + i] = 0;
        key(n, parent, kKDent, hash);
        put_le64(b_, n + 40, child);
        b_[n + 49] = itype;
        put_le16(b_, n + 50, static_cast<std::uint16_t>(name.size()));
        for (std::size_t i = 0; i < name.size(); ++i)
            b_[n + 56 + i] = static_cast<std::uint8_t>(name[i]);
        seal(n, kTDent, len, sqnum);
        return {lnum, static_cast<std::uint32_t>(n - at(lnum)), len};
    }

    Where data(std::uint32_t lnum, std::uint32_t inum, std::uint32_t block,
               const std::string& payload, std::uint64_t sqnum) {
        const std::uint32_t len = static_cast<std::uint32_t>(48 + payload.size());
        const std::size_t n = place(lnum, len);
        for (std::size_t i = 0; i < len; ++i) b_[n + i] = 0;
        key(n, inum, kKData, block);
        put_le32(b_, n + 40, static_cast<std::uint32_t>(payload.size()));
        put_le16(b_, n + 44, 0);  // compression: none
        for (std::size_t i = 0; i < payload.size(); ++i)
            b_[n + 48 + i] = static_cast<std::uint8_t>(payload[i]);
        seal(n, kTData, len, sqnum);
        return {lnum, static_cast<std::uint32_t>(n - at(lnum)), len};
    }

    /// A level-0 index node naming `leaves`. Returns where it landed.
    Where index(std::uint32_t lnum, const std::vector<std::pair<Where, std::array<std::uint32_t, 3>>>& leaves) {
        const std::uint32_t len = static_cast<std::uint32_t>(28 + leaves.size() * 20);
        const std::size_t n = place(lnum, len);
        for (std::size_t i = 0; i < len; ++i) b_[n + i] = 0;
        put_le16(b_, n + 24, static_cast<std::uint16_t>(leaves.size()));
        put_le16(b_, n + 26, 0);  // level 0: the branches point at leaves
        std::size_t br = n + 28;
        for (const auto& [w, k] : leaves) {
            put_le32(b_, br, w.lnum);
            put_le32(b_, br + 4, w.offs);
            put_le32(b_, br + 8, w.len);
            put_le32(b_, br + 12, k[0]);
            put_le32(b_, br + 16, (k[1] << 29) | k[2]);
            br += 20;
        }
        seal(n, kTIdx, len, 4);
        return {lnum, static_cast<std::uint32_t>(n - at(lnum)), len};
    }

    void corrupt(std::uint32_t lnum, std::uint32_t offs) { b_[at(lnum, offs) + 30] ^= 0xFF; }

    const Bytes& bytes() const { return b_; }
    Bytes& bytes() { return b_; }

   private:
    std::size_t place(std::uint32_t lnum, std::uint32_t len) {
        std::uint64_t& next = next_[lnum];
        const std::size_t n = at(lnum, static_cast<std::uint32_t>(next));
        next = align8(next + len);
        return n;
    }

    Bytes b_;
    std::map<std::uint32_t, std::uint64_t> next_;
    std::uint64_t log_next_ = 0;
};

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

/// The SHA-256 of the given byte runs concatenated: the recovered content is
/// only right if its bytes are, not just its length.
std::string sha256_of(const std::vector<Bytes>& parts) {
    Hasher h;
    for (const Bytes& b : parts) h.update(std::span<const std::uint8_t>(b.data(), b.size()));
    return h.finish().sha256;
}

bool has_code(const std::vector<Diagnostic>& ds, const std::string& code) {
    for (const Diagnostic& d : ds) {
        if (d.code == code) return true;
    }
    return false;
}

using Branch = std::pair<Image::Where, std::array<std::uint32_t, 3>>;

/// `/hello.txt`, one block, committed to the index. The base every test
/// builds on.
///
/// The sqnums follow the order UBIFS writes in: a write puts its data nodes
/// down first and the inode node, carrying the new size and times, last. The
/// history pass relies on that -- the state of a file when an inode node was
/// written is the blocks whose sqnum does not pass it.
Image one_file() {
    Image img;
    img.superblock();
    img.log_start();
    const Image::Where root_ino = img.inode(kLeafLeb, kRootIno, 0040755, 0, 10);
    const Image::Where f_data = img.data(kLeafLeb, 20, 0, "index", 11);
    const Image::Where f_dent = img.dent(kLeafLeb, kRootIno, "hello.txt", 20, kItReg, 12);
    const Image::Where f_ino = img.inode(kLeafLeb, 20, 0100644, 5, 13);
    const Image::Where idx = img.index(
        kIdxLeb, std::vector<Branch>{{root_ino, {kRootIno, kKIno, 0}},
                                     {f_ino, {20, kKIno, 0}},
                                     {f_dent, {kRootIno, kKDent, 1}},
                                     {f_data, {20, kKData, 0}}});
    img.master(idx.lnum, idx.offs, idx.len);
    return img;
}

}  // namespace

TEST(UbifsReader, ReadsTheCommittedIndex) {
    const Image img = one_file();
    std::shared_ptr<const Source> keep;
    auto reader = make_ubifs();
    ASSERT_NE(reader, nullptr);
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    ASSERT_EQ(w.r.entries, 1u);
    const EntryResult* f = entry_named(w.r, "hello.txt");
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->meta.size, 5u);
    // FileMeta::mode keeps the type bits when the filesystem has them.
    EXPECT_EQ(f->meta.mode, 0100644u);
    EXPECT_EQ(f->meta.uid, 1000u);
    EXPECT_EQ(f->digests.bytes, 5u);
    EXPECT_EQ(reader->info().attrs.at("inodes"), "2");
    EXPECT_EQ(reader->info().attrs.at("bud_lebs"), "0");
}

TEST(UbifsReader, TheJournalWinsOverTheIndex) {
    Image img = one_file();
    // A bud holding a newer version of the same file, the way a write since
    // the last commit sits on the medium: in the journal, not the index.
    img.data(kBudLeb, 20, 0, "journal!", 100);
    img.inode(kBudLeb, 20, 0100644, 8, 101);
    img.log_ref(kBudLeb, 0, 102);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubifs();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    const EntryResult* f = entry_named(w.r, "hello.txt");
    ASSERT_NE(f, nullptr);
    // 8 bytes of "journal!", not the 5 the index still says.
    EXPECT_EQ(f->meta.size, 8u);
    EXPECT_EQ(f->digests.bytes, 8u);
    EXPECT_EQ(reader->info().attrs.at("bud_lebs"), "1");
    EXPECT_EQ(reader->info().attrs.at("journal_nodes"), "2");
}

TEST(UbifsReader, AnUnlinkInTheJournalRemovesTheName) {
    Image img = one_file();
    // UBIFS unlinks by writing an entry that points at inode 0.
    img.dent(kBudLeb, kRootIno, "hello.txt", 0, kItReg, 100);
    img.log_ref(kBudLeb, 0, 101);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubifs();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(w.r.entries, 0u);
    EXPECT_EQ(reader->info().attrs.at("unlink_records"), "1");
}

TEST(UbifsReader, ATornNodeEndsTheBudAndKeepsWhatCameBefore) {
    Image img = one_file();
    img.data(kBudLeb, 20, 0, "journal!", 100);
    const std::size_t torn = img.at(kBudLeb, 56);  // the node after the data one
    img.inode(kBudLeb, 20, 0100644, 8, 101);
    img.bytes()[torn + 30] ^= 0xFF;  // break its CRC, as an interrupted write does
    img.log_ref(kBudLeb, 0, 102);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubifs();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    // The data node before the tear was applied; the torn inode node was not,
    // so the size still comes from the index.
    const EntryResult* f = entry_named(w.r, "hello.txt");
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->meta.size, 5u);
    EXPECT_EQ(reader->info().attrs.at("journal_nodes"), "1");
}

TEST(UbifsReader, AJournalItCannotReachIsReportedNotIgnored) {
    // The index root is intact; only the master node's log head is wrong, so
    // the tree reads back as of the last commit and anything written after it
    // is unreachable. That is a warning, never a silent omission: on a dump
    // from a running device the journal is where the recent changes are.
    Image img = one_file();
    constexpr std::uint32_t kIndexNodeLen = 28 + 4 * 20;  // four branches
    img.master(kIdxLeb, 0, kIndexNodeLen, 7, /*log_lnum=*/kBudLeb);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubifs();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_NE(entry_named(w.r, "hello.txt"), nullptr);  // the index still read
    EXPECT_TRUE(has_code(w.r.diagnostics, "ubifs-journal-unreplayed"));
    EXPECT_TRUE(w.r.truncated);
}

TEST(UbifsReader, AHoleReadsAsZeros) {
    Image img;
    img.superblock();
    img.log_start();
    const Image::Where root_ino = img.inode(kLeafLeb, kRootIno, 0040755, 0, 10);
    // Block 0 is simply not written, which is how UBIFS makes a hole.
    const Image::Where f_data = img.data(kLeafLeb, 20, 1, "tail", 11);
    const Image::Where f_dent = img.dent(kLeafLeb, kRootIno, "sparse.bin", 20, kItReg, 12);
    const Image::Where f_ino = img.inode(kLeafLeb, 20, 0100644, 4096 + 4, 13);
    const Image::Where idx =
        img.index(kIdxLeb, std::vector<Branch>{{root_ino, {kRootIno, kKIno, 0}},
                                               {f_ino, {20, kKIno, 0}},
                                               {f_dent, {kRootIno, kKDent, 1}},
                                               {f_data, {20, kKData, 1}}});
    img.master(idx.lnum, idx.offs, idx.len);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubifs();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    const EntryResult* f = entry_named(w.r, "sparse.bin");
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->digests.bytes, 4100u);
    // 4096 zeros then "tail": the hole is not closed up.
    Hasher h;
    const Bytes zeros(4096, 0);
    h.update(std::span<const std::uint8_t>(zeros.data(), zeros.size()));
    const Bytes tail{'t', 'a', 'i', 'l'};
    h.update(std::span<const std::uint8_t>(tail.data(), tail.size()));
    EXPECT_EQ(f->digests.sha256, h.finish().sha256);
}

TEST(UbifsReader, ANameWhoseInodeIsGoneIsStillListed) {
    Image img;
    img.superblock();
    img.log_start();
    const Image::Where root_ino = img.inode(kLeafLeb, kRootIno, 0040755, 0, 10);
    const Image::Where f_dent = img.dent(kLeafLeb, kRootIno, "orphan", 20, kItReg, 12);
    const Image::Where idx = img.index(
        kIdxLeb, std::vector<Branch>{{root_ino, {kRootIno, kKIno, 0}}, {f_dent, {kRootIno, kKDent, 1}}});
    img.master(idx.lnum, idx.offs, idx.len);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubifs();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    // The name is evidence even with no inode behind it.
    ASSERT_EQ(w.r.entries, 1u);
    EXPECT_NE(entry_named(w.r, "orphan"), nullptr);
    EXPECT_TRUE(has_code(w.r.diagnostics, "ubifs-missing-inode"));
}

TEST(UbifsReader, ADirectoryThatIsItsOwnAncestorStopsTheBranch) {
    Image img;
    img.superblock();
    img.log_start();
    const Image::Where root_ino = img.inode(kLeafLeb, kRootIno, 0040755, 0, 10);
    const Image::Where d_ino = img.inode(kLeafLeb, 20, 0040755, 0, 11);
    const Image::Where d_dent = img.dent(kLeafLeb, kRootIno, "loop", 20, kItDir, 12);
    // "loop/back" names the root again, so a naive walk never ends.
    const Image::Where back = img.dent(kLeafLeb, 20, "back", kRootIno, kItDir, 13, 2);
    const Image::Where idx = img.index(
        kIdxLeb, std::vector<Branch>{{root_ino, {kRootIno, kKIno, 0}},
                                     {d_ino, {20, kKIno, 0}},
                                     {d_dent, {kRootIno, kKDent, 1}},
                                     {back, {20, kKDent, 2}}});
    img.master(idx.lnum, idx.offs, idx.len);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubifs();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_TRUE(has_code(w.r.diagnostics, "ubifs-directory-loop"));
    // "loop" and "loop/back" are both listed; the walk just does not descend
    // through "back" a second time.
    EXPECT_NE(entry_named(w.r, "loop"), nullptr);
    EXPECT_NE(entry_named(w.r, "loop/back"), nullptr);
    EXPECT_LT(w.r.entries, 10u);
}

// --- history -----------------------------------------------------------
//
// UBIFS never overwrites in place, so the node a write replaced stays where
// it was until garbage collection reclaims its erase block. Recovering those
// is a sweep of the medium, not a walk of the index, and these cover what the
// sweep has to get right.

TEST(UbifsReader, HistoryRecoversTheVersionTheJournalReplaced) {
    Image img = one_file();  // the index holds "index" (5 bytes)
    img.data(kBudLeb, 20, 0, "journal!", 100);
    img.inode(kBudLeb, 20, 0100644, 8, 101);
    img.log_ref(kBudLeb, 0, 102);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubifs();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader, /*history=*/true);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(w.r.superseded, 1u);

    const EntryResult* live = entry_named(w.r, "hello.txt");
    ASSERT_NE(live, nullptr);
    EXPECT_EQ(live->meta.size, 8u);
    EXPECT_EQ(live->meta.version, 0u);  // the live entry is never numbered

    // The committed state is still on the medium and still readable.
    const EntryResult* old_state = nullptr;
    for (const EntryResult& e : w.r.entries_out)
        if (e.meta.superseded && e.meta.path == "hello.txt") old_state = &e;
    ASSERT_NE(old_state, nullptr);
    EXPECT_EQ(old_state->meta.version, 1u);
    EXPECT_EQ(old_state->meta.size, 5u);
    EXPECT_EQ(old_state->digests.sha256, sha256_of({{'i', 'n', 'd', 'e', 'x'}}));
    EXPECT_EQ(old_state->meta.extra.count("sqnum"), 1u);
}

TEST(UbifsReader, HistoryRecoversADeletedFileWithItsContents) {
    Image img = one_file();
    img.dent(kBudLeb, kRootIno, "hello.txt", 0, kItReg, 100);  // the unlink
    img.log_ref(kBudLeb, 0, 101);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubifs();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader, /*history=*/true);
    ASSERT_TRUE(w.st);
    // Gone from the live tree, recovered by the history pass.
    EXPECT_EQ(w.r.deleted, 1u);
    const EntryResult* gone = entry_named(w.r, "hello.txt");
    ASSERT_NE(gone, nullptr);
    EXPECT_TRUE(gone->meta.deleted);
    EXPECT_FALSE(gone->meta.superseded);
    EXPECT_EQ(gone->meta.size, 5u);
    EXPECT_EQ(gone->digests.sha256, sha256_of({{'i', 'n', 'd', 'e', 'x'}}));
    EXPECT_EQ(gone->meta.extra.count("unlink_node_offset"), 1u);
}

TEST(UbifsReader, HistoryFindsNodesNothingPointsAt) {
    Image img = one_file();
    // An inode and its data in a block no index branch and no bud names:
    // a file whose directory entry was reclaimed, or one unlinked while it
    // was still open. Only a sweep of the medium finds it.
    img.data(kBudLeb, 55, 0, "orphan", 200);
    img.inode(kBudLeb, 55, 0100600, 6, 201);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubifs();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    EXPECT_EQ(reader->info().attrs.at("bud_lebs"), "0");  // nothing referenced it
    const Walked w = walk_it(*reader, /*history=*/true);
    ASSERT_TRUE(w.st);
    const EntryResult* found = entry_named(w.r, "lost+found/#55");
    ASSERT_NE(found, nullptr);
    EXPECT_TRUE(found->meta.deleted);
    EXPECT_EQ(found->meta.inode, 55u);
    EXPECT_EQ(found->meta.mode, 0100600u);
    EXPECT_EQ(found->digests.sha256, sha256_of({{'o', 'r', 'p', 'h', 'a', 'n'}}));
    EXPECT_EQ(found->meta.extra.at("name_lost"), "true");
}

TEST(UbifsReader, HistoryLeavesTheLiveTreeAlone) {
    Image img = one_file();
    img.data(kBudLeb, 20, 0, "journal!", 100);
    img.inode(kBudLeb, 20, 0100644, 8, 101);
    img.log_ref(kBudLeb, 0, 102);

    std::shared_ptr<const Source> keep;
    auto a = make_ubifs();
    auto b = make_ubifs();
    ASSERT_TRUE(a->open(span_of(img.bytes(), keep)));
    ASSERT_TRUE(b->open(span_of(img.bytes(), keep)));
    const Walked off = walk_it(*a, false);
    const Walked on = walk_it(*b, true);
    EXPECT_EQ(off.r.superseded, 0u);
    EXPECT_EQ(off.r.deleted, 0u);
    for (const EntryResult& e : off.r.entries_out) {
        EXPECT_FALSE(e.meta.superseded);
        EXPECT_FALSE(e.meta.deleted);
    }
    // The same live entry, byte for byte, in both modes.
    const EntryResult* l1 = entry_named(off.r, "hello.txt");
    const EntryResult* l2 = entry_named(on.r, "hello.txt");
    ASSERT_NE(l1, nullptr);
    ASSERT_NE(l2, nullptr);
    EXPECT_EQ(l1->meta.size, l2->meta.size);
    EXPECT_EQ(l1->meta.version, l2->meta.version);
    EXPECT_EQ(l1->digests.sha256, l2->digests.sha256);
}

TEST(UbifsReader, AnUnlinkWhoseTargetIsGoneIsReportedNotInvented) {
    Image img = one_file();
    // An unlink for a name that has no earlier entry on the medium: the
    // record says something was deleted, but not what.
    img.dent(kBudLeb, kRootIno, "vanished", 0, kItReg, 100, /*hash=*/9);
    img.log_ref(kBudLeb, 0, 101);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubifs();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader, /*history=*/true);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(entry_named(w.r, "vanished"), nullptr);
    EXPECT_TRUE(has_code(w.r.diagnostics, "ubifs-deleted-unresolved"));
    EXPECT_TRUE(has_code(w.r.diagnostics, "ubifs-history-scan"));
}

TEST(UbifsReader, OpenRejectsWhatIsNotAUbifsVolume) {
    std::shared_ptr<const Source> keep;
    auto reader = make_ubifs();

    const Bytes junk(kLebCnt * kLebSize, 0x5A);
    EXPECT_FALSE(reader->open(span_of(junk, keep)));

    // The magic with a broken superblock CRC.
    Image img = one_file();
    Bytes bad = img.bytes();
    bad[30] ^= 0xFF;
    EXPECT_FALSE(reader->open(span_of(bad, keep)));

    // Both master copies broken: nothing says where the index root is. This
    // is what a UBIFS superblock found at a raw offset inside a UBI image
    // looks like, where LEB 1 is not the master node.
    Image nomst = one_file();
    nomst.corrupt(1, 0);
    nomst.corrupt(2, 0);
    EXPECT_FALSE(reader->open(span_of(nomst.bytes(), keep)));

    // A volume shorter than the erase blocks the superblock claims: the LEBs
    // cannot be where lnum says they are.
    const Image full = one_file();
    Bytes cut(full.bytes().begin(),
              full.bytes().begin() + static_cast<std::ptrdiff_t>(4 * kLebSize));
    EXPECT_FALSE(reader->open(span_of(cut, keep)));
}

TEST(UbifsReader, AnIndexBranchPointingAtNothingIsReported) {
    Image img;
    img.superblock();
    img.log_start();
    const Image::Where root_ino = img.inode(kLeafLeb, kRootIno, 0040755, 0, 10);
    const Image::Where f_dent = img.dent(kLeafLeb, kRootIno, "ok", 20, kItReg, 11);
    const Image::Where f_ino = img.inode(kLeafLeb, 20, 0100644, 0, 12);
    // A fourth branch into an erase block that holds nothing.
    const Image::Where nowhere{5, 0, 160};
    const Image::Where idx = img.index(
        kIdxLeb, std::vector<Branch>{{root_ino, {kRootIno, kKIno, 0}},
                                     {f_ino, {20, kKIno, 0}},
                                     {f_dent, {kRootIno, kKDent, 1}},
                                     {nowhere, {30, kKIno, 0}}});
    img.master(idx.lnum, idx.offs, idx.len);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubifs();
    // The tree that did parse is still walked.
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_NE(entry_named(w.r, "ok"), nullptr);
    EXPECT_EQ(reader->info().attrs.at("bad_nodes"), "1");
}
