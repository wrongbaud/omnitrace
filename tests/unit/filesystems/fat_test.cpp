// fat_test.cpp — FAT12/16/32 reader.
//
// The `fat32` fixture covers the real thing end to end through the conformance
// harness (a whole tree, long names, the deleted file). What is here is what a
// fixture cannot give: FAT12 and FAT16, which `mkfs.vfat` can make but which
// the fixture set does not carry, and the hostile shapes a corrupt or crafted
// volume takes.
//
// Images are built by `Writer` below rather than by mkfs, so a test can put a
// chain into a loop or a cluster past the end of the volume and say exactly
// what should happen.
#include <gtest/gtest.h>

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

std::unique_ptr<FilesystemReader> make() {
    return FilesystemRegistry::instance().create("fat");
}

Span span_of(const Bytes& b, std::shared_ptr<const Source>& keep) {
    keep = std::make_shared<MemorySource>(b, "fat");
    return Span::whole(keep);
}

void put16(Bytes& b, std::size_t o, std::uint16_t v) {
    b[o] = static_cast<std::uint8_t>(v);
    b[o + 1] = static_cast<std::uint8_t>(v >> 8);
}
void put32(Bytes& b, std::size_t o, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i) b[o + i] = static_cast<std::uint8_t>(v >> (8U * i));
}

constexpr std::uint8_t kAttrDir = 0x10;
constexpr std::uint8_t kAttrArchive = 0x20;
constexpr std::uint8_t kAttrLfn = 0x0F;

// A directory entry to place, already resolved to a cluster.
struct Ent {
    std::string name83;  // exactly 11 bytes, space padded
    std::uint8_t attr = kAttrArchive;
    std::uint32_t cluster = 0;
    std::uint32_t size = 0;
    bool deleted = false;
    std::string lfn;                // optional long name (ASCII here; UTF-16 on disk)
    std::uint8_t lfn_checksum = 0;  // 0 = compute from name83
    bool lfn_bad_checksum = false;
};

// Builds a minimal but real FAT volume. `bits` picks the width by choosing a
// cluster count that lands in the right band, which is how the format itself
// defines the type.
class Writer {
   public:
    explicit Writer(int bits) : bits_(bits) {
        // Cluster counts either side of the two thresholds.
        data_clusters_ = bits == 12 ? 100u : (bits == 16 ? 5000u : 70000u);
        fat_sectors_ = bits == 12 ? 1u : (bits == 16 ? 20u : 550u);
        root_entries_ = bits == 32 ? 0u : 32u;
    }

    /// Lays the volume out and returns it. `root` is the root directory's
    /// entries; `dirs` maps a cluster to the entries of the directory that
    /// starts there, so a test can build a tree without a recursive builder.
    Bytes build(const std::vector<Ent>& root,
                const std::vector<std::pair<std::uint32_t, std::vector<Ent>>>& dirs = {}) {
        const std::uint64_t root_sectors =
            (static_cast<std::uint64_t>(root_entries_) * 32 + kSector - 1) / kSector;
        const std::uint64_t total = kReserved + 2ull * fat_sectors_ + root_sectors + data_clusters_;
        Bytes img(static_cast<std::size_t>(total * kSector), 0);

        img[0] = 0xEB;
        img[1] = 0x58;
        img[2] = 0x90;
        for (std::size_t i = 0; i < 8; ++i) img[3 + i] = static_cast<std::uint8_t>("omnitest"[i]);
        put16(img, 11, kSector);
        img[13] = 1;  // sectors per cluster
        put16(img, 14, kReserved);
        img[16] = 2;  // two FATs
        put16(img, 17, static_cast<std::uint16_t>(root_entries_));
        put16(img, 19, 0);  // total sectors live in the 32-bit field
        img[21] = 0xF8;
        put16(img, 22, bits_ == 32 ? 0 : static_cast<std::uint16_t>(fat_sectors_));
        put32(img, 32, static_cast<std::uint32_t>(total));
        if (bits_ == 32) {
            put32(img, 36, fat_sectors_);
            put32(img, 44, kRootCluster);
            img[66] = 0x29;
            put32(img, 67, 0x12345678);
            for (std::size_t i = 0; i < 11; ++i)
                img[71 + i] = static_cast<std::uint8_t>("OMNITEST   "[i]);
        } else {
            img[38] = 0x29;
            put32(img, 39, 0x12345678);
            for (std::size_t i = 0; i < 11; ++i)
                img[43 + i] = static_cast<std::uint8_t>("OMNITEST   "[i]);
        }
        put16(img, 510, 0xAA55);

        fat_off_ = static_cast<std::size_t>(kReserved) * kSector;
        root_off_ = fat_off_ + static_cast<std::size_t>(2 * fat_sectors_) * kSector;
        data_off_ = root_off_ + static_cast<std::size_t>(root_sectors) * kSector;

        // FAT[0] carries the media byte with the rest of the width set, and
        // FAT[1] the end-of-chain mark; both are what a reader cross-checks.
        set_fat(img, 0, bits_ == 12 ? 0x0FF8u : (bits_ == 16 ? 0xFFF8u : 0x0FFFFFF8u));
        set_fat(img, 1, eoc());
        img[fat_off_] = 0xF8;

        if (bits_ == 32)
            write_dir(img, kRootCluster, root);
        else
            write_fixed_root(img, root);
        for (const auto& [cluster, ents] : dirs) write_dir(img, cluster, ents);
        return img;
    }

    /// Marks `cluster` as the last of a chain, or points it at `next`.
    void link(Bytes& img, std::uint32_t cluster, std::uint32_t next) {
        set_fat(img, cluster, next);
    }
    std::uint32_t eoc() const {
        return bits_ == 12 ? 0x0FFFu : (bits_ == 16 ? 0xFFFFu : 0x0FFFFFFFu);
    }
    std::size_t cluster_off(std::uint32_t c) const {
        return data_off_ + static_cast<std::size_t>(c - 2) * kSector;
    }
    std::uint32_t clusters() const { return data_clusters_; }

    void set_fat(Bytes& img, std::uint32_t c, std::uint32_t v) const {
        if (bits_ == 32) {
            put32(img, fat_off_ + 4ull * c, v & 0x0FFFFFFFu);
        } else if (bits_ == 16) {
            put16(img, fat_off_ + 2ull * c, static_cast<std::uint16_t>(v));
        } else {
            const std::size_t o = fat_off_ + c + (c / 2);
            std::uint16_t cur = static_cast<std::uint16_t>(img[o] | (img[o + 1] << 8));
            cur = (c & 1u) != 0 ? static_cast<std::uint16_t>((cur & 0x000F) | (v << 4))
                                : static_cast<std::uint16_t>((cur & 0xF000) | (v & 0x0FFF));
            put16(img, o, cur);
        }
    }

   private:
    static constexpr std::uint16_t kSector = 512;
    static constexpr std::uint16_t kReserved = 4;
    static constexpr std::uint32_t kRootCluster = 2;

    static std::uint8_t checksum(const std::string& n83) {
        std::uint8_t sum = 0;
        for (std::size_t i = 0; i < 11; ++i)
            sum = static_cast<std::uint8_t>(((sum & 1) != 0 ? 0x80 : 0) + (sum >> 1) +
                                            static_cast<std::uint8_t>(n83[i]));
        return sum;
    }

    // One entry, plus the long-name entries that must precede it in reverse
    // order -- which is the part a reader gets wrong if it assembles them as
    // it meets them.
    static void emit(Bytes& out, const Ent& e) {
        if (!e.lfn.empty()) {
            const std::uint8_t sum = e.lfn_bad_checksum
                                         ? static_cast<std::uint8_t>(checksum(e.name83) ^ 0xFF)
                                         : checksum(e.name83);
            const std::size_t frags = (e.lfn.size() + 12) / 13;
            for (std::size_t f = frags; f-- > 0;) {
                Bytes le(32, 0);
                le[0] = static_cast<std::uint8_t>(f + 1);
                if (f + 1 == frags) le[0] |= 0x40;  // last fragment, met first
                if (e.deleted) le[0] = 0xE5;
                le[11] = kAttrLfn;
                le[13] = sum;
                static constexpr int kSlots[] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
                for (int i = 0; i < 13; ++i) {
                    const std::size_t idx = f * 13 + static_cast<std::size_t>(i);
                    const std::uint16_t ch = idx < e.lfn.size()
                                                 ? static_cast<std::uint8_t>(e.lfn[idx])
                                                 : (idx == e.lfn.size() ? 0x0000 : 0xFFFF);
                    put16(le, static_cast<std::size_t>(kSlots[i]), ch);
                }
                out.insert(out.end(), le.begin(), le.end());
            }
        }
        Bytes d(32, 0);
        for (std::size_t i = 0; i < 11; ++i) d[i] = static_cast<std::uint8_t>(e.name83[i]);
        if (e.deleted) d[0] = 0xE5;
        d[11] = e.attr;
        put16(d, 20, static_cast<std::uint16_t>(e.cluster >> 16));
        put16(d, 26, static_cast<std::uint16_t>(e.cluster));
        put32(d, 28, e.size);
        put16(d, 22, 0x6000);  // 12:00:00
        put16(d, 24, 0x5621);  // 2023-01-01
        out.insert(out.end(), d.begin(), d.end());
    }

    static Bytes pack(const std::vector<Ent>& ents) {
        Bytes out;
        for (const Ent& e : ents) emit(out, e);
        return out;
    }

    void write_fixed_root(Bytes& img, const std::vector<Ent>& ents) const {
        const Bytes d = pack(ents);
        std::copy(d.begin(), d.end(), img.begin() + static_cast<std::ptrdiff_t>(root_off_));
    }
    // A directory occupies one cluster here, so its chain is one entry long:
    // the end-of-chain mark. Leaving it at zero makes every directory look
    // like a chain into the reserved cluster 0, which is what it means.
    void write_dir(Bytes& img, std::uint32_t cluster, const std::vector<Ent>& ents) const {
        const Bytes d = pack(ents);
        std::copy(d.begin(), d.end(),
                  img.begin() + static_cast<std::ptrdiff_t>(cluster_off(cluster)));
        set_fat(img, cluster, eoc());
    }

    int bits_;
    std::uint32_t data_clusters_ = 0, fat_sectors_ = 0, root_entries_ = 0;
    std::size_t fat_off_ = 0, root_off_ = 0, data_off_ = 0;
};

struct Walked {
    Status open_status;
    WalkResult result;
    std::map<std::string, EntryResult> by_path;
};

Walked walk(const Bytes& img, bool history = false) {
    Walked w;
    auto reader = make();
    std::shared_ptr<const Source> keep;
    w.open_status = reader->open(span_of(img, keep));
    if (!w.open_status) return w;
    ListingSink sink(true, Limits{});
    WalkOptions opts;
    opts.history = history;
    reader->walk(sink, opts, w.result);
    for (const EntryResult& e : w.result.entries_out) w.by_path[e.meta.path] = e;
    return w;
}

bool has_code(const WalkResult& r, const std::string& code) {
    for (const Diagnostic& d : r.diagnostics)
        if (d.code == code) return true;
    return false;
}

}  // namespace

// The width is decided by the cluster count, not by the type string -- which
// is the field the specification says is not required to be correct. All three
// widths read the same tree, and the FAT12 case additionally exercises the
// packed one-and-a-half-byte entry.
TEST(Fat, AllThreeWidthsReadTheSameTree) {
    // An 8.3 entry with no NT lowercase flags is an uppercase name, which is
    // what this builder writes; the fixture covers the lowercase flags.
    for (const int bits : {12, 16, 32}) {
        Writer wr(bits);
        const std::uint32_t file_cluster = bits == 32 ? 3 : 2;
        Bytes img = wr.build({{"HELLO   TXT", kAttrArchive, file_cluster, 5, false, ""}});
        wr.link(img, file_cluster, wr.eoc());
        const std::string data = "hello";
        std::copy(data.begin(), data.end(),
                  img.begin() + static_cast<std::ptrdiff_t>(wr.cluster_off(file_cluster)));

        const Walked w = walk(img);
        ASSERT_TRUE(w.open_status) << "fat" << bits << ": " << w.open_status.error;
        ASSERT_EQ(w.by_path.count("HELLO.TXT"), 1u) << "fat" << bits;
        const EntryResult& e = w.by_path.at("HELLO.TXT");
        EXPECT_EQ(e.meta.size, 5u) << "fat" << bits;
        EXPECT_EQ(e.digests.bytes, 5u) << "fat" << bits;
        EXPECT_EQ(w.result.files, 1u) << "fat" << bits;
    }
}

// Long-name entries precede the entry they name and count *down*, so they are
// met last-fragment-first. Assembling them in the order they arrive spells the
// name backwards -- in 13-character chunks, which is why the name here is
// longer than one fragment.
TEST(Fat, LongNamesAreAssembledInReverse) {
    Writer wr(32);
    const std::string lfn = "a-long-name-that-needs-three-fragments.txt";
    Bytes img = wr.build({{"ALONGN~1TXT", kAttrArchive, 3, 0, false, lfn}});
    wr.link(img, 3, wr.eoc());
    const Walked w = walk(img);
    ASSERT_TRUE(w.open_status) << w.open_status.error;
    EXPECT_EQ(w.by_path.count(lfn), 1u)
        << "the long name was not reassembled; entries seen: "
        << (w.result.entries_out.empty() ? std::string("none")
                                         : w.result.entries_out.front().meta.path);
}

// A long name whose checksum does not match the 8.3 entry behind it is stale --
// left by a rename that reused the slot -- and naming the file after it would
// be wrong.
TEST(Fat, StaleLongNameIsIgnoredInFavourOfTheShortName) {
    Writer wr(32);
    Ent e{"REAL    TXT", kAttrArchive, 3, 0, false, "not-this-name.txt"};
    e.lfn_bad_checksum = true;
    Bytes img = wr.build({e});
    wr.link(img, 3, wr.eoc());
    const Walked w = walk(img);
    ASSERT_TRUE(w.open_status) << w.open_status.error;
    EXPECT_EQ(w.by_path.count("REAL.TXT"), 1u);
    EXPECT_EQ(w.by_path.count("not-this-name.txt"), 0u);
}

// Deleting a file stamps 0xE5 over the first byte of its name and frees the
// chain. Without --history it is not emitted at all; with it, the bytes come
// back and the report says what is uncertain about them.
TEST(Fat, DeletedFileIsRecoveredOnlyWithHistoryAndSaysWhatIsUncertain) {
    Writer wr(32);
    Bytes img = wr.build({{"GONE    TXT", kAttrArchive, 3, 4, /*deleted=*/true, ""}});
    const std::string data = "byes";
    std::copy(data.begin(), data.end(),
              img.begin() + static_cast<std::ptrdiff_t>(wr.cluster_off(3)));

    const Walked plain = walk(img, /*history=*/false);
    ASSERT_TRUE(plain.open_status) << plain.open_status.error;
    EXPECT_EQ(plain.result.entries, 0u) << "a deleted entry is history, not a live file";

    const Walked hist = walk(img, /*history=*/true);
    ASSERT_TRUE(hist.open_status) << hist.open_status.error;
    ASSERT_EQ(hist.result.deleted, 1u);
    const EntryResult& e = hist.result.entries_out.front();
    EXPECT_TRUE(e.meta.deleted);
    EXPECT_EQ(e.meta.size, 4u);
    EXPECT_EQ(e.digests.bytes, 4u) << "the bytes are read contiguously from the first cluster";
    // The first character is gone and nothing in the format keeps a copy.
    EXPECT_EQ(e.meta.path, "_ONE.TXT");
    EXPECT_NE(e.meta.extra.count("name_first_char"), 0u)
        << "a name with an invented first character must say so";
    EXPECT_NE(e.meta.extra.count("recovery"), 0u)
        << "a file read without its chain must say how it was read";
    // Counts are by kind and include historical entries.
    EXPECT_EQ(hist.result.files, 1u);
}

// A deleted long name keeps its fragments but loses the ordinal byte to the
// same 0xE5 stamp, so the fragment count cannot be trusted -- and the whole
// name is recoverable only if they are accumulated positionally instead.
TEST(Fat, DeletedFileWithALongNameKeepsIt) {
    Writer wr(32);
    Bytes img = wr.build({{"GONE    TXT", kAttrArchive, 3, 4, true, "deleted-but-named.txt"}});
    const Walked w = walk(img, /*history=*/true);
    ASSERT_TRUE(w.open_status) << w.open_status.error;
    ASSERT_EQ(w.result.deleted, 1u);
    const EntryResult& e = w.result.entries_out.front();
    EXPECT_EQ(e.meta.path, "deleted-but-named.txt")
        << "the long name survives deletion intact and is the only complete one";
    EXPECT_EQ(e.meta.extra.count("name_first_char"), 0u)
        << "nothing was lost, so nothing should be claimed lost";
}

// A file larger than one cluster cannot be recovered reliably once its chain
// is freed: contiguous is a guess, and one that has to be labelled.
TEST(Fat, MultiClusterDeletedFileWarnsThatContiguousIsAGuess) {
    Writer wr(32);
    Bytes img = wr.build({{"BIG     BIN", kAttrArchive, 3, 600, /*deleted=*/true, ""}});
    const Walked w = walk(img, /*history=*/true);
    ASSERT_TRUE(w.open_status) << w.open_status.error;
    EXPECT_TRUE(has_code(w.result, "fat-deleted-unchained"))
        << "recovering more than one cluster without a chain must be flagged";
}

// Every one of these is a shape a corrupt or crafted volume takes, and none of
// them may hang, read out of bounds or produce a tree.
TEST(Fat, HostileChainsAreRefusedNotFollowed) {
    {  // a chain that points back at itself
        Writer wr(32);
        Bytes img = wr.build({{"LOOP    TXT", kAttrArchive, 3, 2000, false, ""}});
        wr.link(img, 3, 4);
        wr.link(img, 4, 3);
        const Walked w = walk(img);
        ASSERT_TRUE(w.open_status) << w.open_status.error;
        EXPECT_TRUE(has_code(w.result, "fat-bad-chain"));
        EXPECT_EQ(w.result.files, 0u);
    }
    {  // a chain that leaves the data area
        Writer wr(32);
        Bytes img = wr.build({{"OOB     TXT", kAttrArchive, 3, 2000, false, ""}});
        wr.link(img, 3, wr.clusters() + 100);
        const Walked w = walk(img);
        ASSERT_TRUE(w.open_status) << w.open_status.error;
        EXPECT_TRUE(has_code(w.result, "fat-bad-chain"));
    }
    {  // a directory whose first cluster is the reserved 0
        Writer wr(32);
        const Bytes img = wr.build({{"BADDIR     ", kAttrDir, 0, 0, false, ""}});
        const Walked w = walk(img);
        ASSERT_TRUE(w.open_status) << w.open_status.error;
        EXPECT_TRUE(has_code(w.result, "fat-bad-entry"));
        EXPECT_EQ(w.result.dirs, 0u);
    }
    {  // two directories pointing at the same cluster: a loop by another route
        Writer wr(32);
        Bytes img = wr.build({{"SUB        ", kAttrDir, 3, 0, false, ""}},
                             {{3, {{"SUB2       ", kAttrDir, 3, 0, false, ""}}}});
        wr.link(img, 3, wr.eoc());
        const Walked w = walk(img);
        ASSERT_TRUE(w.open_status) << w.open_status.error;
        EXPECT_TRUE(has_code(w.result, "fat-dir-loop"));
    }
}

// "." and ".." are ordinary entries on disk and are how a naive walk loops.
TEST(Fat, DotEntriesAreNotEmitted) {
    Writer wr(32);
    Bytes img = wr.build({{"SUB        ", kAttrDir, 3, 0, false, ""}},
                         {{3,
                           {{".          ", kAttrDir, 3, 0, false, ""},
                            {"..         ", kAttrDir, 0, 0, false, ""},
                            {"CHILD   TXT", kAttrArchive, 4, 0, false, ""}}}});
    wr.link(img, 3, wr.eoc());
    wr.link(img, 4, wr.eoc());
    const Walked w = walk(img);
    ASSERT_TRUE(w.open_status) << w.open_status.error;
    EXPECT_EQ(w.by_path.count("SUB/CHILD.TXT"), 1u);
    EXPECT_EQ(w.by_path.count("SUB/."), 0u);
    EXPECT_EQ(w.by_path.count("SUB/.."), 0u);
    EXPECT_EQ(w.result.dirs, 1u);
}

// The volume label is a directory entry with the volume-id attribute, and it
// is not a file.
TEST(Fat, VolumeLabelIsNotAFile) {
    Writer wr(32);
    Bytes img = wr.build(
        {{"OMNITEST   ", 0x08, 0, 0, false, ""}, {"REAL    TXT", kAttrArchive, 3, 0, false, ""}});
    wr.link(img, 3, wr.eoc());
    const Walked w = walk(img);
    ASSERT_TRUE(w.open_status) << w.open_status.error;
    EXPECT_EQ(w.result.files, 1u);
    EXPECT_EQ(w.by_path.count("REAL.TXT"), 1u);
}

// A file whose recorded size outruns its chain is truncated evidence, not a
// reason to emit nothing.
TEST(Fat, ShortChainEmitsWhatIsThereAndSaysSo) {
    Writer wr(32);
    Bytes img = wr.build({{"SHORT   BIN", kAttrArchive, 3, 4096, false, ""}});
    wr.link(img, 3, wr.eoc());  // one cluster of 512 for a 4096-byte file
    const Walked w = walk(img);
    ASSERT_TRUE(w.open_status) << w.open_status.error;
    ASSERT_EQ(w.by_path.count("SHORT.BIN"), 1u);
    EXPECT_EQ(w.by_path.at("SHORT.BIN").digests.bytes, 512u);
    EXPECT_TRUE(has_code(w.result, "fat-short-read"));
}

TEST(Fat, RefusesWhatIsNotAFatVolume) {
    auto reader = make();
    std::shared_ptr<const Source> keep;
    const Bytes junk(4096, 0x41);
    EXPECT_FALSE(reader->open(span_of(junk, keep)));

    // A BPB that is right except for a cluster size that is not a power of two.
    Writer wr(32);
    Bytes img = wr.build({});
    img[13] = 3;
    auto r2 = make();
    const Status st = r2->open(span_of(img, keep));
    EXPECT_FALSE(st);
    EXPECT_NE(st.error.find("fat-bad-superblock"), std::string::npos) << st.error;
}

TEST(Fat, WalkBeforeOpenFails) {
    auto reader = make();
    ListingSink sink(false, Limits{});
    WalkResult r;
    const Status st = reader->walk(sink, WalkOptions{}, r);
    EXPECT_FALSE(st);
    EXPECT_NE(st.error.find("fat-not-open"), std::string::npos) << st.error;
}

// Truncating a volume at every sector boundary must never crash or hang: the
// scanner hands readers spans that run off the end of a carved partition all
// the time.
TEST(Fat, TruncatedAtEverySectorIsSafe) {
    // FAT12, which is 100 clusters rather than 70,000: the point is to cut in
    // every structure of the volume, not to cut a large one.
    Writer wr(12);
    Bytes img = wr.build({{"SUB        ", kAttrDir, 2, 0, false, ""}},
                         {{2, {{"CHILD   TXT", kAttrArchive, 3, 600, false, ""}}}});
    wr.link(img, 2, wr.eoc());
    wr.link(img, 3, 4);
    wr.link(img, 4, wr.eoc());
    for (std::size_t cut = 1; cut < img.size(); cut += 509) {  // a prime stride: no alignment
        const Bytes small(img.begin(), img.begin() + static_cast<std::ptrdiff_t>(cut));
        const Walked w = walk(small);  // must simply not crash
        if (w.open_status) {
            EXPECT_LE(w.result.entries, 8u);
        }
    }
}
