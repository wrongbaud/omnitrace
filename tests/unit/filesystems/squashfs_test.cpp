// squashfs_test.cpp — SquashfsReader.
//
// Four kinds of coverage:
//   1. A synthetic image assembled byte by byte in the test (both byte orders,
//      vendor magic, every inode class, fragments, sparse blocks) so the
//      reader's parsing is pinned independently of any tool.
//   2. Real images built with mksquashfs at test time for every compressor the
//      installed tool supports, compared entry by entry (metadata + sha256)
//      against the source tree and `diff -r` after extraction through DiskSink.
//   3. Hostile images: truncation at every offset, corrupted superblock
//      pointers, absurd block sizes, seeded random byte flips. Nothing may
//      crash; run this binary under ASan+UBSan.
//   4. Fixtures under tests/fixtures/out and the router.bin corpus (skipped
//      when absent), the latter diffed against unsquashfs.
#include "../../../src/filesystems/squashfs/SquashfsReader.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "omnitrace/core/Hash.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/filesystems/Filesystem.h"

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace omnitrace::fs {
namespace {

namespace stdfs = std::filesystem;

// ------------------------------------------------------------------ helpers

bool has_code(const std::vector<Diagnostic>& d, const std::string& code) {
    for (const Diagnostic& x : d)
        if (x.code == code) return true;
    return false;
}

std::string join_diags(const std::vector<Diagnostic>& d) {
    std::string s;
    for (const Diagnostic& x : d) s += x.code + ": " + x.message + "\n";
    return s;
}

class TempDir {
   public:
    TempDir() {
        stdfs::path base;
        if (const char* env = std::getenv("OMNITRACE_TEST_TMPDIR"))
            base = env;
        else
            base = stdfs::temp_directory_path();
        static int counter = 0;
#ifdef _WIN32
        const long pid = 0;
#else
        const long pid = static_cast<long>(::getpid());
#endif
        path_ =
            base / ("omnitrace-squashfs-" + std::to_string(pid) + "-" + std::to_string(counter++));
        stdfs::remove_all(path_);
        stdfs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        stdfs::remove_all(path_, ec);
    }
    const stdfs::path& path() const { return path_; }

   private:
    stdfs::path path_;
};

std::vector<std::uint8_t> slurp(const stdfs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(in),
                                     std::istreambuf_iterator<char>());
}

void spit(const stdfs::path& p, const std::vector<std::uint8_t>& data) {
    std::ofstream out(p, std::ios::binary);
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
}

void spit(const stdfs::path& p, const std::string& s) {
    std::ofstream out(p, std::ios::binary);
    out.write(s.data(), static_cast<std::streamsize>(s.size()));
}

// Deterministic pseudo-random bytes (xorshift64*), so no two runs differ.
std::vector<std::uint8_t> pseudo_random(std::size_t n, std::uint64_t seed) {
    std::vector<std::uint8_t> v(n);
    std::uint64_t x = seed | 1;
    for (std::size_t i = 0; i < n; ++i) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        v[i] = static_cast<std::uint8_t>((x * 0x2545F4914F6CDD1Dull) >> 56);
    }
    return v;
}

Span span_of(std::vector<std::uint8_t> bytes, const std::string& label = "img") {
    return Span::whole(std::make_shared<MemorySource>(std::move(bytes), label));
}

int run(const std::string& cmd) {
    const int rc = std::system(cmd.c_str());
#ifdef _WIN32
    return rc;
#else
    if (rc == -1) return -1;
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return 128;
#endif
}

bool tool_exists(const char* path) {
#ifdef _WIN32
    (void)path;
    return false;
#else
    return ::access(path, X_OK) == 0;
#endif
}

struct Walked {
    Status status;
    WalkResult result;
    std::map<std::string, EntryResult> by_path;
};

Walked walk_listing(const Span& span, bool hash, WalkOptions opts = {},
                    Status* open_status = nullptr) {
    Walked w;
    SquashfsReader r;
    const Status s = r.open(span);
    if (open_status) *open_status = s;
    if (!s) {
        w.status = s;
        return w;
    }
    ListingSink sink(hash, opts.limits);
    w.status = r.walk(sink, opts, w.result);
    for (const EntryResult& e : w.result.entries_out) w.by_path[e.meta.path] = e;
    return w;
}

// ------------------------------------------------------------------ synthetic image builder
//
// Assembles a minimal but complete v4 image: superblock, one uncompressed data
// block, a fragment block, inode/directory/fragment/id tables each in one
// uncompressed metadata block. Byte order is a parameter so the big-endian
// path is exercised without a big-endian mksquashfs.

struct SynthOptions {
    Endian endian = Endian::Little;
    std::string magic;      // default: the canonical magic for `endian`
    bool loop = false;      // sub/ contains "back" pointing at the root inode
    bool bad_type = false;  // root contains "weird" whose inode type is 99
    std::uint16_t compression = 1;
    bool compressed_meta = false;  // inode table header claims compression (payload is not)
    std::uint32_t block_size = 4096;
    std::uint16_t block_log = 12;
    bool with_xattr_table = false;          // extended file references xattr id 0 with 2 xattrs
    std::uint32_t symlink_target_size = 0;  // 0: the real size; otherwise a hostile claim
};

class Synth {
   public:
    explicit Synth(SynthOptions o) : o_(std::move(o)) {}

    std::vector<std::uint8_t> build() {
        std::vector<std::uint8_t> img(96, 0);  // superblock filled last

        // ---- data: hello.txt (one uncompressed block) and the sparse file's second block
        const std::string hello = "hello world\n";
        const std::uint64_t hello_off = img.size();
        append(img, hello);
        const std::uint64_t sparse_blk_off = img.size();
        std::vector<std::uint8_t> blk(o_.block_size, 0x41);
        img.insert(img.end(), blk.begin(), blk.end());
        // ---- fragment block: "TAIL!" at offset 3
        const std::uint64_t frag_off = img.size();
        append(img, std::string("xyzTAIL!pad"));

        // ---- inode table (one uncompressed metadata block)
        std::vector<std::uint8_t> inodes;
        std::map<std::string, std::uint16_t> at;  // name -> offset in block
        // 1: root dir (listing filled in after the directory table is laid out)
        at["root"] = static_cast<std::uint16_t>(inodes.size());
        const std::size_t root_pos = inodes.size();
        inode_header(inodes, 1, 0755, 0, 1, 1700000000u, 1);
        u32(inodes, 0);  // start_block (patched)
        u32(inodes, 3);  // nlink
        u16(inodes, 0);  // file_size (patched)
        u16(inodes, 0);  // block_offset
        u32(inodes, 8);  // parent = inodes + 1
        // 2: hello.txt (basic file)
        at["hello"] = static_cast<std::uint16_t>(inodes.size());
        inode_header(inodes, 2, 0644, 0, 1, 1700000002u, 2);
        u32(inodes, static_cast<std::uint32_t>(hello_off));
        u32(inodes, 0xFFFFFFFFu);  // no fragment
        u32(inodes, 0);
        u32(inodes, static_cast<std::uint32_t>(hello.size()));
        u32(inodes, static_cast<std::uint32_t>(hello.size()) | (1u << 24));
        // 3: sub (basic dir, patched)
        at["sub"] = static_cast<std::uint16_t>(inodes.size());
        const std::size_t sub_pos = inodes.size();
        inode_header(inodes, 1, 0700, 1, 0, 1700000004u, 3);
        u32(inodes, 0);
        u32(inodes, 2);
        u16(inodes, 0);
        u16(inodes, 0);
        u32(inodes, 1);
        // 4: sub/link (basic symlink)
        at["link"] = static_cast<std::uint16_t>(inodes.size());
        inode_header(inodes, 3, 0777, 0, 1, 1700000006u, 4);
        u32(inodes, 1);
        const std::string target = "../hello.txt";
        u32(inodes, o_.symlink_target_size != 0 ? o_.symlink_target_size
                                                : static_cast<std::uint32_t>(target.size()));
        append(inodes, target);
        // 5: dev (basic char device 5:1)
        at["dev"] = static_cast<std::uint16_t>(inodes.size());
        inode_header(inodes, 5, 0600, 0, 0, 1700000008u, 5);
        u32(inodes, 1);
        u32(inodes, (5u << 8) | 1u);
        // 6: fifo (basic fifo)
        at["fifo"] = static_cast<std::uint16_t>(inodes.size());
        inode_header(inodes, 6, 0644, 1, 1, 1700000010u, 6);
        u32(inodes, 1);
        // 7: sub/big (extended file: sparse block, data block, fragment tail, nlink 2)
        at["big"] = static_cast<std::uint16_t>(inodes.size());
        inode_header(inodes, 9, 0640, 1, 1, 1700000012u, 7);
        u64(inodes, sparse_blk_off);
        u64(inodes, 2ull * o_.block_size + 5);  // file_size
        u64(inodes, o_.block_size);             // sparse bytes
        u32(inodes, 2);                         // nlink
        u32(inodes, 0);                         // fragment index 0
        u32(inodes, 3);                         // offset in fragment
        u32(inodes, o_.with_xattr_table ? 0u : 0xFFFFFFFFu);
        u32(inodes, 0);                           // block 0: sparse
        u32(inodes, o_.block_size | (1u << 24));  // block 1: stored raw
        // 8: extended block device 8:17 with nlink 1 (lblkdev)
        at["blk"] = static_cast<std::uint16_t>(inodes.size());
        inode_header(inodes, 11, 0660, 0, 0, 1700000014u, 8);
        u32(inodes, 1);
        u32(inodes, (8u << 8) | 17u);
        u32(inodes, 0xFFFFFFFFu);
        // 9: weird (type 99) for the bad-type variant
        at["weird"] = static_cast<std::uint16_t>(inodes.size());
        inode_header(inodes, 99, 0644, 0, 0, 1700000016u, 9);
        u32(inodes, 1);
        // 10: empty extended dir for "empty" (ldir, index_count 0)
        at["empty"] = static_cast<std::uint16_t>(inodes.size());
        inode_header(inodes, 8, 0755, 0, 1, 1700000018u, 10);
        u32(inodes, 2);  // nlink
        u32(inodes, 3);  // file_size: empty listing
        u32(inodes, 0);  // start_block
        u32(inodes, 1);  // parent
        u16(inodes, 0);  // index count
        u16(inodes, 0);  // offset
        u32(inodes, 0xFFFFFFFFu);

        // ---- directory table (one uncompressed metadata block)
        std::vector<std::uint8_t> dirs;
        // root listing: sorted names
        const std::size_t root_list_off = dirs.size();
        {
            std::vector<std::pair<std::string, std::string>> ents = {
                {"blk", "blk"},   {"dev", "dev"},         {"empty", "empty"},
                {"fifo", "fifo"}, {"hello.txt", "hello"}, {"sub", "sub"}};
            if (o_.bad_type) ents.push_back({"weird", "weird"});
            listing(dirs, ents, at);
        }
        const std::size_t root_list_len = dirs.size() - root_list_off;
        const std::size_t sub_list_off = dirs.size();
        {
            std::vector<std::pair<std::string, std::string>> ents = {{"big", "big"},
                                                                     {"link", "link"}};
            if (o_.loop) ents.insert(ents.begin(), {"back", "root"});
            listing(dirs, ents, at);
        }
        const std::size_t sub_list_len = dirs.size() - sub_list_off;

        // patch the two directory inodes: start_block 0, file_size = len + 3, offset
        patch32(inodes, root_pos + 16, 0);
        patch16(inodes, root_pos + 24, static_cast<std::uint16_t>(root_list_len + 3));
        patch16(inodes, root_pos + 26, static_cast<std::uint16_t>(root_list_off));
        patch32(inodes, sub_pos + 16, 0);
        patch16(inodes, sub_pos + 24, static_cast<std::uint16_t>(sub_list_len + 3));
        patch16(inodes, sub_pos + 26, static_cast<std::uint16_t>(sub_list_off));

        // ---- lay the tables out
        const std::uint64_t inode_table = img.size();
        meta_block(img, inodes, o_.compressed_meta);
        const std::uint64_t dir_table = img.size();
        meta_block(img, dirs, false);

        // fragment table: entry block then index
        std::vector<std::uint8_t> frag;
        u64(frag, frag_off);
        u32(frag, 11u | (1u << 24));
        u32(frag, 0);
        const std::uint64_t frag_block = img.size();
        meta_block(img, frag, false);
        const std::uint64_t frag_table = img.size();
        u64(img, frag_block);

        // id table: [1000, 100]
        std::vector<std::uint8_t> ids;
        u32(ids, 1000);
        u32(ids, 100);
        const std::uint64_t id_block = img.size();
        meta_block(img, ids, false);
        const std::uint64_t id_table = img.size();
        u64(img, id_block);

        // xattr id table (optional): header, then index -> one id entry with count 2
        std::uint64_t xattr_table = 0xFFFFFFFFFFFFFFFFull;
        if (o_.with_xattr_table) {
            std::vector<std::uint8_t> xid;
            u64(xid, 0);   // xattr ref (not decoded)
            u32(xid, 2);   // count
            u32(xid, 40);  // size
            const std::uint64_t xid_block = img.size();
            meta_block(img, xid, false);
            xattr_table = img.size();
            u64(img, 0);  // xattr_table_start (unused by the reader)
            u32(img, 1);  // xattr_ids
            u32(img, 0);
            u64(img, xid_block);
        }

        // ---- superblock
        std::vector<std::uint8_t> sb;
        std::string magic =
            o_.magic.empty() ? (o_.endian == Endian::Little ? "hsqs" : "sqsh") : o_.magic;
        append(sb, magic);
        u32(sb, 10);           // inodes
        u32(sb, 1700000000u);  // mkfs_time
        u32(sb, o_.block_size);
        u32(sb, 1);  // fragments
        u16(sb, o_.compression);
        u16(sb, o_.block_log);
        u16(sb, 0x00C0);  // flags: duplicates, exportable-less
        u16(sb, 2);       // no_ids
        u16(sb, 4);
        u16(sb, 0);
        u64(sb, static_cast<std::uint64_t>(at["root"]));  // root inode ref: block 0, offset
        u64(sb, img.size());                              // bytes_used
        u64(sb, id_table);
        u64(sb, xattr_table);
        u64(sb, inode_table);
        u64(sb, dir_table);
        u64(sb, frag_table);
        u64(sb, 0xFFFFFFFFFFFFFFFFull);  // export table
        EXPECT_EQ(sb.size(), 96u);
        std::copy(sb.begin(), sb.end(), img.begin());
        return img;
    }

   private:
    SynthOptions o_;

    void u16(std::vector<std::uint8_t>& v, std::uint16_t x) { put<std::uint16_t>(v, x); }
    void u32(std::vector<std::uint8_t>& v, std::uint32_t x) { put<std::uint32_t>(v, x); }
    void u64(std::vector<std::uint8_t>& v, std::uint64_t x) { put<std::uint64_t>(v, x); }
    template <class T>
    void put(std::vector<std::uint8_t>& v, T x) {
        for (std::size_t i = 0; i < sizeof(T); ++i) {
            const std::size_t shift = o_.endian == Endian::Little ? i : sizeof(T) - 1 - i;
            v.push_back(static_cast<std::uint8_t>(x >> (8 * shift)));
        }
    }
    void patch16(std::vector<std::uint8_t>& v, std::size_t off, std::uint16_t x) {
        std::vector<std::uint8_t> tmp;
        u16(tmp, x);
        std::copy(tmp.begin(), tmp.end(), v.begin() + static_cast<std::ptrdiff_t>(off));
    }
    void patch32(std::vector<std::uint8_t>& v, std::size_t off, std::uint32_t x) {
        std::vector<std::uint8_t> tmp;
        u32(tmp, x);
        std::copy(tmp.begin(), tmp.end(), v.begin() + static_cast<std::ptrdiff_t>(off));
    }
    static void append(std::vector<std::uint8_t>& v, const std::string& s) {
        v.insert(v.end(), s.begin(), s.end());
    }

    void inode_header(std::vector<std::uint8_t>& v, std::uint16_t type, std::uint16_t mode,
                      std::uint16_t uid, std::uint16_t gid, std::uint32_t mtime,
                      std::uint32_t number) {
        u16(v, type);
        u16(v, mode);
        u16(v, uid);
        u16(v, gid);
        u32(v, mtime);
        u32(v, number);
    }

    // One directory header covering all entries (all inodes live in block 0).
    void listing(std::vector<std::uint8_t>& v,
                 const std::vector<std::pair<std::string, std::string>>& ents,
                 const std::map<std::string, std::uint16_t>& at) {
        u32(v, static_cast<std::uint32_t>(ents.size() - 1));
        u32(v, 0);  // start block of the inode table block
        u32(v, 1);  // base inode number
        for (const auto& [name, key] : ents) {
            const std::uint16_t off = at.at(key);
            u16(v, off);
            u16(v, 0);  // inode number delta (not used by the reader)
            u16(v, static_cast<std::uint16_t>(key == "root" || key == "sub" || key == "empty" ? 1
                                                                                              : 2));
            u16(v, static_cast<std::uint16_t>(name.size() - 1));
            append(v, name);
        }
    }

    void meta_block(std::vector<std::uint8_t>& img, const std::vector<std::uint8_t>& data,
                    bool claim_compressed) {
        u16(img, static_cast<std::uint16_t>(data.size() | (claim_compressed ? 0 : 0x8000)));
        img.insert(img.end(), data.begin(), data.end());
    }
};

void check_synth(const Walked& w, const std::string& label) {
    ASSERT_TRUE(w.status.ok) << label << ": " << w.status.error << "\n"
                             << join_diags(w.result.diagnostics);
    // Emission order: as stored (sorted) and pre-order.
    std::vector<std::string> order;
    for (const EntryResult& e : w.result.entries_out) order.push_back(e.meta.path);
    const std::vector<std::string> want = {"blk",       "dev", "empty",   "fifo",
                                           "hello.txt", "sub", "sub/big", "sub/link"};
    EXPECT_EQ(order, want) << label;
    EXPECT_EQ(w.result.files, 2u) << label;
    EXPECT_EQ(w.result.dirs, 2u) << label;
    EXPECT_EQ(w.result.symlinks, 1u) << label;
    EXPECT_EQ(w.result.others, 3u) << label;

    const EntryResult& hello = w.by_path.at("hello.txt");
    EXPECT_EQ(hello.meta.kind, EntryKind::Regular);
    EXPECT_EQ(hello.meta.mode, 0644u);
    EXPECT_EQ(hello.meta.uid, 1000u);
    EXPECT_EQ(hello.meta.gid, 100u);
    EXPECT_EQ(hello.meta.size, 12u);
    EXPECT_EQ(hello.meta.mtime.value_or(0), 1700000002);
    EXPECT_EQ(hello.meta.inode, 2u);
    EXPECT_EQ(hello.meta.nlink, 1u);
    EXPECT_EQ(hello.digests.sha256,
              "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447");
    EXPECT_EQ(hello.digests.bytes, 12u);

    const EntryResult& sub = w.by_path.at("sub");
    EXPECT_EQ(sub.meta.kind, EntryKind::Directory);
    EXPECT_EQ(sub.meta.mode, 0700u);
    EXPECT_EQ(sub.meta.uid, 100u);
    EXPECT_EQ(sub.meta.gid, 1000u);
    EXPECT_EQ(sub.meta.nlink, 2u);
    EXPECT_EQ(sub.meta.inode, 3u);

    const EntryResult& link = w.by_path.at("sub/link");
    EXPECT_EQ(link.meta.kind, EntryKind::Symlink);
    EXPECT_EQ(link.meta.link_target, "../hello.txt");
    EXPECT_EQ(link.meta.size, 12u);
    EXPECT_EQ(link.meta.mode, 0777u);

    const EntryResult& dev = w.by_path.at("dev");
    EXPECT_EQ(dev.meta.kind, EntryKind::CharDevice);
    EXPECT_EQ(dev.meta.rdev_major, 5u);
    EXPECT_EQ(dev.meta.rdev_minor, 1u);
    EXPECT_EQ(dev.meta.mode, 0600u);

    const EntryResult& blk = w.by_path.at("blk");
    EXPECT_EQ(blk.meta.kind, EntryKind::BlockDevice);
    EXPECT_EQ(blk.meta.rdev_major, 8u);
    EXPECT_EQ(blk.meta.rdev_minor, 17u);

    EXPECT_EQ(w.by_path.at("fifo").meta.kind, EntryKind::Fifo);
    EXPECT_EQ(w.by_path.at("empty").meta.kind, EntryKind::Directory);
    EXPECT_EQ(w.by_path.at("empty").meta.inode, 10u);

    // sub/big: 4096 zeros (sparse), 4096 x 'A' (raw block), "TAIL!" from the fragment.
    const EntryResult& big = w.by_path.at("sub/big");
    EXPECT_EQ(big.meta.kind, EntryKind::Regular);
    EXPECT_EQ(big.meta.size, 2u * 4096 + 5);
    EXPECT_EQ(big.meta.nlink, 2u);
    EXPECT_EQ(big.meta.mode, 0640u);
    EXPECT_EQ(big.meta.extra.at("sparse"), "4096");
    std::vector<std::uint8_t> expect(4096, 0);
    expect.insert(expect.end(), 4096, 0x41);
    const std::string tail = "TAIL!";
    expect.insert(expect.end(), tail.begin(), tail.end());
    EXPECT_EQ(big.digests.sha256, Hasher::of(expect).sha256);
    EXPECT_EQ(big.digests.bytes, expect.size());
    EXPECT_FALSE(big.truncated);
}

// ------------------------------------------------------------------ synthetic tests

TEST(SquashfsSynth, LittleEndian) {
    Synth s({});
    const auto img = s.build();
    SquashfsReader r;
    ASSERT_TRUE(r.open(span_of(img)).ok);
    const FilesystemInfo fi = r.info();
    EXPECT_EQ(fi.format, "squashfs");
    EXPECT_EQ(fi.block_size, 4096u);
    EXPECT_EQ(fi.compression, "gzip");
    EXPECT_EQ(fi.endian, Endian::Little);
    EXPECT_EQ(fi.size, img.size());
    EXPECT_EQ(fi.attrs.at("inodes"), "10");
    EXPECT_EQ(fi.attrs.at("fragments"), "1");
    EXPECT_EQ(fi.attrs.at("version"), "4.0");
    EXPECT_EQ(fi.attrs.at("magic"), "hsqs");
    EXPECT_EQ(fi.attrs.at("exportable"), "false");
    EXPECT_TRUE(fi.label.empty());
    check_synth(walk_listing(span_of(img), true), "le");
}

TEST(SquashfsSynth, BigEndian) {
    SynthOptions o;
    o.endian = Endian::Big;
    const auto img = Synth(o).build();
    SquashfsReader r;
    ASSERT_TRUE(r.open(span_of(img)).ok);
    EXPECT_EQ(r.info().endian, Endian::Big);
    EXPECT_EQ(r.info().attrs.at("magic"), "sqsh");
    check_synth(walk_listing(span_of(img), true), "be");
}

TEST(SquashfsSynth, VendorMagics) {
    for (const auto& [magic, endian] : std::vector<std::pair<std::string, Endian>>{
             {"shsq", Endian::Little}, {"qshs", Endian::Big}}) {
        SynthOptions o;
        o.endian = endian;
        o.magic = magic;
        const auto img = Synth(o).build();
        SquashfsReader r;
        ASSERT_TRUE(r.open(span_of(img)).ok) << magic;
        EXPECT_EQ(r.info().endian, endian) << magic;
        check_synth(walk_listing(span_of(img), true), magic);
    }
}

TEST(SquashfsSynth, NotSquashfs) {
    SquashfsReader r;
    EXPECT_FALSE(r.open(span_of(std::vector<std::uint8_t>(200, 0))).ok);
    EXPECT_FALSE(r.open(span_of({})).ok);
    std::vector<std::uint8_t> v(200, 0);
    std::memcpy(v.data(), "hsqs", 4);  // magic but major 0
    EXPECT_FALSE(r.open(span_of(v)).ok);
    // Walking without a successful open fails cleanly.
    ListingSink sink;
    WalkResult out;
    EXPECT_FALSE(r.walk(sink, {}, out).ok);
    EXPECT_EQ(r.info().format, "squashfs");
}

TEST(SquashfsSynth, DirectoryLoop) {
    SynthOptions o;
    o.loop = true;
    const auto img = Synth(o).build();
    const Walked w = walk_listing(span_of(img), false);
    ASSERT_TRUE(w.status.ok) << w.status.error;
    EXPECT_TRUE(has_code(w.result.diagnostics, "squashfs-dir-loop"))
        << join_diags(w.result.diagnostics);
    // Everything else is still there, exactly once.
    EXPECT_EQ(w.result.entries, 8u);
    EXPECT_EQ(w.by_path.count("sub/back"), 0u);
    EXPECT_EQ(w.by_path.count("sub/big"), 1u);
}

TEST(SquashfsSynth, BadInodeType) {
    SynthOptions o;
    o.bad_type = true;
    const auto img = Synth(o).build();
    const Walked w = walk_listing(span_of(img), false);
    ASSERT_TRUE(w.status.ok);
    EXPECT_TRUE(has_code(w.result.diagnostics, "squashfs-bad-inode-type"))
        << join_diags(w.result.diagnostics);
    EXPECT_EQ(w.by_path.count("weird"), 0u);
    EXPECT_EQ(w.result.entries, 8u);
}

TEST(SquashfsSynth, UnknownCompression) {
    SynthOptions o;
    o.compression = 9;
    o.compressed_meta = true;
    const auto img = Synth(o).build();
    SquashfsReader r;
    ASSERT_TRUE(r.open(span_of(img)).ok);
    EXPECT_EQ(r.info().compression, "unknown");
    ListingSink sink;
    WalkResult out;
    const Status s = r.walk(sink, {}, out);
    EXPECT_FALSE(s.ok);
    EXPECT_TRUE(has_code(out.diagnostics, "squashfs-unsupported-compression"))
        << join_diags(out.diagnostics);
    EXPECT_TRUE(has_code(out.diagnostics, "squashfs-metadata-corrupt"))
        << join_diags(out.diagnostics);
}

TEST(SquashfsSynth, CorruptMetadataPayload) {
    // Claims gzip-compressed inode table but the bytes are raw: decode fails.
    SynthOptions o;
    o.compressed_meta = true;
    const auto img = Synth(o).build();
    SquashfsReader r;
    ASSERT_TRUE(r.open(span_of(img)).ok);
    ListingSink sink;
    WalkResult out;
    EXPECT_FALSE(r.walk(sink, {}, out).ok);
    EXPECT_TRUE(has_code(out.diagnostics, "squashfs-metadata-corrupt"))
        << join_diags(out.diagnostics);
}

TEST(SquashfsSynth, XattrCountRecorded) {
    SynthOptions o;
    o.with_xattr_table = true;
    const auto img = Synth(o).build();
    const Walked w = walk_listing(span_of(img), false);
    ASSERT_TRUE(w.status.ok) << w.status.error;
    EXPECT_EQ(w.by_path.at("sub/big").meta.extra.at("xattrs"), "2");
    EXPECT_EQ(w.by_path.at("hello.txt").meta.extra.count("xattrs"), 0u);
    SquashfsReader r;
    ASSERT_TRUE(r.open(span_of(img)).ok);
    EXPECT_EQ(r.info().attrs.at("xattr_ids"), "1");
}

TEST(SquashfsSynth, MetadataOnlyWalk) {
    const auto img = Synth({}).build();
    WalkOptions opts;
    opts.extract_data = false;
    const Walked w = walk_listing(span_of(img), true, opts);
    ASSERT_TRUE(w.status.ok);
    EXPECT_EQ(w.result.entries, 8u);
    EXPECT_EQ(w.by_path.at("hello.txt").meta.size, 12u);
    EXPECT_EQ(w.by_path.at("hello.txt").digests.bytes, 0u);
    EXPECT_EQ(w.result.bytes, 0u);
}

TEST(SquashfsSynth, LimitsStopTheWalk) {
    const auto img = Synth({}).build();
    {
        WalkOptions opts;
        opts.limits.max_files = 3;
        const Walked w = walk_listing(span_of(img), false, opts);
        ASSERT_TRUE(w.status.ok);
        EXPECT_TRUE(w.result.truncated);
        EXPECT_EQ(w.result.entries, 3u);
        EXPECT_TRUE(has_code(w.result.diagnostics, "squashfs-limit-files"))
            << join_diags(w.result.diagnostics);
    }
    {
        WalkOptions opts;
        opts.limits.max_nodes_per_fs = 2;
        const Walked w = walk_listing(span_of(img), false, opts);
        ASSERT_TRUE(w.status.ok);
        EXPECT_TRUE(w.result.truncated);
        EXPECT_EQ(w.result.entries, 2u);
        EXPECT_TRUE(has_code(w.result.diagnostics, "squashfs-limit-nodes"))
            << join_diags(w.result.diagnostics);
    }
    {
        // A per-file byte limit in the sink truncates the data; the reader
        // records it and moves on to the next entry.
        WalkOptions opts;
        opts.limits.max_file_bytes = 100;
        const Walked w = walk_listing(span_of(img), true, opts);
        ASSERT_TRUE(w.status.ok);
        EXPECT_EQ(w.result.entries, 8u);
        EXPECT_TRUE(w.by_path.at("sub/big").truncated);
        EXPECT_FALSE(w.by_path.at("hello.txt").truncated);
    }
}

TEST(SquashfsSynth, DirectoryListingCappedByNodeLimit) {
    // The root listing has six entries; with max_nodes_per_fs = 3 the listing
    // itself is cut at three (rule 4), not just the walk that follows it.
    const auto img = Synth({}).build();
    WalkOptions opts;
    opts.limits.max_nodes_per_fs = 3;
    const Walked w = walk_listing(span_of(img), false, opts);
    ASSERT_TRUE(w.status.ok) << w.status.error;
    EXPECT_TRUE(w.result.truncated);
    EXPECT_TRUE(has_code(w.result.diagnostics, "squashfs-limit-nodes"))
        << join_diags(w.result.diagnostics);
    EXPECT_EQ(w.result.entries, 3u);
    EXPECT_EQ(w.by_path.count("blk"), 1u);
    EXPECT_EQ(w.by_path.count("empty"), 1u);
    EXPECT_EQ(w.by_path.count("fifo"), 0u);
}

TEST(SquashfsHostile, SymlinkTargetSizeIsNeverAllocatedUpFront) {
    // target_size 0xFFFFFFFF used to allocate 4 GiB before reading a byte.
    {
        SynthOptions o;
        o.symlink_target_size = 0xFFFFFFFFu;
        const Walked w = walk_listing(span_of(Synth(o).build()), false);
        ASSERT_TRUE(w.status.ok) << w.status.error;
        EXPECT_TRUE(has_code(w.result.diagnostics, "squashfs-limit-file-bytes"))
            << join_diags(w.result.diagnostics);
        EXPECT_EQ(w.by_path.count("sub/link"), 0u);
        EXPECT_EQ(w.result.entries, 7u);
    }
    {
        // Within the limit but longer than the metadata stream: corrupt inode,
        // skipped, everything else intact.
        SynthOptions o;
        o.symlink_target_size = 5000;
        const Walked w = walk_listing(span_of(Synth(o).build()), false);
        ASSERT_TRUE(w.status.ok) << w.status.error;
        EXPECT_TRUE(has_code(w.result.diagnostics, "squashfs-metadata-corrupt"))
            << join_diags(w.result.diagnostics);
        EXPECT_EQ(w.by_path.count("sub/link"), 0u);
        EXPECT_EQ(w.result.entries, 7u);
    }
    {
        // The guard is the Limits field, not a hard-coded cap.
        WalkOptions opts;
        opts.limits.max_file_bytes = 4;
        const Walked w = walk_listing(span_of(Synth({}).build()), false, opts);
        ASSERT_TRUE(w.status.ok) << w.status.error;
        EXPECT_TRUE(has_code(w.result.diagnostics, "squashfs-limit-file-bytes"))
            << join_diags(w.result.diagnostics);
        EXPECT_EQ(w.by_path.count("sub/link"), 0u);
    }
}

TEST(SquashfsSynth, Registry) {
    FilesystemRegistry& reg = FilesystemRegistry::instance();
    const std::vector<std::string> formats = reg.formats();
    EXPECT_NE(std::find(formats.begin(), formats.end(), "squashfs"), formats.end());
    std::unique_ptr<FilesystemReader> r = reg.create("squashfs");
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->format(), "squashfs");
    EXPECT_EQ(reg.create("no-such-format"), nullptr);
    EXPECT_TRUE(r->open(span_of(Synth({}).build())).ok);
}

// ------------------------------------------------------------------ hostile input

// Opens and walks whatever it is given; the only requirement is no crash and
// no UB. Returns true if the walk reported success.
bool survive(const std::vector<std::uint8_t>& img) {
    Walked w = walk_listing(span_of(img), true);
    // Also through DiskSink-free metadata-only path.
    WalkOptions opts;
    opts.extract_data = false;
    walk_listing(span_of(img), false, opts);
    return w.status.ok;
}

TEST(SquashfsHostile, TruncatedSyntheticAtEveryOffset) {
    const auto img = Synth({}).build();
    ASSERT_LT(img.size(), 8000u);
    for (std::size_t cut = 0; cut < img.size(); ++cut) {
        std::vector<std::uint8_t> t(img.begin(), img.begin() + static_cast<std::ptrdiff_t>(cut));
        survive(t);
    }
    EXPECT_TRUE(survive(img));
}

TEST(SquashfsHostile, SuperblockPointersAndSizes) {
    const auto base = Synth({}).build();
    auto put64 = [](std::vector<std::uint8_t>& v, std::size_t off, std::uint64_t x) {
        for (std::size_t i = 0; i < 8; ++i) v[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
    };
    auto put32 = [](std::vector<std::uint8_t>& v, std::size_t off, std::uint32_t x) {
        for (std::size_t i = 0; i < 4; ++i) v[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
    };
    auto put16 = [](std::vector<std::uint8_t>& v, std::size_t off, std::uint16_t x) {
        for (std::size_t i = 0; i < 2; ++i) v[off + i] = static_cast<std::uint8_t>(x >> (8 * i));
    };
    const std::uint64_t evil[] = {0,
                                  1,
                                  95,
                                  96,
                                  base.size() - 1,
                                  base.size(),
                                  base.size() + 1,
                                  0x7FFFFFFFFFFFFFFFull,
                                  0xFFFFFFFFFFFFFFF0ull,
                                  0xFFFFFFFFFFFFFFFEull,
                                  0xFFFFFFFFFFFFFFFFull};
    // Every 64-bit pointer field: root_inode, bytes_used, id, xattr, inode, dir, frag, export.
    for (std::size_t off = 32; off <= 88; off += 8) {
        for (std::uint64_t v : evil) {
            std::vector<std::uint8_t> img = base;
            put64(img, off, v);
            survive(img);
        }
    }
    // A table the walk depends on pointing outside the image must leave a trace.
    for (std::size_t off : {std::size_t{64}, std::size_t{72}, std::size_t{80}, std::size_t{48}}) {
        for (std::uint64_t v :
             std::vector<std::uint64_t>{base.size() + 1, 0x7FFFFFFFFFFFFFFFull,
                                        0xFFFFFFFFFFFFFFF0ull, 0xFFFFFFFFFFFFFFFFull}) {
            std::vector<std::uint8_t> img = base;
            put64(img, off, v);
            Status open;
            const Walked w = walk_listing(span_of(img), true, {}, &open);
            EXPECT_TRUE(!open.ok || !w.status.ok || !w.result.diagnostics.empty())
                << "off " << off << " v " << v;
        }
    }
    // Inode references inside the root inode field with absurd offsets.
    for (std::uint64_t v : {0xFFFFull, 0x10000ull, 0x1FFFFull, 0xFFFF0000ull, 0x2000ull << 16}) {
        std::vector<std::uint8_t> img = base;
        put64(img, 32, v);
        const Walked w = walk_listing(span_of(img), false);
        EXPECT_FALSE(w.status.ok) << "root ref " << v;
    }
    // Block size / log / compression / id count.
    for (std::uint32_t bs :
         {0u, 1u, 4095u, 4097u, 1u << 20, (1u << 20) + 1, 1u << 31, 0xFFFFFFFFu}) {
        std::vector<std::uint8_t> img = base;
        put32(img, 12, bs);
        SquashfsReader r;
        EXPECT_FALSE(r.open(span_of(img)).ok) << "block_size " << bs;
    }
    for (std::uint16_t bl : std::vector<std::uint16_t>{0, 11, 13, 21, 63, 0xFFFF}) {
        std::vector<std::uint8_t> img = base;
        put16(img, 22, bl);
        SquashfsReader r;
        EXPECT_FALSE(r.open(span_of(img)).ok) << "block_log " << bl;
    }
    {
        // Consistent but huge block size (1 MiB, log 20): data blocks then claim
        // more than the image holds.
        std::vector<std::uint8_t> img = base;
        put32(img, 12, 1u << 20);
        put16(img, 22, 20);
        const Walked w = walk_listing(span_of(img), true);
        EXPECT_TRUE(w.status.ok);
        EXPECT_FALSE(w.result.diagnostics.empty());
    }
    for (std::uint16_t comp : std::vector<std::uint16_t>{0, 7, 0xFFFF}) {
        std::vector<std::uint8_t> img = base;
        put16(img, 20, comp);
        Status open;
        const Walked w = walk_listing(span_of(img), true, {}, &open);
        // Metadata here is stored uncompressed, so the walk still succeeds but
        // the unknown codec is reported.
        EXPECT_TRUE(open.ok);
        EXPECT_TRUE(has_code(w.result.diagnostics, "squashfs-unsupported-compression"));
    }
    for (std::uint16_t ids : std::vector<std::uint16_t>{0, 1, 3, 0xFFFF}) {
        std::vector<std::uint8_t> img = base;
        put16(img, 26, ids);
        survive(img);
    }
    for (std::uint32_t frags : {0u, 2u, 0xFFFFFFFFu}) {
        std::vector<std::uint8_t> img = base;
        put32(img, 16, frags);
        survive(img);
    }
    // Version 3 and 5 are refused.
    for (std::uint16_t major : std::vector<std::uint16_t>{0, 1, 3, 5, 0xFFFF}) {
        std::vector<std::uint8_t> img = base;
        put16(img, 28, major);
        SquashfsReader r;
        EXPECT_FALSE(r.open(span_of(img)).ok) << "major " << major;
    }
}

TEST(SquashfsHostile, InodeAndDirectoryFields) {
    // Flip every byte of the inode and directory tables to 0x00, 0xFF and 0x7F
    // in turn; the parser must survive every single-byte corruption.
    const auto base = Synth({}).build();
    for (std::size_t off = 96; off < base.size(); ++off) {
        for (std::uint8_t v :
             {std::uint8_t{0x00}, std::uint8_t{0xFF}, std::uint8_t{0x7F}, std::uint8_t{0x80}}) {
            std::vector<std::uint8_t> img = base;
            if (img[off] == v) continue;
            img[off] = v;
            survive(img);
        }
    }
}

TEST(SquashfsHostile, SeededRandomFlips) {
    const auto base = Synth({}).build();
    std::uint64_t x = 0x9E3779B97F4A7C15ull;
    auto next = [&]() {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        return x * 0x2545F4914F6CDD1Dull;
    };
    for (int iter = 0; iter < 2000; ++iter) {
        std::vector<std::uint8_t> img = base;
        const std::size_t flips = 1 + static_cast<std::size_t>(next() % 8);
        for (std::size_t f = 0; f < flips; ++f) {
            const std::size_t off = static_cast<std::size_t>(next() % img.size());
            img[off] = static_cast<std::uint8_t>(next());
        }
        survive(img);
    }
}

// ------------------------------------------------------------------ mksquashfs images

struct SourceEntry {
    EntryKind kind = EntryKind::Regular;
    std::uint32_t mode = 0, uid = 0, gid = 0;
    std::uint64_t size = 0;
    std::int64_t mtime = 0;
    std::string link_target;
    std::string sha256;
};

#ifndef _WIN32
std::map<std::string, SourceEntry> scan_tree(const stdfs::path& root) {
    std::map<std::string, SourceEntry> out;
    for (const auto& de :
         stdfs::recursive_directory_iterator(root, stdfs::directory_options::none)) {
        const std::string rel = de.path().lexically_relative(root).generic_string();
        struct stat st{};
        if (::lstat(de.path().c_str(), &st) != 0) continue;
        SourceEntry e;
        if (S_ISDIR(st.st_mode))
            e.kind = EntryKind::Directory;
        else if (S_ISLNK(st.st_mode))
            e.kind = EntryKind::Symlink;
        else if (S_ISREG(st.st_mode))
            e.kind = EntryKind::Regular;
        else if (S_ISCHR(st.st_mode))
            e.kind = EntryKind::CharDevice;
        else if (S_ISFIFO(st.st_mode))
            e.kind = EntryKind::Fifo;
        else
            e.kind = EntryKind::Unknown;
        e.mode = static_cast<std::uint32_t>(st.st_mode & 07777u);
        e.uid = static_cast<std::uint32_t>(st.st_uid);
        e.gid = static_cast<std::uint32_t>(st.st_gid);
        e.mtime = static_cast<std::int64_t>(st.st_mtime);
        if (e.kind == EntryKind::Regular) {
            e.size = static_cast<std::uint64_t>(st.st_size);
            Digests d;
            if (hash_file(de.path().string(), d).ok) e.sha256 = d.sha256;
        } else if (e.kind == EntryKind::Symlink) {
            e.link_target = stdfs::read_symlink(de.path()).string();
            e.size = e.link_target.size();
        }
        out[rel] = e;
    }
    return out;
}
#endif

// Builds the source tree every mksquashfs test images. Returns the tree root.
stdfs::path make_source_tree(const TempDir& tmp) {
    const stdfs::path root = tmp.path() / "src";
    stdfs::create_directories(root / "a" / "b" / "c");
    stdfs::create_directories(root / "dev");
    stdfs::create_directories(root / "dir with spaces");
    spit(root / "a" / "b" / "c" / "deep.txt", std::string("deep\n"));
    stdfs::create_symlink("b/c/deep.txt", root / "a" / "link");
    stdfs::create_symlink("/etc/passwd", root / "abs");
    spit(root / "empty.txt", std::string());
    spit(root / "big.bin", pseudo_random(300 * 1024, 7));
    spit(root / "secret.key", pseudo_random(1024, 11));
    stdfs::permissions(root / "secret.key", stdfs::perms::owner_read | stdfs::perms::owner_write);
    {
        std::vector<std::uint8_t> z(256 * 1024 + 16, 0);
        std::memcpy(z.data() + 256 * 1024, "END-OF-SPARSE!!!", 16);
        spit(root / "zeros.bin", z);  // two all-zero blocks (stored sparse) + a 16-byte tail
    }
    spit(root / "dir with spaces" / "ünïcödé.txt", std::string("unicode name\n"));
    spit(root / "small.txt", std::string("tiny\n"));  // fragment-only file
    // A file whose size is an exact multiple of the block size (no tail).
    spit(root / "exact.bin", pseudo_random(128 * 1024, 13));
    return root;
}

// Runs mksquashfs; returns false if the tool refused (codec not compiled in).
bool build_image(const stdfs::path& src, const stdfs::path& img, const std::string& comp,
                 const std::vector<std::string>& extra) {
    std::string cmd =
        "/usr/bin/mksquashfs '" + src.string() + "' '" + img.string() + "' -comp " + comp +
        " -noappend -no-progress -quiet -no-xattrs -all-time 1700000000"
        " -p 'dev/console c 600 0 0 5 1' -p 'fifo i 644 0 0 f' -p 'blk b 660 0 0 8 17'";
    for (const std::string& a : extra) cmd += " " + a;
    cmd += " >/dev/null 2>&1";
    stdfs::remove(img);
    return run(cmd) == 0 && stdfs::exists(img);
}

// Compares every source-tree entry with what the reader produced.
void compare_listing(const std::map<std::string, SourceEntry>& src, const Walked& w,
                     const std::string& label) {
    ASSERT_TRUE(w.status.ok) << label << ": " << w.status.error << "\n"
                             << join_diags(w.result.diagnostics);
    for (const Diagnostic& d : w.result.diagnostics) {
        EXPECT_NE(d.severity, Severity::Error) << label << ": " << d.code << ": " << d.message;
        EXPECT_NE(d.severity, Severity::Warning) << label << ": " << d.code << ": " << d.message;
    }
    for (const auto& [path, e] : src) {
        const auto it = w.by_path.find(path);
        ASSERT_NE(it, w.by_path.end()) << label << ": missing " << path;
        const FileMeta& m = it->second.meta;
        EXPECT_EQ(m.kind, e.kind) << label << ": " << path;
        EXPECT_EQ(m.mode, e.mode) << label << ": " << path;
        EXPECT_EQ(m.uid, e.uid) << label << ": " << path;
        EXPECT_EQ(m.gid, e.gid) << label << ": " << path;
        if (e.kind != EntryKind::Directory) {
            EXPECT_EQ(m.size, e.size) << label << ": " << path;
        }
        EXPECT_EQ(m.mtime.value_or(-1), 1700000000) << label << ": " << path;
        EXPECT_EQ(m.link_target, e.link_target) << label << ": " << path;
        EXPECT_FALSE(it->second.truncated) << label << ": " << path;
        if (e.kind == EntryKind::Regular) {
            EXPECT_EQ(it->second.digests.sha256, e.sha256) << label << ": " << path;
            EXPECT_EQ(it->second.digests.bytes, e.size) << label << ": " << path;
            EXPECT_EQ(m.nlink, 1u) << label << ": " << path;
        }
        EXPECT_NE(m.inode, 0u) << label << ": " << path;
    }
    // The pseudo entries mksquashfs added.
    ASSERT_EQ(w.by_path.count("dev/console"), 1u) << label;
    const FileMeta& con = w.by_path.at("dev/console").meta;
    EXPECT_EQ(con.kind, EntryKind::CharDevice) << label;
    EXPECT_EQ(con.mode, 0600u) << label;
    EXPECT_EQ(con.uid, 0u) << label;
    EXPECT_EQ(con.rdev_major, 5u) << label;
    EXPECT_EQ(con.rdev_minor, 1u) << label;
    ASSERT_EQ(w.by_path.count("blk"), 1u) << label;
    EXPECT_EQ(w.by_path.at("blk").meta.kind, EntryKind::BlockDevice) << label;
    EXPECT_EQ(w.by_path.at("blk").meta.rdev_major, 8u) << label;
    EXPECT_EQ(w.by_path.at("blk").meta.rdev_minor, 17u) << label;
    ASSERT_EQ(w.by_path.count("fifo"), 1u) << label;
    EXPECT_EQ(w.by_path.at("fifo").meta.kind, EntryKind::Fifo) << label;
    EXPECT_EQ(w.by_path.at("fifo").meta.mode, 0644u) << label;
    EXPECT_EQ(w.result.entries, src.size() + 3) << label;
    // Inode numbers are unique across the image.
    std::vector<std::uint64_t> inodes;
    for (const EntryResult& e : w.result.entries_out) inodes.push_back(e.meta.inode);
    std::sort(inodes.begin(), inodes.end());
    EXPECT_EQ(std::adjacent_find(inodes.begin(), inodes.end()), inodes.end())
        << label << ": duplicate inode numbers";
}

void extract_and_diff(const Span& span, const stdfs::path& src, const stdfs::path& out,
                      const std::string& label) {
    SquashfsReader r;
    ASSERT_TRUE(r.open(span).ok) << label;
    std::unique_ptr<DiskSink> sink;
    ASSERT_TRUE(DiskSink::open(out.string(), {}, sink).ok) << label;
    WalkResult res;
    ASSERT_TRUE(r.walk(*sink, {}, res).ok) << label;
    for (const Diagnostic& d : res.diagnostics)
        EXPECT_NE(d.severity, Severity::Warning) << label << ": " << d.code << ": " << d.message;
    // Special files are recorded but not created by DiskSink, and the source
    // tree never had them, so the trees must be identical.
    const int rc = run("diff -r --no-dereference '" + src.string() + "' '" + out.string() +
                       "' >/dev/null 2>&1");
    EXPECT_EQ(rc, 0) << label << ": extracted tree differs from the source tree";
}

class SquashfsMksquashfs : public ::testing::TestWithParam<std::string> {};

TEST_P(SquashfsMksquashfs, RoundTrip) {
#ifdef _WIN32
    GTEST_SKIP() << "POSIX only";
#else
    if (!tool_exists("/usr/bin/mksquashfs")) GTEST_SKIP() << "mksquashfs not installed";
    const std::string comp = GetParam();
    TempDir tmp;
    const stdfs::path src = make_source_tree(tmp);
    const auto tree = scan_tree(src);
    ASSERT_GE(tree.size(), 14u);

    struct Variant {
        std::string name;
        std::vector<std::string> args;
    };
    const std::vector<Variant> variants = {
        {"default", {}},
        {"b4k", {"-b", "4096"}},        // many blocks per file, tiny fragments
        {"nofrag", {"-no-fragments"}},  // tails stored as short blocks
        {"alwaysfrag", {"-always-use-fragments"}},
        {"raw", {"-noI", "-noD", "-noF", "-noX"}},  // header names the codec, nothing is compressed
    };
    for (const Variant& v : variants) {
        const stdfs::path img = tmp.path() / ("img-" + comp + "-" + v.name + ".sqsh");
        if (!build_image(src, img, comp, v.args)) {
            if (v.name == "default")
                GTEST_SKIP() << "mksquashfs cannot build -comp " << comp << " on this host";
            ADD_FAILURE() << "mksquashfs failed for variant " << v.name;
            continue;
        }
        const std::string label = comp + "/" + v.name;
        std::shared_ptr<MappedFile> mf;
        ASSERT_TRUE(MappedFile::open(img.string(), mf).ok) << label;
        const Span span = Span::whole(mf);

        SquashfsReader r;
        ASSERT_TRUE(r.open(span).ok) << label;
        const FilesystemInfo fi = r.info();
        EXPECT_EQ(fi.compression, comp) << label;
        EXPECT_EQ(fi.block_size, v.name == "b4k" ? 4096u : 131072u) << label;
        EXPECT_EQ(fi.attrs.at("inodes"), std::to_string(tree.size() + 3 + 1))
            << label;  // + pseudo entries + root

        compare_listing(tree, walk_listing(span, true), label);
        extract_and_diff(span, src, tmp.path() / ("out-" + comp + "-" + v.name), label);

        // The mksquashfs image, truncated at a few dozen points, must not crash.
        const std::vector<std::uint8_t> bytes = slurp(img);
        for (std::size_t cut = 0; cut < bytes.size();
             cut += std::max<std::size_t>(1, bytes.size() / 37)) {
            std::vector<std::uint8_t> t(bytes.begin(),
                                        bytes.begin() + static_cast<std::ptrdiff_t>(cut));
            survive(t);
        }
        // Seeded flips over the compressed image (decoders see garbage).
        std::uint64_t x = 0xD1B54A32D192ED03ull ^ bytes.size();
        for (int iter = 0; iter < 60; ++iter) {
            std::vector<std::uint8_t> f = bytes;
            for (int k = 0; k < 4; ++k) {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                f[static_cast<std::size_t>((x * 0x2545F4914F6CDD1Dull) % f.size())] ^=
                    static_cast<std::uint8_t>(x);
            }
            survive(f);
        }
    }
#endif
}

INSTANTIATE_TEST_SUITE_P(Codecs, SquashfsMksquashfs,
                         ::testing::Values("gzip", "xz", "lz4", "zstd", "lzo", "lzma"));

// ------------------------------------------------------------------ fixtures

// Crude parser for the flat `tree:` section of a fixture's expected.yaml
// (one `- path:` per entry, `key: value` lines below, scalars only).
std::map<std::string, std::map<std::string, std::string>> read_expected_tree(
    const stdfs::path& yaml) {
    std::map<std::string, std::map<std::string, std::string>> out;
    std::ifstream in(yaml);
    std::string line;
    bool in_tree = false;
    std::string cur;
    auto unquote = [](std::string v) {
        if (v.size() >= 2 && v.front() == '\'' && v.back() == '\'') v = v.substr(1, v.size() - 2);
        return v;
    };
    while (std::getline(in, line)) {
        if (line == "tree:") {
            in_tree = true;
            continue;
        }
        if (!in_tree) continue;
        if (!line.empty() && line[0] != ' ' && line[0] != '-') break;
        if (line.rfind("- path: ", 0) == 0) {
            cur = unquote(line.substr(8));
            out[cur]["path"] = cur;
            continue;
        }
        const auto colon = line.find(": ");
        if (cur.empty() || colon == std::string::npos) continue;
        const std::string key = line.substr(2, colon - 2);
        out[cur][key] = unquote(line.substr(colon + 2));
    }
    return out;
}

class SquashfsFixture : public ::testing::TestWithParam<std::string> {};

TEST_P(SquashfsFixture, MatchesExpectedYaml) {
    const std::string name = GetParam();
    const stdfs::path dir = stdfs::path(OMNITRACE_TEST_DATA_DIR) / "out";
    const stdfs::path img = dir / (name + ".img");
    const stdfs::path yaml = dir / (name + ".expected.yaml");
    if (!stdfs::exists(img) || !stdfs::exists(yaml))
        GTEST_SKIP() << "fixture " << name << " not built";
    const auto expected = read_expected_tree(yaml);
    ASSERT_FALSE(expected.empty());

    std::shared_ptr<MappedFile> mf;
    ASSERT_TRUE(MappedFile::open(img.string(), mf).ok);
    const Walked w = walk_listing(Span::whole(mf), true);
    ASSERT_TRUE(w.status.ok) << w.status.error << "\n" << join_diags(w.result.diagnostics);
    for (const Diagnostic& d : w.result.diagnostics)
        EXPECT_NE(d.severity, Severity::Warning) << d.code << ": " << d.message;
    EXPECT_EQ(w.result.entries, expected.size());
    for (const auto& [path, fields] : expected) {
        const auto it = w.by_path.find(path);
        ASSERT_NE(it, w.by_path.end()) << "missing " << path;
        const FileMeta& m = it->second.meta;
        const std::string kind = fields.at("kind");
        EXPECT_EQ(std::string(entry_kind_name(m.kind)), kind) << path;
        EXPECT_EQ(m.mode, static_cast<std::uint32_t>(std::stoul(fields.at("mode"), nullptr, 8)))
            << path;
        EXPECT_EQ(m.uid, static_cast<std::uint32_t>(std::stoul(fields.at("uid")))) << path;
        EXPECT_EQ(m.gid, static_cast<std::uint32_t>(std::stoul(fields.at("gid")))) << path;
        EXPECT_EQ(m.mtime.value_or(-1), std::stoll(fields.at("mtime"))) << path;
        if (kind != "directory") {
            EXPECT_EQ(m.size, std::stoull(fields.at("size"))) << path;
        }
        if (fields.count("sha256")) {
            EXPECT_EQ(it->second.digests.sha256, fields.at("sha256")) << path;
        }
        if (fields.count("nlink")) {
            EXPECT_EQ(m.nlink, static_cast<std::uint32_t>(std::stoul(fields.at("nlink")))) << path;
        }
        if (fields.count("link_target")) {
            EXPECT_EQ(m.link_target, fields.at("link_target")) << path;
        }
    }
}

INSTANTIATE_TEST_SUITE_P(Images, SquashfsFixture,
                         ::testing::Values("squashfs-gzip", "squashfs-xz", "squashfs-lz4",
                                           "squashfs-zstd", "squashfs-none"));

// ------------------------------------------------------------------ corpus: router.bin vs
// unsquashfs

TEST(SquashfsCorpus, RouterMatchesUnsquashfs) {
#ifdef _WIN32
    GTEST_SKIP() << "POSIX only";
#else
    const std::string bin = "/home/wrongbaud/projects/omnitrace/firmware/router.bin";
    if (!stdfs::exists(bin)) GTEST_SKIP() << "corpus file missing: " << bin;
    if (!tool_exists("/usr/bin/unsquashfs")) GTEST_SKIP() << "unsquashfs not installed";
    constexpr std::uint64_t kStart = 0x1c9245, kEnd = 0xc60000;

    std::shared_ptr<MappedFile> mf;
    ASSERT_TRUE(MappedFile::open(bin, mf).ok);
    const Span span = Span::whole(mf).sub(kStart);

    TempDir tmp;
    const stdfs::path ours = tmp.path() / "ours";
    const stdfs::path ref = tmp.path() / "ref";
    {
        SquashfsReader r;
        ASSERT_TRUE(r.open(span).ok);
        const FilesystemInfo fi = r.info();
        EXPECT_EQ(fi.compression, "xz");
        EXPECT_EQ(fi.block_size, 524288u);
        EXPECT_EQ(fi.attrs.at("inodes"), "3384");
        EXPECT_EQ(fi.attrs.at("fragments"), "53");
        EXPECT_EQ(fi.attrs.at("exportable"), "true");
        std::unique_ptr<DiskSink> sink;
        ASSERT_TRUE(DiskSink::open(ours.string(), {}, sink).ok);
        WalkResult res;
        ASSERT_TRUE(r.walk(*sink, {}, res).ok);
        for (const Diagnostic& d : res.diagnostics)
            EXPECT_NE(d.severity, Severity::Warning) << d.code << ": " << d.message;
        EXPECT_EQ(res.files, 2716u);
        EXPECT_EQ(res.symlinks, 438u);
        EXPECT_EQ(
            res.dirs,
            229u);  // unsquashfs -lls counts 230 including the root itself, which is not an entry
        EXPECT_EQ(res.others, 0u);
        EXPECT_FALSE(res.truncated);
    }
    // Reference: unsquashfs over the same byte slice.
    const stdfs::path slice = tmp.path() / "slice.sqsh";
    {
        const auto view = Span::whole(mf).sub(kStart, kEnd - kStart);
        const auto bytes = view.bytes(0, static_cast<std::size_t>(view.size()));
        ASSERT_TRUE(bytes.has_value());
        spit(slice, *bytes);
    }
    ASSERT_EQ(run("/usr/bin/unsquashfs -n -q -d '" + ref.string() + "' '" + slice.string() +
                  "' >/dev/null 2>&1"),
              0);
    EXPECT_EQ(run("diff -r --no-dereference '" + ours.string() + "' '" + ref.string() +
                  "' >/dev/null 2>&1"),
              0)
        << "extracted tree differs from unsquashfs output";

    struct stat a{}, b{};
    ASSERT_EQ(::lstat((ours / "etc" / "shadow").c_str(), &a), 0);
    ASSERT_EQ(::lstat((ref / "etc" / "shadow").c_str(), &b), 0);
    EXPECT_EQ(a.st_mode & 07777u, 0600u);
    EXPECT_EQ(a.st_mtime, b.st_mtime);
#endif
}

}  // namespace
}  // namespace omnitrace::fs
