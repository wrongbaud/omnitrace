// ext_test.cpp — ExtReader.
//
// Four kinds of coverage:
//   1. A synthetic ext2 image assembled byte by byte (1 KiB blocks, one
//      group, block maps, fast and slow symlinks, a device, a fifo, an EA
//      block, a freed inode named only by a slack directory entry) so the
//      parsing is pinned independently of any tool.
//   2. Real images built with mkfs.ext2/ext3/ext4 and populated with debugfs
//      at test time: default ext4, ext4 without metadata_csum/64bit, ext2 with
//      1 KiB blocks (double-indirect maps), ext3 with a journal, ext4 with
//      inline_data. Every entry's metadata and sha256 are compared with the
//      staging tree, the DiskSink output is diffed against it, and deletions
//      made with debugfs are recovered through history.
//   3. Hostile images: truncation at every offset of the synthetic image and
//      at many offsets of a mkfs image, crafted corruptions (absurd block
//      size, extent depth 9, extents past the image, rec_len 0 and > block,
//      i_size 2^60, self-referencing indirect block, directory loop), seeded
//      byte flips. Nothing may crash; run this binary under ASan+UBSan.
//   4. Fixtures under tests/fixtures/out (ext4.img with its history section)
//      and two corpus partitions (skipped when absent), diffed against
//      debugfs rdump.
#include "../../../src/filesystems/ext/ExtReader.h"

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
#include <sstream>
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
        path_ = base / ("omnitrace-ext-" + std::to_string(pid) + "-" + std::to_string(counter++));
        stdfs::remove_all(path_);
        stdfs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        // `debugfs rdump` reproduces the image's modes, and a directory
        // without owner write/search would make remove_all leave the whole
        // tree (a 1 GiB slice per run) behind in the temp directory.
        for (auto it = stdfs::recursive_directory_iterator(
                 path_, stdfs::directory_options::skip_permission_denied, ec);
             !ec && it != stdfs::recursive_directory_iterator(); it.increment(ec)) {
            if (!it->is_symlink(ec) && it->is_directory(ec))
                stdfs::permissions(it->path(), stdfs::perms::owner_all, stdfs::perm_options::add,
                                   ec);
        }
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

std::string sha256_of(const std::vector<std::uint8_t>& b) {
    return Hasher::of(b).sha256;
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

std::string capture(const std::string& cmd) {
#ifdef _WIN32
    (void)cmd;
    return {};
#else
    std::string out;
    FILE* f = ::popen(cmd.c_str(), "r");
    if (!f) return out;
    char buf[4096];
    while (std::size_t n = std::fread(buf, 1, sizeof buf, f)) out.append(buf, n);
    ::pclose(f);
    return out;
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

std::string sq(const std::string& s) {  // shell single-quote
    std::string out = "'";
    for (const char c : s) {
        if (c == '\'')
            out += "'\\''";
        else
            out += c;
    }
    return out + "'";
}

std::string dq(const std::string& s) {  // debugfs double-quote
    std::string out = "\"";
    for (const char c : s) {
        if (c == '"') out += '\\';
        out += c;
    }
    return out + "\"";
}

struct Walked {
    Status status;
    WalkResult result;
    std::map<std::string, EntryResult> by_path;  // live entries only
    std::vector<EntryResult> history;            // deleted / superseded entries
};

Walked walk_listing(const Span& span, bool hash, WalkOptions opts = {},
                    Status* open_status = nullptr) {
    Walked w;
    ExtReader r;
    const Status s = r.open(span);
    if (open_status) *open_status = s;
    if (!s) {
        w.status = s;
        return w;
    }
    ListingSink sink(hash, opts.limits);
    w.status = r.walk(sink, opts, w.result);
    for (const EntryResult& e : w.result.entries_out) {
        if (e.meta.deleted || e.meta.superseded)
            w.history.push_back(e);
        else
            w.by_path[e.meta.path] = e;
    }
    return w;
}

void put16(std::vector<std::uint8_t>& v, std::size_t off, std::uint16_t x) {
    v[off] = static_cast<std::uint8_t>(x);
    v[off + 1] = static_cast<std::uint8_t>(x >> 8);
}
void put32(std::vector<std::uint8_t>& v, std::size_t off, std::uint32_t x) {
    put16(v, off, static_cast<std::uint16_t>(x));
    put16(v, off + 2, static_cast<std::uint16_t>(x >> 16));
}

// ------------------------------------------------------------------ synthetic ext2 image
//
// 1 KiB blocks, one block group, 32 inodes of 128 bytes, rev 1 with the
// filetype feature. Block layout: 0 boot, 1 superblock, 2 GDT, 3 block bitmap,
// 4 inode bitmap, 5-8 inode table, 9 root dir, 10 lost+found, 11 sub,
// 12 hello.txt, 13-24 big (direct), 25 big's indirect block, 26 big's 13th
// block, 27 slow symlink target, 28 gone.txt (freed), 29 EA block of hello.

constexpr std::uint32_t kSynBlock = 1024;
constexpr std::uint32_t kSynBlocks = 32;
constexpr std::uint32_t kSynInodes = 32;
constexpr std::size_t kSynInodeSize = 128;
constexpr std::uint64_t kSynSb = 1024;
constexpr std::uint32_t kSynItable = 5;

struct SynthOptions {
    bool loop = false;  // sub/ contains "back" -> inode 2
    bool bad_rec_len0 = false;
    bool bad_rec_len_big = false;
    bool huge_size = false;            // big: i_size_high makes 2^60
    bool self_indirect = false;        // big's indirect block points at itself
    bool extent_depth9 = false;        // hello.txt: EXTENTS_FL with depth 9
    bool extent_past = false;          // hello.txt: extent mapping blocks past the image
    bool extent_shared_index = false;  // hello.txt: depth-5 root over one shared index block per
                                       // level (30..33), 84 entries each, ending in an empty leaf
                                       // (34): 4 * 84^4 leaf visits unless a child is checked
                                       // against its parent's entry
    bool huge_dir_size = false;        // sub: i_size 2^60 via largedir + i_size_high
    bool bad_log_block = false;        // s_log_block_size = 20
};

std::size_t syn_inode_off(std::uint32_t ino) {
    return kSynItable * kSynBlock + (ino - 1) * kSynInodeSize;
}
std::size_t syn_block_off(std::uint32_t b) {
    return static_cast<std::size_t>(b) * kSynBlock;
}

const std::string kSynHello = "hello world\n";
const std::string kSynSlowTarget =
    "../../a/very/long/symlink/target/path/that/does/not/fit/in/the/inode/block/area/x";
const std::string kSynGone = "this file was unlinked but its inode and block survive\n";

std::vector<std::uint8_t> syn_big_content() {
    return pseudo_random(12 * kSynBlock + 100, 0x5EED);  // 13 blocks, last partial
}

std::vector<std::uint8_t> build_synth(const SynthOptions& o) {
    std::vector<std::uint8_t> img(kSynBlocks * kSynBlock, 0);
    // ---- superblock
    const std::size_t sb = kSynSb;
    put32(img, sb + 0x00, kSynInodes);
    put32(img, sb + 0x04, kSynBlocks);
    put32(img, sb + 0x0C, 2);   // free blocks
    put32(img, sb + 0x10, 12);  // free inodes
    put32(img, sb + 0x14, 1);   // first data block
    put32(img, sb + 0x18, o.bad_log_block ? 20u : 0u);
    put32(img, sb + 0x20, 8192);
    put32(img, sb + 0x24, 8192);
    put32(img, sb + 0x28, kSynInodes);
    put32(img, sb + 0x2C, 1700000000u);
    put32(img, sb + 0x30, 1700000100u);
    put16(img, sb + 0x34, 3);
    put16(img, sb + 0x38, 0xEF53);
    put16(img, sb + 0x3A, 1);
    put32(img, sb + 0x48, 0);
    put32(img, sb + 0x4C, 1);
    put32(img, sb + 0x54, 11);
    put16(img, sb + 0x58, kSynInodeSize);
    put32(img, sb + 0x5C, 0x0008);                               // ext_attr
    put32(img, sb + 0x60, o.huge_dir_size ? 0x4002u : 0x0002u);  // filetype (+ largedir)
    put32(img, sb + 0x64, 0x0000);
    for (std::size_t i = 0; i < 16; ++i) img[sb + 0x68 + i] = static_cast<std::uint8_t>(i + 1);
    std::memcpy(&img[sb + 0x78], "synth", 5);
    std::memcpy(&img[sb + 0x88], "/mnt/synth", 10);
    // ---- group descriptor
    const std::size_t gd = 2 * kSynBlock;
    put32(img, gd + 0x00, 3);
    put32(img, gd + 0x04, 4);
    put32(img, gd + 0x08, kSynItable);
    put16(img, gd + 0x0C, 2);
    put16(img, gd + 0x0E, 12);
    put16(img, gd + 0x10, 3);
    // ---- bitmaps: blocks 1..29 used except 28 (freed); inodes 1..19 used except 17
    for (std::uint32_t b = 1; b <= 29; ++b) {
        if (b == 28) continue;
        const std::uint32_t bit = b - 1;  // first_data_block = 1
        img[3 * kSynBlock + bit / 8] |= static_cast<std::uint8_t>(1u << (bit % 8));
    }
    for (std::uint32_t i = 1; i <= 19; ++i) {
        if (i == 17) continue;
        img[4 * kSynBlock + (i - 1) / 8] |= static_cast<std::uint8_t>(1u << ((i - 1) % 8));
    }
    // ---- inodes
    auto inode = [&](std::uint32_t ino, std::uint16_t mode, std::uint32_t uid, std::uint32_t gid,
                     std::uint32_t size, std::uint32_t mtime, std::uint16_t links,
                     std::uint32_t blocks512) {
        const std::size_t p = syn_inode_off(ino);
        put16(img, p + 0x00, mode);
        put16(img, p + 0x02, static_cast<std::uint16_t>(uid));
        put32(img, p + 0x04, size);
        put32(img, p + 0x08, mtime + 1);
        put32(img, p + 0x0C, mtime + 2);
        put32(img, p + 0x10, mtime);
        put16(img, p + 0x18, static_cast<std::uint16_t>(gid));
        put16(img, p + 0x1A, links);
        put32(img, p + 0x1C, blocks512);
        put16(img, p + 0x78, static_cast<std::uint16_t>(uid >> 16));
        put16(img, p + 0x7A, static_cast<std::uint16_t>(gid >> 16));
        return p;
    };
    auto block_ptr = [&](std::size_t p, std::size_t i, std::uint32_t b) {
        put32(img, p + 0x28 + i * 4, b);
    };
    // 2: root
    {
        const std::size_t p = inode(2, 040755, 0, 0, kSynBlock, 1700000000u, 4, 2);
        block_ptr(p, 0, 9);
    }
    // 11: lost+found
    {
        const std::size_t p = inode(11, 040700, 0, 0, kSynBlock, 1700000001u, 2, 2);
        block_ptr(p, 0, 10);
    }
    // 12: hello.txt (+ EA block 29)
    {
        const std::size_t p =
            inode(12, 0100644, 1000, 100, static_cast<std::uint32_t>(kSynHello.size()), 1700000002u,
                  1, 4);
        block_ptr(p, 0, 12);
        put32(img, p + 0x68, 29);  // i_file_acl
        if (o.extent_shared_index) {
            img.resize(40 * kSynBlock, 0);
            put32(img, sb + 0x04, 40);       // blocks_count: room for blocks 30..34
            put32(img, p + 0x20, 0x80000);   // EXTENTS_FL
            put32(img, p + 0x04, 4u << 20);  // 4 MiB: every index entry is inside the file
            const std::size_t e = p + 0x28;
            put16(img, e + 0, 0xF30A);
            put16(img, e + 2, 4);  // entries
            put16(img, e + 4, 4);
            put16(img, e + 6, 5);  // depth 5: every entry is an index to block 30
            for (std::size_t i = 0; i < 4; ++i) {
                put32(img, e + 12 + i * 12, static_cast<std::uint32_t>(i));
                put32(img, e + 16 + i * 12, 30);
            }
            // Blocks 30..33: index nodes of depth 4..1, each with 84 entries
            // ((1024 - 12) / 12) that all point at the next block; 34: a leaf
            // with no entries.
            for (std::uint32_t b = 30; b <= 33; ++b) {
                const std::size_t x = syn_block_off(b);
                put16(img, x + 0, 0xF30A);
                put16(img, x + 2, 84);
                put16(img, x + 4, 84);
                put16(img, x + 6, static_cast<std::uint16_t>(34 - b));
                for (std::size_t i = 0; i < 84; ++i) {
                    put32(img, x + 12 + i * 12, static_cast<std::uint32_t>(i));
                    put32(img, x + 16 + i * 12, b + 1);
                }
            }
            const std::size_t leaf = syn_block_off(34);
            put16(img, leaf + 0, 0xF30A);
            put16(img, leaf + 2, 0);
            put16(img, leaf + 4, 84);
            put16(img, leaf + 6, 0);
        } else if (o.extent_depth9 || o.extent_past) {
            put32(img, p + 0x20, 0x80000);  // EXTENTS_FL
            const std::size_t e = p + 0x28;
            put16(img, e + 0, 0xF30A);
            put16(img, e + 2, 1);
            put16(img, e + 4, 4);
            put16(img, e + 6, o.extent_depth9 ? 9 : 0);
            if (o.extent_depth9) {
                put32(img, e + 12, 0);
                put32(img, e + 16, 12);  // leaf lo: block 12 (the data block, not an index node)
            } else {
                put32(img, e + 12, 0);
                put16(img, e + 16, 1);  // len
                put16(img, e + 18, 0);
                put32(img, e + 20, 31);     // physical block 31: inside blocks_count but the
                                            // content is the last block; make it point past
                put32(img, sb + 0x04, 31);  // shrink blocks_count so 31 is out of range
            }
        }
    }
    // 13: sub
    {
        const std::size_t p = inode(13, 040750, 1000, 100, kSynBlock, 1700000003u, 2, 2);
        block_ptr(p, 0, 11);
        if (o.huge_dir_size) put32(img, p + 0x6C, 1u << 28);  // i_size_high -> 2^60 + 1 KiB
    }
    // 14: sub/link (fast symlink)
    {
        const std::string t = "../hello.txt";
        const std::size_t p =
            inode(14, 0120777, 1000, 100, static_cast<std::uint32_t>(t.size()), 1700000004u, 1, 0);
        std::memcpy(&img[p + 0x28], t.data(), t.size());
    }
    // 15: dev (char 5:1, new encoding)
    {
        const std::size_t p = inode(15, 020600, 0, 0, 0, 1700000005u, 1, 0);
        put32(img, p + 0x28 + 4, (5u << 8) | 1u);
    }
    // 16: big (12 direct + 1 through the indirect block 25)
    {
        const auto content = syn_big_content();
        const std::size_t p =
            inode(16, 0100640, 70000, 70001, static_cast<std::uint32_t>(content.size()),
                  1700000006u, 1, 14 * 2);
        for (std::size_t i = 0; i < 12; ++i) block_ptr(p, i, static_cast<std::uint32_t>(13 + i));
        block_ptr(p, 12, 25);
        put32(img, syn_block_off(25), o.self_indirect ? 25u : 26u);
        for (std::size_t i = 0; i < 12; ++i)
            std::memcpy(&img[syn_block_off(static_cast<std::uint32_t>(13 + i))],
                        content.data() + i * kSynBlock, kSynBlock);
        std::memcpy(&img[syn_block_off(26)], content.data() + 12 * kSynBlock, 100);
        if (o.huge_size) put32(img, p + 0x6C, 1u << 28);  // i_size_high -> 2^60
    }
    // 17: gone.txt (freed: not in the inode bitmap, dtime set, block 28 free)
    {
        const std::size_t p = inode(17, 0100600, 1000, 100,
                                    static_cast<std::uint32_t>(kSynGone.size()), 1700000007u, 0, 2);
        put32(img, p + 0x14, 1700000500u);  // dtime
        block_ptr(p, 0, 28);
        std::memcpy(&img[syn_block_off(28)], kSynGone.data(), kSynGone.size());
    }
    // 18: slowlink (target in block 27)
    {
        const std::size_t p =
            inode(18, 0120777, 0, 0, static_cast<std::uint32_t>(kSynSlowTarget.size()), 1700000008u,
                  1, 2);
        block_ptr(p, 0, 27);
        std::memcpy(&img[syn_block_off(27)], kSynSlowTarget.data(), kSynSlowTarget.size());
    }
    // 19: fifo
    inode(19, 010644, 1000, 100, 0, 1700000009u, 1, 0);

    // ---- directories
    auto dirent = [&](std::size_t p, std::uint32_t ino, std::uint16_t rec_len,
                      const std::string& name, std::uint8_t ft, std::size_t advance = 0) {
        put32(img, p, ino);
        put16(img, p + 4, rec_len);
        img[p + 6] = static_cast<std::uint8_t>(name.size());
        img[p + 7] = ft;
        std::memcpy(&img[p + 8], name.data(), name.size());
        return p + (advance ? advance : rec_len);
    };

    auto rec = [](const std::string& name) {
        return static_cast<std::uint16_t>((8 + name.size() + 3) & ~std::size_t{3});
    };
    {
        std::size_t p = syn_block_off(9);
        const std::size_t end = p + kSynBlock;
        p = dirent(p, 2, 12, ".", 2);
        p = dirent(p, 2, 12, "..", 2);
        p = dirent(p, 11, rec("lost+found"), "lost+found", 2);
        p = dirent(p, 12, o.bad_rec_len0 ? std::uint16_t{0} : rec("hello.txt"), "hello.txt", 1,
                   rec("hello.txt"));
        p = dirent(p, 13, rec("sub"), "sub", 2);
        p = dirent(p, 15, o.bad_rec_len_big ? std::uint16_t{2048} : rec("dev"), "dev", 3,
                   rec("dev"));
        p = dirent(p, 16, rec("big"), "big", 1);
        p = dirent(p, 18, rec("slowlink"), "slowlink", 7);
        const std::size_t last = p;
        // fifo is the last live entry: its rec_len spans the rest of the block,
        // and the slack holds the unlinked "gone.txt" entry as the kernel leaves it.
        dirent(last, 19, static_cast<std::uint16_t>(end - last), "fifo", 5);
        dirent(last + rec("fifo"), 17, static_cast<std::uint16_t>(end - last - rec("fifo")),
               "gone.txt", 1);
    }
    {
        std::size_t p = syn_block_off(10);
        p = dirent(p, 11, 12, ".", 2);
        dirent(p, 2, static_cast<std::uint16_t>(kSynBlock - 12), "..", 2);
    }
    {
        std::size_t p = syn_block_off(11);
        const std::size_t end = p + kSynBlock;
        p = dirent(p, 13, 12, ".", 2);
        p = dirent(p, 2, 12, "..", 2);
        if (o.loop) {
            p = dirent(p, 14, rec("link"), "link", 7);
            dirent(p, 2, static_cast<std::uint16_t>(end - p), "back", 2);
        } else {
            dirent(p, 14, static_cast<std::uint16_t>(end - p), "link", 7);
        }
    }
    // ---- EA block 29: user.test = "yes" (3 bytes), value at the block end
    {
        const std::size_t b = syn_block_off(29);
        put32(img, b + 0, 0xEA020000u);
        put32(img, b + 4, 1);  // refcount
        put32(img, b + 8, 1);  // blocks
        const std::size_t e = b + 32;
        img[e + 0] = 4;  // name_len "test"
        img[e + 1] = 1;  // user.
        put16(img, e + 2, kSynBlock - 4);
        put32(img, e + 4, 0);
        put32(img, e + 8, 3);
        std::memcpy(&img[e + 16], "test", 4);
        std::memcpy(&img[b + kSynBlock - 4], "yes", 3);
    }
    // hello.txt data
    std::memcpy(&img[syn_block_off(12)], kSynHello.data(), kSynHello.size());
    return img;
}

// ------------------------------------------------------------------ synthetic tests

TEST(ExtSynthetic, ListsEveryEntryWithMetadata) {
    const Walked w = walk_listing(span_of(build_synth({})), true);
    ASSERT_TRUE(w.status.ok) << w.status.error << "\n" << join_diags(w.result.diagnostics);
    for (const Diagnostic& d : w.result.diagnostics)
        EXPECT_NE(d.severity, Severity::Warning) << d.code << ": " << d.message;
    ASSERT_EQ(w.result.entries, 8u) << join_diags(w.result.diagnostics);
    EXPECT_EQ(w.result.files, 2u);
    EXPECT_EQ(w.result.dirs, 2u);
    EXPECT_EQ(w.result.symlinks, 2u);
    EXPECT_EQ(w.result.others, 2u);
    EXPECT_FALSE(w.result.truncated);

    // Emission order: on-disk directory order, children after their directory.
    std::vector<std::string> order;
    for (const EntryResult& e : w.result.entries_out) order.push_back(e.meta.path);
    const std::vector<std::string> expected = {"hello.txt", "sub",      "sub/link", "dev",
                                               "big",       "slowlink", "fifo"};
    ASSERT_EQ(order.size(), 8u);
    EXPECT_EQ(std::vector<std::string>(order.begin() + 1, order.end()), expected);
    EXPECT_EQ(order[0], "lost+found");

    const EntryResult& hello = w.by_path.at("hello.txt");
    EXPECT_EQ(hello.meta.kind, EntryKind::Regular);
    EXPECT_EQ(hello.meta.mode, 0644u);
    EXPECT_EQ(hello.meta.uid, 1000u);
    EXPECT_EQ(hello.meta.gid, 100u);
    EXPECT_EQ(hello.meta.size, kSynHello.size());
    EXPECT_EQ(hello.meta.inode, 12u);
    EXPECT_EQ(hello.meta.nlink, 1u);
    EXPECT_EQ(hello.meta.mtime.value_or(0), 1700000002);
    EXPECT_EQ(hello.meta.atime.value_or(0), 1700000003);
    EXPECT_EQ(hello.meta.ctime.value_or(0), 1700000004);
    EXPECT_FALSE(hello.meta.crtime.has_value());  // 128-byte inodes have no crtime
    EXPECT_FALSE(hello.meta.mtime_nsec.has_value());
    EXPECT_EQ(hello.digests.sha256,
              sha256_of(std::vector<std::uint8_t>(kSynHello.begin(), kSynHello.end())));
    EXPECT_EQ(hello.meta.extra.at("xattrs"), "user.test=3");

    const EntryResult& big = w.by_path.at("big");
    EXPECT_EQ(big.meta.size, 12 * kSynBlock + 100);
    EXPECT_EQ(big.meta.uid, 70000u);  // uid_high in use
    EXPECT_EQ(big.meta.gid, 70001u);
    EXPECT_EQ(big.digests.sha256, sha256_of(syn_big_content()));
    EXPECT_FALSE(big.truncated);

    const EntryResult& link = w.by_path.at("sub/link");
    EXPECT_EQ(link.meta.kind, EntryKind::Symlink);
    EXPECT_EQ(link.meta.link_target, "../hello.txt");
    EXPECT_EQ(link.meta.mode, 0777u);
    const EntryResult& slow = w.by_path.at("slowlink");
    EXPECT_EQ(slow.meta.link_target, kSynSlowTarget);

    const EntryResult& dev = w.by_path.at("dev");
    EXPECT_EQ(dev.meta.kind, EntryKind::CharDevice);
    EXPECT_EQ(dev.meta.rdev_major, 5u);
    EXPECT_EQ(dev.meta.rdev_minor, 1u);
    EXPECT_EQ(dev.meta.mode, 0600u);
    EXPECT_EQ(w.by_path.at("fifo").meta.kind, EntryKind::Fifo);
    EXPECT_EQ(w.by_path.at("sub").meta.mode, 0750u);
    EXPECT_EQ(w.by_path.at("sub").meta.nlink, 2u);
    EXPECT_EQ(w.by_path.at("lost+found").meta.mode, 0700u);
    EXPECT_TRUE(w.history.empty());
}

TEST(ExtSynthetic, InfoAttrs) {
    ExtReader r;
    EXPECT_EQ(r.format(), "ext");
    ASSERT_TRUE(r.open(span_of(build_synth({}))).ok);
    EXPECT_EQ(r.format(), "ext2");
    const FilesystemInfo fi = r.info();
    EXPECT_EQ(fi.format, "ext2");
    EXPECT_EQ(fi.label, "synth");
    EXPECT_EQ(fi.block_size, 1024u);
    EXPECT_EQ(fi.size, 32u * 1024u);
    EXPECT_EQ(fi.attrs.at("volume_name"), "synth");
    EXPECT_EQ(fi.attrs.at("uuid"), "01020304-0506-0708-090a-0b0c0d0e0f10");
    EXPECT_EQ(fi.attrs.at("inode_count"), "32");
    EXPECT_EQ(fi.attrs.at("blocks_count"), "32");
    EXPECT_EQ(fi.attrs.at("free_blocks"), "2");
    EXPECT_EQ(fi.attrs.at("free_inodes"), "12");
    EXPECT_EQ(fi.attrs.at("feature_compat"), "0x00000008");
    EXPECT_EQ(fi.attrs.at("feature_incompat"), "0x00000002");
    EXPECT_EQ(fi.attrs.at("features"), "ext_attr|filetype|");
    EXPECT_EQ(fi.attrs.at("state"), "clean");
    EXPECT_EQ(fi.attrs.at("last_mount_time"), "1700000000");
    EXPECT_EQ(fi.attrs.at("last_write_time"), "1700000100");
    EXPECT_EQ(fi.attrs.at("mount_count"), "3");
    EXPECT_EQ(fi.attrs.at("creator_os"), "linux");
    EXPECT_EQ(fi.attrs.at("has_journal"), "false");
    EXPECT_EQ(fi.attrs.at("journal_inode"), "0");
    EXPECT_EQ(fi.attrs.at("csum_type"), "none");
    EXPECT_EQ(fi.attrs.at("last_mounted"), "/mnt/synth");
    EXPECT_EQ(fi.attrs.at("block_groups"), "1");
}

TEST(ExtSynthetic, HistoryRecoversFreedInodeNamedInSlack) {
    WalkOptions opts;
    opts.history = true;
    const Walked w = walk_listing(span_of(build_synth({})), true, opts);
    ASSERT_TRUE(w.status.ok) << w.status.error;
    EXPECT_EQ(w.by_path.size(), 8u);
    ASSERT_EQ(w.history.size(), 1u) << join_diags(w.result.diagnostics);
    const EntryResult& gone = w.history[0];
    EXPECT_EQ(gone.meta.path, "gone.txt");
    EXPECT_TRUE(gone.meta.deleted);
    EXPECT_FALSE(gone.meta.superseded);
    EXPECT_EQ(gone.meta.version, 1u);
    EXPECT_EQ(gone.meta.inode, 17u);
    EXPECT_EQ(gone.meta.size, kSynGone.size());
    EXPECT_EQ(gone.meta.mode, 0600u);
    EXPECT_EQ(gone.meta.mtime.value_or(0), 1700000007);
    EXPECT_EQ(gone.meta.extra.at("dtime"), "1700000500");
    EXPECT_EQ(gone.meta.extra.at("content"), "recovered from unallocated blocks");
    EXPECT_EQ(gone.digests.sha256,
              sha256_of(std::vector<std::uint8_t>(kSynGone.begin(), kSynGone.end())));
    EXPECT_FALSE(gone.truncated);
    EXPECT_EQ(w.result.deleted, 1u);
    EXPECT_EQ(w.result.superseded, 0u);
    EXPECT_FALSE(has_code(w.result.diagnostics, "ext-deleted-no-blocks"));
}

TEST(ExtSynthetic, HistoryMarksReusedBlocksAndClearedMaps) {
    // Block 28 allocated again: the content is not trustworthy and is zero-filled.
    {
        auto img = build_synth({});
        img[3 * kSynBlock + 27 / 8] |= static_cast<std::uint8_t>(1u << (27 % 8));
        WalkOptions opts;
        opts.history = true;
        const Walked w = walk_listing(span_of(img), true, opts);
        ASSERT_EQ(w.history.size(), 1u);
        EXPECT_TRUE(w.history[0].truncated);
        EXPECT_TRUE(has_code(w.result.diagnostics, "ext-deleted-blocks-reused"));
        EXPECT_NE(w.history[0].meta.extra.at("content").find("reused"), std::string::npos);
    }
    // Block map cleared (what the kernel does on a real unlink): metadata only.
    {
        auto img = build_synth({});
        put32(img, syn_inode_off(17) + 0x28, 0);
        WalkOptions opts;
        opts.history = true;
        const Walked w = walk_listing(span_of(img), true, opts);
        ASSERT_EQ(w.history.size(), 1u);
        EXPECT_EQ(w.history[0].meta.size, kSynGone.size());
        EXPECT_EQ(w.history[0].digests.bytes, 0u);
        EXPECT_TRUE(w.history[0].truncated);
        EXPECT_EQ(w.history[0].meta.extra.at("content"), "unavailable: block map cleared");
        EXPECT_TRUE(has_code(w.result.diagnostics, "ext-deleted-no-blocks"));
    }
    // A freed inode with no surviving name lands in lost+found/#<inode>.
    {
        auto img = build_synth({});
        const std::size_t slack = syn_block_off(9) + kSynBlock;  // overwrite the gone.txt remnant
        std::size_t p = slack;
        for (std::size_t i = 0; i < kSynBlock; ++i)
            if (std::memcmp(&img[syn_block_off(9) + i], "gone.txt", 8) == 0)
                p = syn_block_off(9) + i;
        ASSERT_NE(p, slack);
        std::memset(&img[p - 8], 0, 8 + 8);
        WalkOptions opts;
        opts.history = true;
        const Walked w = walk_listing(span_of(img), true, opts);
        ASSERT_EQ(w.history.size(), 1u);
        EXPECT_EQ(w.history[0].meta.path, "lost+found/#17");
        EXPECT_TRUE(w.history[0].meta.deleted);
        EXPECT_EQ(w.history[0].digests.sha256,
                  sha256_of(std::vector<std::uint8_t>(kSynGone.begin(), kSynGone.end())));
    }
    // A slack name whose inode is live elsewhere is a rename: dropped.
    {
        auto img = build_synth({});
        std::size_t p = 0;
        for (std::size_t i = 0; i < kSynBlock; ++i)
            if (std::memcmp(&img[syn_block_off(9) + i], "gone.txt", 8) == 0)
                p = syn_block_off(9) + i;
        put32(img, p - 8, 12);  // now names hello.txt's inode
        WalkOptions opts;
        opts.history = true;
        const Walked w = walk_listing(span_of(img), true, opts);
        for (const EntryResult& e : w.history) EXPECT_NE(e.meta.path, "gone.txt");
        EXPECT_EQ(w.by_path.size(), 8u);
    }
}

TEST(ExtSynthetic, DiskSinkRoundTrip) {
    TempDir tmp;
    const stdfs::path out = tmp.path() / "out";
    ExtReader r;
    ASSERT_TRUE(r.open(span_of(build_synth({}))).ok);
    std::unique_ptr<DiskSink> sink;
    ASSERT_TRUE(DiskSink::open(out.string(), {}, sink).ok);
    WalkResult res;
    WalkOptions opts;
    opts.history = true;
    ASSERT_TRUE(r.walk(*sink, opts, res).ok);
    EXPECT_EQ(slurp(out / "hello.txt"),
              std::vector<std::uint8_t>(kSynHello.begin(), kSynHello.end()));
    EXPECT_EQ(slurp(out / "big"), syn_big_content());
    EXPECT_TRUE(stdfs::is_symlink(out / "sub" / "link"));
    EXPECT_EQ(stdfs::read_symlink(out / "sub" / "link").string(), "../hello.txt");
    EXPECT_TRUE(stdfs::is_directory(out / "lost+found"));
    EXPECT_FALSE(stdfs::exists(out / "dev"));  // specials are recorded, not created
    EXPECT_EQ(slurp(out / ".omnitrace-versions" / "gone.txt" / "v1"),
              std::vector<std::uint8_t>(kSynGone.begin(), kSynGone.end()));
}

TEST(ExtSynthetic, Registry) {
    for (const char* id : {"ext2", "ext3", "ext4"}) {
        auto r = FilesystemRegistry::instance().create(id);
        ASSERT_NE(r, nullptr) << id;
        EXPECT_EQ(r->format(), "ext");
        EXPECT_TRUE(r->open(span_of(build_synth({}))).ok);
        EXPECT_EQ(r->format(), "ext2");
    }
    EXPECT_FALSE(ExtReader().open(span_of(std::vector<std::uint8_t>(4096, 0))).ok);
}

// ------------------------------------------------------------------ hostile

// Opens and walks (with history, hashing, small limits) and returns the
// diagnostics; the only requirement is that nothing crashes.
WalkResult survive(std::vector<std::uint8_t> bytes, Status* open_st = nullptr,
                   Status* walk_st = nullptr) {
    WalkOptions opts;
    opts.history = true;
    opts.limits.max_file_bytes = 4u << 20;
    opts.limits.max_nodes_per_fs = 200000;
    Status os;
    Walked w = walk_listing(span_of(std::move(bytes)), true, opts, &os);
    if (open_st) *open_st = os;
    if (walk_st) *walk_st = w.status;
    return std::move(w.result);
}

TEST(ExtHostile, TruncatedAtEveryOffset) {
    const auto full = build_synth({});
    for (std::size_t cut = 0; cut < full.size(); cut += 61) {
        std::vector<std::uint8_t> t(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(cut));
        survive(std::move(t));
    }
    // Exact block boundaries too.
    for (std::uint32_t b = 0; b <= kSynBlocks; ++b)
        survive(std::vector<std::uint8_t>(full.begin(), full.begin() + b * kSynBlock));
}

TEST(ExtHostile, BadLogBlockSize) {
    Status os;
    survive(build_synth({.bad_log_block = true}), &os);
    EXPECT_FALSE(os.ok);
    EXPECT_EQ(os.error.rfind("ext-superblock-bad", 0), 0u) << os.error;
}

TEST(ExtHostile, ExtentDepthNine) {
    Status os, ws;
    const WalkResult r = survive(build_synth({.extent_depth9 = true}), &os, &ws);
    ASSERT_TRUE(os.ok);
    EXPECT_TRUE(ws.ok);
    EXPECT_TRUE(has_code(r.diagnostics, "ext-extent-corrupt")) << join_diags(r.diagnostics);
    for (const EntryResult& e : r.entries_out)
        if (e.meta.path == "hello.txt") {
            EXPECT_TRUE(e.truncated);
        }
}

TEST(ExtHostile, SharedExtentIndexBlockIsRefusedOnce) {
    // Every index node is shared by all 84 entries of its parent and the
    // leaf is empty, so nothing ever advances: an unchecked walk visits the
    // leaf 4 * 84^4 times. The kernel's rules (a child starts at the logical
    // block its parent's entry names, an empty non-root node is corrupt)
    // refuse the tree on the first path and the file is cut there.
    Status os, ws;
    const WalkResult r = survive(build_synth({.extent_shared_index = true}), &os, &ws);
    ASSERT_TRUE(os.ok);
    EXPECT_TRUE(ws.ok);
    EXPECT_TRUE(has_code(r.diagnostics, "ext-extent-corrupt")) << join_diags(r.diagnostics);
    std::size_t extent_diags = 0;
    for (const Diagnostic& d : r.diagnostics) extent_diags += d.code == "ext-extent-corrupt";
    EXPECT_EQ(extent_diags, 1u) << join_diags(r.diagnostics);
    for (const EntryResult& e : r.entries_out) {
        if (e.meta.path == "hello.txt") {
            EXPECT_TRUE(e.truncated);
        }
    }
}

TEST(ExtHostile, HugeDirectorySizeIsCappedByFileBytes) {
    // A largedir directory claiming 2^60 bytes: only max_file_bytes worth of
    // directory blocks are looked at, the entries it does hold are listed.
    Status os, ws;
    const WalkResult r = survive(build_synth({.huge_dir_size = true}), &os, &ws);
    ASSERT_TRUE(os.ok);
    EXPECT_TRUE(ws.ok);
    EXPECT_TRUE(has_code(r.diagnostics, "ext-limit-file-bytes")) << join_diags(r.diagnostics);
    EXPECT_TRUE(r.truncated);
    bool link = false;
    for (const EntryResult& e : r.entries_out) link = link || e.meta.path == "sub/link";
    EXPECT_TRUE(link);
}

TEST(ExtHostile, ExtentPastImage) {
    Status os;
    const WalkResult r = survive(build_synth({.extent_past = true}), &os);
    ASSERT_TRUE(os.ok);
    EXPECT_TRUE(has_code(r.diagnostics, "ext-extent-corrupt")) << join_diags(r.diagnostics);
}

TEST(ExtHostile, DirentRecLenZeroAndOversized) {
    {
        const WalkResult r = survive(build_synth({.bad_rec_len0 = true}));
        EXPECT_TRUE(has_code(r.diagnostics, "ext-dirent-corrupt")) << join_diags(r.diagnostics);
        // Entries before the corruption are kept.
        bool lf = false;
        for (const EntryResult& e : r.entries_out) lf = lf || e.meta.path == "lost+found";
        EXPECT_TRUE(lf);
    }
    {
        const WalkResult r = survive(build_synth({.bad_rec_len_big = true}));
        EXPECT_TRUE(has_code(r.diagnostics, "ext-dirent-corrupt")) << join_diags(r.diagnostics);
    }
}

TEST(ExtHostile, HugeSizeStaysWithinLimits) {
    WalkOptions opts;
    opts.limits.max_file_bytes = 64 * 1024;
    const Walked w = walk_listing(span_of(build_synth({.huge_size = true})), true, opts);
    ASSERT_TRUE(w.status.ok);
    const EntryResult& big = w.by_path.at("big");
    EXPECT_EQ(big.meta.size, (1ull << 60) + 12 * kSynBlock + 100);
    EXPECT_TRUE(big.truncated);
    EXPECT_LE(big.digests.bytes, 64u * 1024u);
    EXPECT_TRUE(has_code(w.result.diagnostics, "ext-limit-file-bytes"));
}

TEST(ExtHostile, SelfReferencingIndirectBlock) {
    Status os, ws;
    const WalkResult r = survive(build_synth({.self_indirect = true}), &os, &ws);
    ASSERT_TRUE(os.ok);
    EXPECT_TRUE(ws.ok);
    for (const EntryResult& e : r.entries_out)
        if (e.meta.path == "big") {
            EXPECT_EQ(e.digests.bytes, 12 * kSynBlock + 100);
        }
}

TEST(ExtHostile, DirectoryLoop) {
    Status os;
    const WalkResult r = survive(build_synth({.loop = true}), &os);
    ASSERT_TRUE(os.ok);
    EXPECT_TRUE(has_code(r.diagnostics, "ext-dir-loop")) << join_diags(r.diagnostics);
    EXPECT_EQ(r.entries, 9u);  // 8 live entries + gone.txt (history); "back" is not listed
}

TEST(ExtHostile, CorruptSuperblockFields) {
    const auto full = build_synth({});
    const std::size_t sb = kSynSb;
    for (const std::size_t off : {0x00u, 0x04u, 0x14u, 0x18u, 0x20u, 0x28u, 0x4Cu, 0x54u, 0x58u,
                                  0x5Cu, 0x60u, 0x64u, 0xFEu, 0x104u, 0x150u}) {
        for (const std::uint32_t val :
             {0u, 1u, 0x7Fu, 0xFFu, 0x8000u, 0xFFFFu, 0x7FFFFFFFu, 0xFFFFFFFFu}) {
            auto img = full;
            put32(img, sb + off, val);
            survive(std::move(img));
        }
    }
    // group descriptor pointers and every inode's block pointers
    for (const std::size_t off : {0x00u, 0x04u, 0x08u}) {
        for (const std::uint32_t val : {0u, 31u, 32u, 0xFFFFFFFFu}) {
            auto img = full;
            put32(img, 2 * kSynBlock + off, val);
            survive(std::move(img));
        }
    }
    for (std::uint32_t ino = 2; ino <= 19; ++ino) {
        for (std::size_t i = 0; i < 15; ++i) {
            for (const std::uint32_t val : {0u, 1u, 5u, 31u, 0xFFFFFFFFu}) {
                auto img = full;
                put32(img, syn_inode_off(ino) + 0x28 + i * 4, val);
                survive(std::move(img));
            }
        }
        for (const std::uint32_t flags : {0x80000u, 0x10000000u, 0x800u, 0xFFFFFFFFu}) {
            auto img = full;
            put32(img, syn_inode_off(ino) + 0x20, flags);
            survive(std::move(img));
        }
        auto img = full;
        put32(img, syn_inode_off(ino) + 0x68, 9);  // EA block -> a directory block
        survive(std::move(img));
    }
}

TEST(ExtHostile, SeededByteFlips) {
    const auto full = build_synth({});
    std::uint64_t x = 0xD1B54A32D192ED03ull;
    for (int iter = 0; iter < 400; ++iter) {
        auto f = full;
        for (int k = 0; k < 6; ++k) {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            f[static_cast<std::size_t>((x * 0x2545F4914F6CDD1Dull) % f.size())] ^=
                static_cast<std::uint8_t>(x);
        }
        survive(std::move(f));
    }
}

// ------------------------------------------------------------------ real tools

#ifndef _WIN32

struct Spec {
    std::string path;
    std::string kind;  // dir | file | symlink | hardlink | chr | blk | fifo
    unsigned mode = 0644;
    std::uint32_t uid = 1000, gid = 100;
    std::int64_t mtime = 1700000000;
    std::vector<std::uint8_t> content;
    std::string target;  // symlink target or hard link source
    unsigned major = 0, minor = 0;
};

Spec S(std::string path, std::string kind, unsigned mode, std::uint32_t uid, std::uint32_t gid,
       std::int64_t mtime, std::vector<std::uint8_t> content = {}, std::string target = {},
       unsigned major = 0, unsigned minor = 0) {
    Spec s;
    s.path = std::move(path);
    s.kind = std::move(kind);
    s.mode = mode;
    s.uid = uid;
    s.gid = gid;
    s.mtime = mtime;
    s.content = std::move(content);
    s.target = std::move(target);
    s.major = major;
    s.minor = minor;
    return s;
}

std::vector<std::uint8_t> bytes_of(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

std::vector<std::uint8_t> sparse_content() {
    std::vector<std::uint8_t> v = pseudo_random(4096, 0x0A);
    v.resize(4096 + 192 * 1024, 0);
    const auto tail = pseudo_random(4096, 0x0B);
    v.insert(v.end(), tail.begin(), tail.end());
    return v;
}

constexpr int kManyFiles = 1000;
constexpr std::uint32_t kNsec = 123456789;

std::vector<Spec> make_spec() {
    const std::int64_t t = 1700000000;
    std::vector<Spec> s = {
        S("bin", "dir", 0755, 1000, 100, t + 2),
        S("bin/busybox", "file", 0755, 1000, 100, t + 4, pseudo_random(300 * 1024, 1)),
        S("bin/ash", "hardlink", 0755, 1000, 100, t + 4, {}, "bin/busybox"),
        S("bin/sh", "symlink", 0777, 1000, 100, t + 6, {}, "busybox"),
        S("etc", "dir", 0755, 0, 0, t + 8),
        S("etc/passwd", "file", 0644, 0, 0, t + 10,
          bytes_of("root:x:0:0:root:/root:/bin/sh\nadmin:x:1000:100::/home/admin:/bin/sh\n")),
        S("etc/secret.key", "file", 0600, 1000, 100, t + 12, pseudo_random(1024, 2)),
        S("etc/longlink", "symlink", 0777, 0, 0, t + 14, {},
          "../../a/very/long/symlink/target/path/that/does/not/fit/in/the/inode/i_block/area/xx"),
        S("data", "dir", 0755, 1000, 100, t + 18),
        S("data/big.bin", "file", 0644, 1000, 100, t + 20, pseudo_random(3 * 1024 * 1024, 3)),
        S("data/sparse.bin", "file", 0644, 1000, 100, t + 22, sparse_content()),
        S("data/empty.txt", "file", 0644, 1000, 100, t + 24),
        S("data/small.txt", "file", 0640, 1000, 100, t + 26, bytes_of("tiny\n")),
        S("data/dir with spaces", "dir", 0755, 1000, 100, t + 28),
        S("data/dir with spaces/ünïcödé ファイル.txt", "file", 0644, 1000, 100, t + 30,
          bytes_of("ünïcödé content ✓\n")),
        S("data/immutable.txt", "file", 0444, 0, 0, t + 32, bytes_of("do not touch\n")),
        S("data/xattr.txt", "file", 0644, 1000, 100, t + 34, bytes_of("with attributes\n")),
        S("dev", "dir", 0755, 0, 0, t + 36),
        S("dev/null", "chr", 0666, 0, 0, t + 38, {}, "", 1, 3),
        S("dev/sda", "blk", 0660, 0, 6, t + 40, {}, "", 8, 0),
        S("dev/initctl", "fifo", 0600, 0, 0, t + 42),
        S("many", "dir", 0755, 1000, 100, t + 44),
    };
    for (int i = 0; i < kManyFiles; ++i) {
        char name[16];
        std::snprintf(name, sizeof name, "f%04d", i);
        s.push_back(S("many/" + std::string(name), "file", 0644, 1000, 100, t + 100 + i,
                      bytes_of(std::string(name) + "\n")));
    }
    return s;
}

// Host staging tree: what DiskSink output must equal (no devices/fifos: the
// sink records those without creating them; lost+found is added because
// mkfs creates it).
void stage(const stdfs::path& root, const std::vector<Spec>& spec) {
    stdfs::create_directories(root / "lost+found");
    for (const Spec& e : spec) {
        const stdfs::path p = root / e.path;
        if (e.kind == "dir") {
            stdfs::create_directories(p);
        } else if (e.kind == "file") {
            spit(p, e.content);
        } else if (e.kind == "symlink") {
            stdfs::create_symlink(e.target, p);
        } else if (e.kind == "hardlink") {
            stdfs::create_hard_link(root / e.target, p);
        }
    }
}

struct Variant {
    std::string name;
    std::string mkfs;
    std::string args;
    std::uint32_t small_file_flags;  // i_flags a 13-byte file gets (debugfs sif replaces flags)
    bool inline_data;
};

const std::vector<Variant> kVariants = {
    {"ext4", "mkfs.ext4", "-b 4096 -I 256", 0x80000, false},
    {"ext4-nocsum", "mkfs.ext4", "-b 4096 -O ^metadata_csum,^64bit", 0x80000, false},
    {"ext2", "mkfs.ext2", "-b 1024 -I 128", 0, false},
    {"ext3", "mkfs.ext3", "-b 4096", 0, false},
    {"ext4-inline", "mkfs.ext4", "-b 4096 -I 256 -O inline_data", 0x10000000, true},
};

std::string debugfs_populate_script(const stdfs::path& stg, const std::vector<Spec>& spec,
                                    const Variant& v) {
    std::ostringstream sc;
    auto times = [&](const Spec& e) {
        for (const char* f : {"mtime", "atime", "ctime", "crtime"})
            sc << "sif " << dq(e.path) << " " << f << " @" << e.mtime << "\n";
    };
    // Fragment the free space first so big.bin spans more than one extent:
    // two 1 MiB files, the first removed before big.bin is written.
    const stdfs::path fragA = stg.parent_path() / "frag-a";
    const stdfs::path fragB = stg.parent_path() / "frag-b";
    spit(fragA, pseudo_random(1u << 20, 77));
    spit(fragB, pseudo_random(1u << 20, 78));
    sc << "write " << dq(fragA.string()) << " frag-a\n";
    sc << "write " << dq(fragB.string()) << " frag-b\n";
    sc << "rm frag-a\n";
    for (const Spec& e : spec) {
        if (e.kind == "dir") {
            sc << "mkdir " << dq(e.path) << "\n";
        } else if (e.kind == "file") {
            sc << "write " << dq((stg / e.path).string()) << " " << dq(e.path) << "\n";
        } else if (e.kind == "symlink") {
            sc << "symlink " << dq(e.path) << " " << dq(e.target) << "\n";
        } else if (e.kind == "hardlink") {
            sc << "ln " << dq(e.target) << " " << dq(e.path) << "\n";
            sc << "sif " << dq(e.target) << " links_count 2\n";
            continue;
        } else if (e.kind == "chr" || e.kind == "blk" || e.kind == "fifo") {
            // mknod links the literal name into the current directory.
            const auto slash = e.path.rfind('/');
            sc << "cd " << dq(e.path.substr(0, slash)) << "\n";
            sc << "mknod " << dq(e.path.substr(slash + 1)) << " ";
            if (e.kind == "fifo")
                sc << "p\n";
            else
                sc << (e.kind == "chr" ? "c " : "b ") << e.major << " " << e.minor << "\n";
            sc << "cd /\n";
        }
        if (e.kind != "symlink") {
            unsigned type = 0100000;
            if (e.kind == "dir") type = 040000;
            if (e.kind == "chr") type = 020000;
            if (e.kind == "blk") type = 060000;
            if (e.kind == "fifo") type = 010000;
            sc << "sif " << dq(e.path) << " mode 0" << std::oct << (type | e.mode) << std::dec
               << "\n";
        }
        sc << "sif " << dq(e.path) << " uid " << e.uid << "\n";
        sc << "sif " << dq(e.path) << " gid " << e.gid << "\n";
        times(e);
    }
    sc << "rm frag-b\n";
    sc << "sif data/immutable.txt flags " << (v.small_file_flags | 0x10u) << "\n";
    sc << "ea_set data/xattr.txt user.test hello\n";
    sc << "ea_set data/xattr.txt user.other 12345678\n";
    sc << "sif etc/passwd mtime_extra " << (kNsec << 2) << "\n";
    for (auto it = spec.rbegin(); it != spec.rend(); ++it)
        if (it->kind == "dir") times(*it);
    for (const char* f : {"mtime", "atime", "ctime"}) sc << "sif / " << f << " @1700000000\n";
    return sc.str();
}

std::uint32_t debugfs_inode_of(const stdfs::path& img, const std::string& path) {
    const std::string out =
        capture("debugfs -R " + sq("stat " + dq(path)) + " " + sq(img.string()) + " 2>/dev/null");
    const auto p = out.find("Inode: ");
    if (p == std::string::npos) return 0;
    return static_cast<std::uint32_t>(std::stoul(out.substr(p + 7)));
}

std::vector<std::uint64_t> debugfs_blocks_of(const stdfs::path& img, const std::string& path) {
    const std::string out =
        capture("debugfs -R " + sq("blocks " + dq(path)) + " " + sq(img.string()) + " 2>/dev/null");
    std::vector<std::uint64_t> v;
    std::istringstream in(out);
    std::uint64_t b;
    while (in >> b) v.push_back(b);
    return v;
}

bool build_image(const Variant& v, const stdfs::path& img, const stdfs::path& stg,
                 const std::vector<Spec>& spec, const std::string& size) {
    if (run(v.mkfs + " -q -F " + v.args +
            " -L omnitrace -E lazy_itable_init=0,lazy_journal_init=0 " + sq(img.string()) + " " +
            size + " >/dev/null 2>&1") != 0)
        return false;
    const stdfs::path script = img.string() + ".populate";
    spit(script, debugfs_populate_script(stg, spec, v));
    return run("debugfs -w -f " + sq(script.string()) + " " + sq(img.string()) +
               " >/dev/null 2>&1") == 0;
}

void compare_listing(const std::vector<Spec>& spec, const Walked& w, const std::string& label,
                     bool inline_data) {
    ASSERT_TRUE(w.status.ok) << label << ": " << w.status.error << "\n"
                             << join_diags(w.result.diagnostics);
    for (const Diagnostic& d : w.result.diagnostics)
        EXPECT_NE(d.severity, Severity::Warning) << label << ": " << d.code << ": " << d.message;
    EXPECT_EQ(w.by_path.size(), spec.size() + 1) << label;  // + lost+found
    for (const Spec& e : spec) {
        const auto it = w.by_path.find(e.path);
        ASSERT_NE(it, w.by_path.end()) << label << ": missing " << e.path;
        const FileMeta& m = it->second.meta;
        const std::string p = label + ": " + e.path;
        EXPECT_EQ(m.mode, e.mode) << p;
        EXPECT_EQ(m.uid, e.uid) << p;
        EXPECT_EQ(m.gid, e.gid) << p;
        EXPECT_EQ(m.mtime.value_or(-1), e.mtime) << p;
        EXPECT_EQ(m.atime.value_or(-1), e.mtime) << p;
        EXPECT_EQ(m.ctime.value_or(-1), e.mtime) << p;
        EXPECT_NE(m.inode, 0u) << p;
        if (e.kind == "file" || e.kind == "hardlink") {
            EXPECT_EQ(m.kind, EntryKind::Regular) << p;
            const std::vector<std::uint8_t>& content =
                e.kind == "hardlink"
                    ? std::find_if(spec.begin(), spec.end(),
                                   [&](const Spec& s) { return s.path == e.target; })
                          ->content
                    : e.content;
            EXPECT_EQ(m.size, content.size()) << p;
            EXPECT_EQ(it->second.digests.sha256, sha256_of(content)) << p;
            EXPECT_EQ(it->second.digests.bytes, content.size()) << p;
            EXPECT_FALSE(it->second.truncated) << p;
            EXPECT_EQ(m.nlink, e.kind == "hardlink" || e.path == "bin/busybox" ? 2u : 1u) << p;
        } else if (e.kind == "dir") {
            EXPECT_EQ(m.kind, EntryKind::Directory) << p;
        } else if (e.kind == "symlink") {
            EXPECT_EQ(m.kind, EntryKind::Symlink) << p;
            EXPECT_EQ(m.link_target, e.target) << p;
            EXPECT_EQ(m.size, e.target.size()) << p;
        } else if (e.kind == "chr" || e.kind == "blk") {
            EXPECT_EQ(m.kind, e.kind == "chr" ? EntryKind::CharDevice : EntryKind::BlockDevice)
                << p;
            EXPECT_EQ(m.rdev_major, e.major) << p;
            EXPECT_EQ(m.rdev_minor, e.minor) << p;
        } else if (e.kind == "fifo") {
            EXPECT_EQ(m.kind, EntryKind::Fifo) << p;
        }
    }
    // hard links share the inode
    EXPECT_EQ(w.by_path.at("bin/ash").meta.inode, w.by_path.at("bin/busybox").meta.inode) << label;
    EXPECT_EQ(w.by_path.at("data/immutable.txt").meta.extra.at("immutable"), "true") << label;
    // An inline_data filesystem gives every small file an empty system.data xattr.
    EXPECT_EQ(w.by_path.at("data/xattr.txt").meta.extra.at("xattrs"),
              inline_data ? "system.data=0;user.test=5;user.other=8" : "user.test=5;user.other=8")
        << label;
    EXPECT_EQ(w.by_path.at("lost+found").meta.kind, EntryKind::Directory) << label;
    EXPECT_EQ(w.by_path.at("lost+found").meta.mode, 0700u) << label;
    // children come after their directory, root entries in on-disk order
    std::map<std::string, std::size_t> pos;
    for (std::size_t i = 0; i < w.result.entries_out.size(); ++i)
        pos[w.result.entries_out[i].meta.path] = i;
    EXPECT_LT(pos.at("bin"), pos.at("bin/busybox")) << label;
    EXPECT_LT(pos.at("many"), pos.at("many/f0999")) << label;
    EXPECT_LT(pos.at("many/f0000"), pos.at("many/f0999")) << label;
}

void extract_and_diff(const Span& span, const stdfs::path& stg, const stdfs::path& out,
                      const std::string& label) {
    ExtReader r;
    ASSERT_TRUE(r.open(span).ok) << label;
    std::unique_ptr<DiskSink> sink;
    ASSERT_TRUE(DiskSink::open(out.string(), {}, sink).ok) << label;
    WalkResult res;
    ASSERT_TRUE(r.walk(*sink, {}, res).ok) << label;
    for (const Diagnostic& d : res.diagnostics)
        EXPECT_NE(d.severity, Severity::Warning) << label << ": " << d.code << ": " << d.message;
    const int rc = run("diff -r --no-dereference " + sq(stg.string()) + " " + sq(out.string()) +
                       " >/dev/null 2>&1");
    EXPECT_EQ(rc, 0) << label << ": extracted tree differs from the staging tree";
    struct stat a{};
    ASSERT_EQ(::lstat((out / "etc" / "secret.key").c_str(), &a), 0) << label;
    EXPECT_EQ(a.st_mode & 07777u, 0600u) << label;
    EXPECT_EQ(a.st_mtime, 1700000012) << label;
}

class ExtMkfs : public ::testing::TestWithParam<Variant> {};

TEST_P(ExtMkfs, RoundTripAndHistory) {
    const Variant v = GetParam();
    if (!tool_exists("/usr/bin/debugfs") || !tool_exists(("/usr/bin/" + v.mkfs).c_str()))
        GTEST_SKIP() << v.mkfs << " or debugfs not installed";
    TempDir tmp;
    const std::vector<Spec> spec = make_spec();
    const stdfs::path stg = tmp.path() / "stage";
    stage(stg, spec);
    const stdfs::path img = tmp.path() / (v.name + ".img");
    ASSERT_TRUE(build_image(v, img, stg, spec, "64M")) << v.name;
    const std::string label = v.name;

    std::shared_ptr<MappedFile> mf;
    ASSERT_TRUE(MappedFile::open(img.string(), mf).ok);
    const Span span = Span::whole(mf);
    {
        ExtReader r;
        ASSERT_TRUE(r.open(span).ok) << label;
        const FilesystemInfo fi = r.info();
        EXPECT_EQ(fi.label, "omnitrace") << label;
        EXPECT_EQ(fi.block_size, v.name == "ext2" ? 1024u : 4096u) << label;
        const std::string expect_fmt =
            v.name == "ext2" ? "ext2" : (v.name == "ext3" ? "ext3" : "ext4");
        EXPECT_EQ(fi.format, expect_fmt) << label;
        EXPECT_EQ(r.format(), expect_fmt) << label;
        EXPECT_EQ(fi.attrs.at("has_journal"), v.name == "ext2" ? "false" : "true") << label;
        if (v.name == "ext4") {
            EXPECT_EQ(fi.attrs.at("csum_type"), "crc32c") << label;
            EXPECT_NE(fi.attrs.at("features").find("64bit"), std::string::npos) << label;
            EXPECT_NE(fi.attrs.at("features").find("flex_bg"), std::string::npos) << label;
        }
        if (v.name == "ext4-nocsum") {
            EXPECT_NE(fi.attrs.at("csum_type"), "crc32c") << label;
        }
        EXPECT_EQ(fi.attrs.at("state"), "clean") << label;
        EXPECT_EQ(fi.attrs.at("uuid").size(), 36u) << label;
    }
    const Walked w = walk_listing(span, true);
    compare_listing(spec, w, label, v.inline_data);
    if (v.name != "ext2") {
        EXPECT_EQ(w.by_path.at("etc/passwd").meta.mtime_nsec.value_or(0), kNsec) << label;
        EXPECT_EQ(w.by_path.at("etc/passwd").meta.crtime.value_or(-1), 1700000010) << label;
    } else {
        EXPECT_FALSE(w.by_path.at("etc/passwd").meta.crtime.has_value()) << label;
    }
    if (v.inline_data) {
        EXPECT_EQ(w.by_path.at("data/small.txt").meta.extra.count("inline"), 1u) << label;
        EXPECT_EQ(w.by_path.at("many/f0001").meta.extra.count("inline"), 1u) << label;
    }
    extract_and_diff(span, stg, tmp.path() / "out", label);

    // ---- history: delete with debugfs, then walk again with history on.
    const std::uint32_t ino_secret = debugfs_inode_of(img, "etc/secret.key");
    const std::uint32_t ino_small = debugfs_inode_of(img, "data/small.txt");
    const std::uint32_t ino_f500 = debugfs_inode_of(img, "many/f0500");
    const std::uint32_t ino_busybox = debugfs_inode_of(img, "bin/busybox");
    const std::uint32_t ino_big = debugfs_inode_of(img, "data/big.bin");
    ASSERT_NE(ino_secret, 0u);
    ASSERT_NE(ino_small, 0u);
    ASSERT_NE(ino_f500, 0u);
    const auto secret_blocks = debugfs_blocks_of(img, "etc/secret.key");
    ASSERT_FALSE(secret_blocks.empty());
    {
        std::ostringstream sc;
        sc << "rm etc/secret.key\n";
        sc << "rm data/small.txt\n";
        sc << "rm many/f0500\n";
        sc << "unlink bin/ash\n";  // the inode stays live as bin/busybox: a rename, not a deletion
        sc << "rm data/big.bin\n";
        // A real kernel unlink clears the extent tree / block map: emulate on big.bin.
        if (v.name == "ext2" || v.name == "ext3") {
            for (int i = 0; i < 12; ++i) sc << "sif <" << ino_big << "> block[" << i << "] 0\n";
            for (const char* f : {"IND", "DIND", "TIND"})
                sc << "sif <" << ino_big << "> block[" << f << "] 0\n";
        } else
            sc << "sif <" << ino_big << "> block[0] 0xF30A\n";  // header with 0 entries
        // Mark secret.key's first block allocated again: its content is not trustworthy.
        sc << "setb " << secret_blocks[0] << "\n";
        const stdfs::path script = tmp.path() / "history.debugfs";
        spit(script, sc.str());
        ASSERT_EQ(run("debugfs -w -f " + sq(script.string()) + " " + sq(img.string()) +
                      " >/dev/null 2>&1"),
                  0);
    }
    std::shared_ptr<MappedFile> mf2;
    ASSERT_TRUE(MappedFile::open(img.string(), mf2).ok);
    WalkOptions hopts;
    hopts.history = true;
    const Walked h = walk_listing(Span::whole(mf2), true, hopts);
    ASSERT_TRUE(h.status.ok) << label << ": " << h.status.error;
    EXPECT_EQ(h.by_path.size(), spec.size() + 1 - 5) << label;
    EXPECT_EQ(h.by_path.count("bin/ash"), 0u) << label;
    EXPECT_EQ(h.by_path.at("bin/busybox").meta.inode, ino_busybox) << label;
    std::map<std::string, EntryResult> hist;
    for (const EntryResult& e : h.history) {
        EXPECT_TRUE(e.meta.deleted) << label << ": " << e.meta.path;
        EXPECT_FALSE(e.meta.superseded) << label << ": " << e.meta.path;
        EXPECT_EQ(e.meta.version, 1u) << label << ": " << e.meta.path;
        hist[e.meta.path] = e;
    }
    EXPECT_EQ(h.result.deleted, h.history.size()) << label;
    EXPECT_EQ(hist.count("bin/ash"), 0u) << label << ": a rename remnant must not be a deletion";
    ASSERT_EQ(hist.count("etc/secret.key"), 1u) << label << "\n"
                                                << join_diags(h.result.diagnostics);
    ASSERT_EQ(hist.count("data/small.txt"), 1u) << label;
    ASSERT_EQ(hist.count("many/f0500"), 1u) << label;
    ASSERT_EQ(hist.count("data/big.bin"), 1u) << label;
    {
        const EntryResult& e = hist.at("etc/secret.key");
        EXPECT_EQ(e.meta.inode, ino_secret) << label;
        EXPECT_EQ(e.meta.size, 1024u) << label;
        EXPECT_EQ(e.meta.mode, 0600u) << label;
        EXPECT_EQ(e.meta.mtime.value_or(0), 1700000012) << label;
        EXPECT_NE(e.meta.extra.count("dtime"), 0u) << label;
        EXPECT_TRUE(e.truncated) << label;  // its block was marked allocated
        EXPECT_NE(e.meta.extra.at("content").find("reused"), std::string::npos) << label;
        EXPECT_TRUE(has_code(h.result.diagnostics, "ext-deleted-blocks-reused")) << label;
    }
    {
        const EntryResult& e = hist.at("data/small.txt");
        EXPECT_EQ(e.meta.inode, ino_small) << label;
        EXPECT_EQ(e.meta.size, 5u) << label;
        EXPECT_EQ(e.digests.sha256, sha256_of(bytes_of("tiny\n"))) << label;
        EXPECT_FALSE(e.truncated) << label;
    }
    {
        const EntryResult& e = hist.at("many/f0500");
        EXPECT_EQ(e.meta.inode, ino_f500) << label;
        EXPECT_EQ(e.digests.sha256, sha256_of(bytes_of("f0500\n"))) << label;
        EXPECT_EQ(e.meta.extra.at("content"), "recovered from unallocated blocks") << label;
    }
    {
        const EntryResult& e = hist.at("data/big.bin");
        EXPECT_EQ(e.meta.inode, ino_big) << label;
        EXPECT_EQ(e.meta.size, 3u * 1024u * 1024u) << label;  // recorded size survives
        EXPECT_EQ(e.meta.mtime.value_or(0), 1700000020) << label;
        EXPECT_EQ(e.digests.bytes, 0u) << label;
        EXPECT_TRUE(e.truncated) << label;
        EXPECT_EQ(e.meta.extra.at("content"), v.name == "ext2" || v.name == "ext3"
                                                  ? "unavailable: block map cleared"
                                                  : "unavailable: extents cleared")
            << label;
        EXPECT_TRUE(has_code(h.result.diagnostics, "ext-deleted-no-blocks")) << label;
    }
    // Extract with history into a DiskSink: versions land under .omnitrace-versions.
    {
        ExtReader r;
        ASSERT_TRUE(r.open(Span::whole(mf2)).ok);
        std::unique_ptr<DiskSink> sink;
        const stdfs::path out = tmp.path() / "out-history";
        ASSERT_TRUE(DiskSink::open(out.string(), {}, sink).ok);
        WalkResult res;
        ASSERT_TRUE(r.walk(*sink, hopts, res).ok);
        EXPECT_EQ(slurp(out / ".omnitrace-versions" / "data" / "small.txt" / "v1"),
                  bytes_of("tiny\n"))
            << label;
        EXPECT_FALSE(stdfs::exists(out / "data" / "small.txt")) << label;
    }
    // The mkfs image must survive truncation and seeded flips (history on).
    {
        const std::vector<std::uint8_t> bytes = slurp(img);
        for (std::size_t cut = 0; cut < bytes.size();
             cut += std::max<std::size_t>(1, bytes.size() / 23)) {
            std::vector<std::uint8_t> t(bytes.begin(),
                                        bytes.begin() + static_cast<std::ptrdiff_t>(cut));
            survive(std::move(t));
        }
        std::uint64_t x = 0xD1B54A32D192ED03ull ^ bytes.size();
        for (int iter = 0; iter < 12; ++iter) {
            std::vector<std::uint8_t> f = bytes;
            // Flips concentrated in the first 4 MiB, where every metadata block of
            // a 64 MiB image lives (the rest is data and unused blocks).
            for (int k = 0; k < 16; ++k) {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                f[static_cast<std::size_t>((x * 0x2545F4914F6CDD1Dull) % (4u << 20))] ^=
                    static_cast<std::uint8_t>(x);
            }
            survive(std::move(f));
        }
    }
}

INSTANTIATE_TEST_SUITE_P(Variants, ExtMkfs, ::testing::ValuesIn(kVariants),
                         [](const ::testing::TestParamInfo<Variant>& i) {
                             std::string n = i.param.name;
                             std::replace(n.begin(), n.end(), '-', '_');
                             return n;
                         });

TEST(ExtMkfs, MetadataCsumMismatchIsReportedNotRefused) {
    if (!tool_exists("/usr/bin/debugfs") || !tool_exists("/usr/bin/mkfs.ext4"))
        GTEST_SKIP() << "mkfs.ext4 or debugfs not installed";
    TempDir tmp;
    const stdfs::path img = tmp.path() / "csum.img";
    ASSERT_EQ(run("mkfs.ext4 -q -F -b 4096 -O metadata_csum -E lazy_itable_init=0 " +
                  sq(img.string()) + " 16M >/dev/null 2>&1"),
              0);
    const stdfs::path host = tmp.path() / "a.txt";
    spit(host, std::string("checksummed\n"));
    ASSERT_EQ(run("debugfs -w -R " + sq("write " + host.string() + " a.txt") + " " +
                  sq(img.string()) + " >/dev/null 2>&1"),
              0);
    std::vector<std::uint8_t> bytes = slurp(img);
    {
        const Walked w = walk_listing(span_of(bytes), true);
        ASSERT_TRUE(w.status.ok);
        EXPECT_FALSE(has_code(w.result.diagnostics, "ext-inode-csum-mismatch"))
            << join_diags(w.result.diagnostics);
        EXPECT_FALSE(has_code(w.result.diagnostics, "ext-gdt-csum-mismatch"));
        EXPECT_FALSE(has_code(w.result.diagnostics, "ext-superblock-bad"));
        EXPECT_EQ(w.by_path.count("a.txt"), 1u);
    }
    // Flip a byte in the superblock's volume name, a descriptor's reserved
    // area and the root inode's atime: every checksum layer must notice.
    bytes[1024 + 0x78] ^= 0x01;
    const std::uint64_t gdt = 4096;
    bytes[gdt + 0x3C] ^= 0x01;
    const std::uint32_t itable = static_cast<std::uint32_t>(bytes[gdt + 8]) |
                                 (static_cast<std::uint32_t>(bytes[gdt + 9]) << 8) |
                                 (static_cast<std::uint32_t>(bytes[gdt + 10]) << 16) |
                                 (static_cast<std::uint32_t>(bytes[gdt + 11]) << 24);
    bytes[itable * 4096ull + 256 + 0x08] ^= 0x01;  // inode 2, i_atime
    const Walked w = walk_listing(span_of(bytes), true);
    ASSERT_TRUE(w.status.ok) << w.status.error;
    EXPECT_TRUE(has_code(w.result.diagnostics, "ext-superblock-bad"))
        << join_diags(w.result.diagnostics);
    EXPECT_TRUE(has_code(w.result.diagnostics, "ext-gdt-csum-mismatch"));
    EXPECT_TRUE(has_code(w.result.diagnostics, "ext-inode-csum-mismatch"));
    EXPECT_EQ(w.by_path.count("a.txt"), 1u);  // still walked
}

#endif  // !_WIN32

// ------------------------------------------------------------------ fixtures

// Crude parser for a fixture's expected.yaml: the flat `tree:` list and the
// `superseded:` / `deleted:` / `deleted_names:` lists under `history:`.
struct Expected {
    std::map<std::string, std::map<std::string, std::string>> tree;
    std::vector<std::map<std::string, std::string>> superseded, deleted, deleted_names;
    std::map<std::string, std::string> attrs;
};

Expected read_expected(const stdfs::path& yaml) {
    Expected out;
    std::ifstream in(yaml);
    std::string line, section, sub;
    std::map<std::string, std::string>* cur = nullptr;
    auto unquote = [](std::string v) {
        if (v.size() >= 2 && v.front() == '\'' && v.back() == '\'') v = v.substr(1, v.size() - 2);
        return v;
    };
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        if (line[0] != ' ' && line[0] != '-') {
            section = line.substr(0, line.find(':'));
            sub.clear();
            cur = nullptr;
            continue;
        }
        const auto indent = line.find_first_not_of(' ');
        const std::string body = line.substr(indent);
        if (section == "tree") {
            if (body.rfind("- path: ", 0) == 0) {
                const std::string p = unquote(body.substr(8));
                cur = &out.tree[p];
                (*cur)["path"] = p;
            } else if (cur) {
                const auto c = body.find(": ");
                if (c != std::string::npos) (*cur)[body.substr(0, c)] = unquote(body.substr(c + 2));
            }
        } else if (section == "attrs") {
            const auto c = body.find(": ");
            if (c != std::string::npos) out.attrs[body.substr(0, c)] = unquote(body.substr(c + 2));
        } else if (section == "history") {
            if (indent == 2 && body.rfind("- ", 0) != 0) {
                sub = body.substr(0, body.find(':'));
                cur = nullptr;
                continue;
            }
            std::vector<std::map<std::string, std::string>>* list = nullptr;
            if (sub == "superseded") list = &out.superseded;
            if (sub == "deleted") list = &out.deleted;
            if (sub == "deleted_names") list = &out.deleted_names;
            if (!list) continue;
            std::string kv = body;
            if (body.rfind("- ", 0) == 0) {
                list->push_back({});
                cur = &list->back();
                kv = body.substr(2);
            }
            const auto c = kv.find(": ");
            if (cur && c != std::string::npos) (*cur)[kv.substr(0, c)] = unquote(kv.substr(c + 2));
        }
    }
    return out;
}

TEST(ExtFixture, Ext4MatchesExpectedYaml) {
    const stdfs::path dir = stdfs::path(OMNITRACE_TEST_DATA_DIR) / "out";
    const stdfs::path img = dir / "ext4.img";
    const stdfs::path yaml = dir / "ext4.expected.yaml";
    if (!stdfs::exists(img) || !stdfs::exists(yaml)) GTEST_SKIP() << "fixture ext4 not built";
    const Expected expected = read_expected(yaml);
    ASSERT_FALSE(expected.tree.empty());

    std::shared_ptr<MappedFile> mf;
    ASSERT_TRUE(MappedFile::open(img.string(), mf).ok);
    {
        ExtReader r;
        ASSERT_TRUE(r.open(Span::whole(mf)).ok);
        const FilesystemInfo fi = r.info();
        EXPECT_EQ(fi.attrs.at("block_size"), expected.attrs.at("block_size"));
        EXPECT_EQ(fi.attrs.at("uuid"), expected.attrs.at("uuid"));
        EXPECT_EQ(fi.label, expected.attrs.at("label"));
        EXPECT_EQ(fi.attrs.at("has_journal"), expected.attrs.at("journal"));
    }
    WalkOptions opts;
    opts.history = true;
    const Walked w = walk_listing(Span::whole(mf), true, opts);
    ASSERT_TRUE(w.status.ok) << w.status.error << "\n" << join_diags(w.result.diagnostics);
    for (const Diagnostic& d : w.result.diagnostics)
        EXPECT_NE(d.severity, Severity::Warning) << d.code << ": " << d.message;
    // The tree section omits lost+found, which mkfs creates and a mount shows.
    EXPECT_EQ(w.by_path.size(), expected.tree.size() + 1);
    EXPECT_EQ(w.by_path.count("lost+found"), 1u);
    for (const auto& [path, fields] : expected.tree) {
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
        EXPECT_FALSE(it->second.truncated) << path;
    }
    // History. The fixture was populated with debugfs, so freed inodes keep
    // their extent trees (content recoverable) and the slack entries keep the
    // names. What the on-disk state can say:
    //  * deleted.txt: slack name -> freed inode: deleted, content recovered.
    //  * config.txt v1 (inode 26): its entry was overwritten by the later
    //    link, so no name survives: lost+found/#26, deleted, content recovered.
    //  * config.txt v2 (inode 31): named only by the slack entry ".config.v2":
    //    deleted under that name, content recovered.
    //  * ".config.v3" names the live inode 32 (renamed to config.txt): dropped.
    // expected.yaml lists exactly those three under history.deleted (v1 with
    // recovered_as = lost+found/#<inode>) and nothing under superseded.
    std::map<std::string, EntryResult> hist;
    for (const EntryResult& e : w.history) hist[e.meta.path] = e;
    ASSERT_EQ(expected.deleted.size(), 3u);
    ASSERT_EQ(expected.superseded.size(), 0u);
    for (const auto& d : expected.deleted) {
        const std::string path = d.count("recovered_as") ? d.at("recovered_as") : d.at("path");
        ASSERT_EQ(hist.count(path), 1u) << path << "\n" << join_diags(w.result.diagnostics);
        const EntryResult& e = hist.at(path);
        EXPECT_TRUE(e.meta.deleted) << path;
        EXPECT_FALSE(e.meta.superseded) << path;
        EXPECT_EQ(e.meta.inode, std::stoull(d.at("inode"))) << path;
        EXPECT_EQ(e.meta.size, std::stoull(d.at("size"))) << path;
        EXPECT_EQ(e.digests.sha256, d.at("sha256")) << path;
        EXPECT_EQ(e.meta.mtime.value_or(-1), std::stoll(d.at("mtime"))) << path;
        EXPECT_EQ(e.meta.extra.at("dtime"), d.at("dtime")) << path;
        EXPECT_EQ(e.meta.version, 1u) << path;
    }
    EXPECT_EQ(hist.count("history/.config.v3"), 0u);
    EXPECT_EQ(hist.size(), 3u) << join_diags(w.result.diagnostics);
    EXPECT_EQ(w.result.deleted, 3u);
    EXPECT_EQ(w.result.superseded, 0u);

    // The fixture, truncated and flipped, must not crash.
    const std::vector<std::uint8_t> bytes = slurp(img);
    for (std::size_t cut = 0; cut < bytes.size(); cut += bytes.size() / 29)
        survive(std::vector<std::uint8_t>(bytes.begin(),
                                          bytes.begin() + static_cast<std::ptrdiff_t>(cut)));
}

// ------------------------------------------------------------------ corpus vs debugfs rdump

#ifndef _WIN32

struct Corpus {
    std::string name, file;
    std::uint64_t offset, size;
};

void corpus_vs_debugfs(const Corpus& c) {
    if (!stdfs::exists(c.file)) GTEST_SKIP() << "corpus file missing: " << c.file;
    if (!tool_exists("/usr/bin/debugfs")) GTEST_SKIP() << "debugfs not installed";
    std::shared_ptr<MappedFile> mf;
    ASSERT_TRUE(MappedFile::open(c.file, mf).ok);
    const Span span = Span::whole(mf).sub(c.offset, c.size);
    TempDir tmp;
    const stdfs::path ours = tmp.path() / "ours";
    const stdfs::path ref = tmp.path() / "ref";
    const stdfs::path slice = tmp.path() / "slice.img";
    WalkResult res;
    std::vector<std::string> refused;
    {
        ExtReader r;
        ASSERT_TRUE(r.open(span).ok);
        std::unique_ptr<DiskSink> sink;
        ASSERT_TRUE(DiskSink::open(ours.string(), {}, sink).ok);
        ASSERT_TRUE(r.walk(*sink, {}, res).ok);
        for (const Diagnostic& d : res.diagnostics) {
            // A name every Sink refuses (Windows reserved device names such as
            // "Con") is reported per entry and expected here.
            if (d.code == "ext-sink-error" &&
                d.message.find("sink-unsafe-path") != std::string::npos) {
                refused.push_back(d.message.substr(1, d.message.find('\'', 1) - 1));
                continue;
            }
            EXPECT_NE(d.severity, Severity::Warning) << d.code << ": " << d.message;
        }
        EXPECT_GT(res.entries, 3u);
        EXPECT_FALSE(res.truncated);
    }
    // Reference: debugfs rdump over the same byte slice.
    ASSERT_EQ(run("dd if=" + sq(c.file) + " of=" + sq(slice.string()) +
                  " bs=1M iflag=skip_bytes,count_bytes skip=" + std::to_string(c.offset) +
                  " count=" + std::to_string(c.size) + " status=none"),
              0);
    stdfs::create_directories(ref);
    ASSERT_EQ(run("debugfs -R " + sq("rdump / " + ref.string()) + " " + sq(slice.string()) +
                  " >/dev/null 2>&1"),
              0);
    // Modes and mtimes of every regular file (before the chmod that lets diff
    // read mode-0 files); uid/gid/size against debugfs stat for a sample.
    int sampled = 0;
    int split_names = 0;  // regular files present in our tree but absent from the reference
    for (const EntryResult& e : res.entries_out) {
        if (e.meta.kind != EntryKind::Regular) continue;
        if (std::find(refused.begin(), refused.end(), e.meta.path) != refused.end()) continue;
        struct stat a{}, b{};
        ASSERT_EQ(::lstat((ours / e.meta.path).c_str(), &a), 0) << e.meta.path;
        if (::lstat((ref / e.meta.path).c_str(), &b) != 0) {
            ++split_names;
            continue;
        }
        // DiskSink applies permission bits only (never setuid/setgid/sticky).
        EXPECT_EQ(a.st_mode & 0777u, b.st_mode & 0777u) << e.meta.path;
        EXPECT_EQ(a.st_mode & 0777u, e.meta.mode & 0777u) << e.meta.path;
        EXPECT_EQ(a.st_mtime, b.st_mtime) << e.meta.path;
        EXPECT_EQ(a.st_mtime, e.meta.mtime.value_or(-1)) << e.meta.path;
        if (sampled < 25 && (res.entries_out.size() < 50 || (e.meta.inode % 37) == 0)) {
            ++sampled;
            const std::string out = capture("debugfs -R " + sq("stat " + dq("/" + e.meta.path)) +
                                            " " + sq(slice.string()) + " 2>/dev/null");
            const auto u = out.find("User:");
            const auto g = out.find("Group:");
            const auto sz = out.find("Size:");
            ASSERT_NE(u, std::string::npos) << e.meta.path;
            EXPECT_EQ(std::stoul(out.substr(u + 5)), e.meta.uid) << e.meta.path;
            EXPECT_EQ(std::stoul(out.substr(g + 6)), e.meta.gid) << e.meta.path;
            EXPECT_EQ(std::stoull(out.substr(sz + 5)), e.meta.size) << e.meta.path;
        }
    }
    // debugfs creates fifos and sockets; DiskSink records them without creating them.
    run("find " + sq(ref.string()) + " \\( -type p -o -type s \\) -delete");
    run("chmod -R u+rX " + sq(ours.string()) + " " + sq(ref.string()));
    // On POSIX every name the filesystem holds is written verbatim (a
    // backslash, a Windows device name such as "Con"), so the trees must be
    // identical; nothing is refused or split.
    EXPECT_TRUE(refused.empty()) << c.name << ": " << refused.size() << " refused names";
    const std::string diff = capture("diff -r --no-dereference -q " + sq(ours.string()) + " " +
                                     sq(ref.string()) + " 2>&1");
    std::istringstream lines(diff);
    std::string line;
    while (std::getline(lines, line)) EXPECT_TRUE(false) << c.name << ": " << line;
    EXPECT_GT(sampled, 0);
    EXPECT_EQ(split_names, 0) << c.name;
}

TEST(ExtCorpus, EmmcRootfsMatchesDebugfs) {
    corpus_vs_debugfs({"full-emmc", "/home/wrongbaud/projects/omnitrace/firmware/full-emmc.bin",
                       0x3700000ull, 512ull << 20});
}

TEST(ExtCorpus, UserDataHomeMatchesDebugfs) {
    corpus_vs_debugfs(
        {"userdata-p7",
         "/home/wrongbaud/projects/omnitrace-v2/corpus/auto-ivi-example/flash/UserData.BIN",
         1435517952ull, 52428800ull});
}

#endif  // !_WIN32

}  // namespace
}  // namespace omnitrace::fs
