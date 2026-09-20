// qnx6_test.cpp — Qnx6Reader.
//
// Coverage:
//   1. Images assembled block by block in the test (both byte orders) by a
//      small mkqnx6fs-alike: two superblocks with correct CRCs, an inode
//      table behind one and two levels of indirection, a root directory, a
//      subdirectory, a long file name through the longfile table, a symlink,
//      a device, a fifo, a three-block file with a hole, and an older second
//      superblock describing a snapshot in which one file had different
//      content, another had a different mode and a third still existed.
//   2. History: superseded and deleted entries from the previous snapshot,
//      deleted inode-table records (data intact, data reused), the
//      per-entry version cap, DiskSink placement.
//   3. Hostile images: truncation, seeded byte flips, 7 levels, a block
//      pointer past the image, a zero-length dirent, a long-name index past
//      the table, a self-referencing directory, a huge num_blocks, two bad
//      superblock CRCs, the node/file/byte limits. Nothing may crash; run
//      this binary under ASan+UBSan.
//   4. Corpus slices (skipped when absent) compared entry by entry, hash by
//      hash, against a qnxmount FUSE mount of the same bytes.
#include "../../../src/filesystems/qnx6/Qnx6Reader.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <span>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "omnitrace/core/Hash.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/filesystems/Filesystem.h"

#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace omnitrace::fs {
namespace {

namespace stdfs = std::filesystem;
using Bytes = std::vector<std::uint8_t>;

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
        path_ = base / ("omnitrace-qnx6-" + std::to_string(pid) + "-" + std::to_string(counter++));
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

Bytes bytes_of(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

std::string sha256_of(const Bytes& d) {
    return Hasher::of(d).sha256;
}

Span span_of(Bytes bytes, const std::string& label = "img") {
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

bool tool_exists(const std::string& path) {
#ifdef _WIN32
    (void)path;
    return false;
#else
    return ::access(path.c_str(), X_OK) == 0;
#endif
}

// Superblock CRC written bit by bit, independently of the reader's table:
// polynomial 0x04C11DB7, MSB first, seed 0, no final xor.
std::uint32_t sb_crc(const std::uint8_t* p, std::size_t n) {
    std::uint32_t crc = 0;
    for (std::size_t i = 0; i < n; ++i) {
        crc ^= static_cast<std::uint32_t>(p[i]) << 24;
        for (int k = 0; k < 8; ++k)
            crc = (crc & 0x80000000u) ? (crc << 1) ^ 0x04C11DB7u : (crc << 1);
    }
    return crc;
}

// Long-name checksum as fs-qnx6 stores it in the directory entry.
std::uint32_t lf_checksum(const std::string& name) {
    std::uint32_t crc = 0;
    for (const char c : name) {
        const std::uint32_t v =
            static_cast<std::uint32_t>(static_cast<std::int32_t>(static_cast<signed char>(c)));
        crc = ((crc >> 1) + v) ^ ((crc & 1u) ? 0x80000000u : 0u);
    }
    return crc;
}

constexpr std::uint32_t kHole = 0xFFFFFFFFu;
constexpr std::uint16_t kIfReg = 0100000, kIfDir = 0040000, kIfLnk = 0120000, kIfChr = 0020000,
                        kIfFifo = 0010000;

// ------------------------------------------------------------------ image builder

struct BInode {
    std::uint16_t mode = 0, ext_mode = 0;
    std::uint32_t uid = 0, gid = 0;
    std::uint32_t ftime = 1700000000u, mtime = 1700000000u, atime = 1700000000u,
                  ctime = 1700000000u;
    std::uint8_t status = 3, levels = 0;
    std::uint64_t size = 0;
    std::array<std::uint32_t, 16> ptr{};
    BInode() { ptr.fill(kHole); }
};

struct BTree {
    std::uint64_t size = 0;
    std::array<std::uint32_t, 16> ptr{};
    std::uint8_t levels = 0;
    std::vector<std::uint32_t> data_blocks;  // leaf blocks in file order (kHole = hole)
    BTree() { ptr.fill(kHole); }
};

struct DirEnt {
    DirEnt(std::uint32_t i, std::string n, std::optional<std::uint32_t> li = std::nullopt)
        : ino(i), name(std::move(n)), long_index(li) {}
    std::uint32_t ino = 0;
    std::string name;
    std::optional<std::uint32_t> long_index;  // set for names longer than 27 bytes
};

// A snapshot: one inode table, one longfile table, one bitmap, one serial.
struct Snapshot {
    std::uint64_t serial = 0;
    std::vector<BInode> inodes;  // index ino-1
    std::vector<std::string> longnames;
    int itab_levels = -1;  // forced indirection for the inode table
    // filled by write_superblock:
    BTree itab, longfile, bitmap;
    std::uint64_t sb_off = 0;
};

class Builder {
   public:
    Builder(Endian e, std::uint32_t bs, std::uint32_t nb) : e_(e), bs_(bs), nb_(nb) {
        data_start_ = round_up(0x3000, bs);
        tail_ = round_up(0x1000, bs);
        img_.assign(static_cast<std::size_t>(data_start_ + std::uint64_t{nb} * bs + tail_), 0);
        const std::uint64_t bits = data_start_ / bs + nb + tail_ / bs;
        bitmap_.assign(static_cast<std::size_t>((bits + 7) / 8), 0);
        for (std::uint64_t b = 0; b < data_start_ / bs; ++b) set_bit(b);
        for (std::uint64_t b = data_start_ / bs + nb; b < bits; ++b) set_bit(b);
        // boot block: magic, offset, sblk0 = 16, sblk1 = second superblock sector
        img_[0] = 0xEB;
        img_[1] = 0x10;
        img_[2] = 0x90;
        img_[3] = 0x00;
        put32_le(8, 16);
        put32_le(12, static_cast<std::uint32_t>((data_start_ + std::uint64_t{nb} * bs) / 512));
    }

    static std::uint64_t round_up(std::uint64_t v, std::uint64_t to) {
        return (v + to - 1) / to * to;
    }
    std::uint64_t data_start() const { return data_start_; }
    std::uint32_t blocksize() const { return bs_; }
    std::uint64_t second_sb_off() const { return data_start_ + std::uint64_t{nb_} * bs_; }
    std::uint64_t block_off(std::uint32_t b) const { return data_start_ + std::uint64_t{b} * bs_; }
    Bytes& image() { return img_; }

    std::uint32_t alloc() {
        const std::uint32_t b = next_++;
        if (b >= nb_) throw std::runtime_error("image full");
        set_bit(data_start_ / bs_ + b);
        return b;
    }
    void free_block(std::uint32_t b) {
        const std::uint64_t bit = data_start_ / bs_ + b;
        bitmap_[static_cast<std::size_t>(bit / 8)] &= static_cast<std::uint8_t>(~(1u << (bit % 8)));
    }
    bool bit_set(std::uint32_t b) const {
        const std::uint64_t bit = data_start_ / bs_ + b;
        return (bitmap_[static_cast<std::size_t>(bit / 8)] >> (bit % 8)) & 1u;
    }

    void write_block(std::uint32_t b, const Bytes& data) {
        const std::size_t off = static_cast<std::size_t>(block_off(b));
        std::fill(img_.begin() + static_cast<std::ptrdiff_t>(off),
                  img_.begin() + static_cast<std::ptrdiff_t>(off + bs_), 0);
        std::copy(
            data.begin(),
            data.begin() + static_cast<std::ptrdiff_t>(std::min<std::size_t>(data.size(), bs_)),
            img_.begin() + static_cast<std::ptrdiff_t>(off));
    }

    // Data blocks (nullopt = hole) as a pointer tree with at least
    // `force_levels` levels of indirection.
    BTree put_blocks(const std::vector<std::optional<Bytes>>& blocks, std::uint64_t size,
                     int force_levels = -1) {
        BTree t;
        t.size = size;
        for (const auto& b : blocks) {
            if (!b) {
                t.data_blocks.push_back(kHole);
                continue;
            }
            const std::uint32_t n = alloc();
            write_block(n, *b);
            t.data_blocks.push_back(n);
        }
        std::vector<std::uint32_t> level = t.data_blocks;
        int levels = 0;
        const std::size_t per = bs_ / 4;
        while (level.size() > 16 || levels < force_levels) {
            std::vector<std::uint32_t> next;
            for (std::size_t i = 0; i < level.size(); i += per) {
                Bytes ind(bs_, 0xFF);
                for (std::size_t k = 0; k < per && i + k < level.size(); ++k)
                    put32(ind, k * 4, level[i + k]);
                const std::uint32_t n = alloc();
                write_block(n, ind);
                next.push_back(n);
            }
            if (next.empty()) {
                Bytes ind(bs_, 0xFF);
                const std::uint32_t n = alloc();
                write_block(n, ind);
                next.push_back(n);
            }
            level = next;
            ++levels;
        }
        for (std::size_t i = 0; i < level.size() && i < 16; ++i) t.ptr[i] = level[i];
        t.levels = static_cast<std::uint8_t>(levels);
        return t;
    }
    BTree put_data(const Bytes& data, int force_levels = -1) {
        std::vector<std::optional<Bytes>> blocks;
        for (std::size_t i = 0; i < data.size(); i += bs_)
            blocks.emplace_back(Bytes(
                data.begin() + static_cast<std::ptrdiff_t>(i),
                data.begin() +
                    static_cast<std::ptrdiff_t>(std::min<std::size_t>(i + bs_, data.size()))));
        return put_blocks(blocks, data.size(), force_levels);
    }

    static void assign(BInode& in, const BTree& t) {
        in.size = t.size;
        in.ptr = t.ptr;
        in.levels = t.levels;
    }

    Bytes dir_bytes(const std::vector<DirEnt>& entries) const {
        Bytes out;
        for (const DirEnt& d : entries) {
            Bytes e(32, 0);
            put32(e, 0, d.ino);
            if (d.long_index) {
                e[4] = 0xFF;
                put32(e, 8, *d.long_index);
                put32(e, 12, lf_checksum(d.name));
            } else {
                e[4] = static_cast<std::uint8_t>(d.name.size());
                std::copy(d.name.begin(), d.name.end(), e.begin() + 5);
            }
            out.insert(out.end(), e.begin(), e.end());
        }
        return out;
    }

    // Serialize the snapshot's tables and write its superblock at `off`.
    void write_superblock(std::uint64_t off, Snapshot& s) {
        Bytes itab;
        for (const BInode& in : s.inodes) {
            Bytes r(128, 0);
            put64(r, 0, in.size);
            put32(r, 8, in.uid);
            put32(r, 12, in.gid);
            put32(r, 16, in.ftime);
            put32(r, 20, in.mtime);
            put32(r, 24, in.atime);
            put32(r, 28, in.ctime);
            put16(r, 32, in.mode);
            put16(r, 34, in.ext_mode);
            for (std::size_t i = 0; i < 16; ++i) put32(r, 36 + 4 * i, in.ptr[i]);
            r[100] = in.levels;
            r[101] = in.status;
            itab.insert(itab.end(), r.begin(), r.end());
        }
        s.itab = put_data(itab, s.itab_levels);
        Bytes lf;
        for (const std::string& n : s.longnames) {
            Bytes slot(bs_, 0);
            put16(slot, 0, static_cast<std::uint16_t>(n.size()));
            std::copy(n.begin(), n.end(), slot.begin() + 2);
            lf.insert(lf.end(), slot.begin(), slot.end());
        }
        s.longfile = put_data(lf);
        // The bitmap's own blocks are allocated before its bytes are copied.
        const std::size_t nbm = (bitmap_.size() + bs_ - 1) / bs_;
        std::vector<std::uint32_t> bm_blocks;
        for (std::size_t i = 0; i < nbm; ++i) bm_blocks.push_back(alloc());
        s.bitmap = BTree{};
        s.bitmap.size = bitmap_.size();
        for (std::size_t i = 0; i < nbm; ++i) {
            Bytes chunk(bitmap_.begin() + static_cast<std::ptrdiff_t>(i * bs_),
                        bitmap_.begin() + static_cast<std::ptrdiff_t>(std::min<std::size_t>(
                                              (i + 1) * bs_, bitmap_.size())));
            write_block(bm_blocks[i], chunk);
            s.bitmap.ptr[i] = bm_blocks[i];
            s.bitmap.data_blocks.push_back(bm_blocks[i]);
        }

        Bytes sb(512, 0);
        put32(sb, 0, 0x68191122u);
        put64(sb, 8, s.serial);
        put32(sb, 16, 1600000000u);  // ctime
        put32(sb, 20, 1600000001u);  // atime
        put32(sb, 24, 0x302);        // flags
        put16(sb, 28, 4);
        put16(sb, 30, 3);
        for (std::size_t i = 0; i < 16; ++i) sb[32 + i] = static_cast<std::uint8_t>(0xA0 + i);
        put32(sb, 48, bs_);
        put32(sb, 52, static_cast<std::uint32_t>(s.inodes.size()));
        put32(sb, 56, 0);
        put32(sb, 60, nb_);
        put32(sb, 64, nb_ - next_);
        put32(sb, 68, 1);
        auto root_node = [&](std::size_t at, const BTree& t) {
            put64(sb, at, t.size);
            for (std::size_t i = 0; i < 16; ++i) put32(sb, at + 8 + 4 * i, t.ptr[i]);
            sb[at + 72] = t.levels;
            sb[at + 73] = 1;
        };
        root_node(72, s.itab);
        root_node(152, s.bitmap);
        root_node(232, s.longfile);
        BTree none;
        root_node(312, none);
        root_node(392, none);
        put32(sb, 4, sb_crc(sb.data() + 8, 504));
        std::copy(sb.begin(), sb.end(), img_.begin() + static_cast<std::ptrdiff_t>(off));
        s.sb_off = off;
    }

    // Recompute the CRC of the superblock at `off` after a patch.
    void fix_crc(std::uint64_t off) {
        put32(img_, static_cast<std::size_t>(off + 4), sb_crc(img_.data() + off + 8, 504));
    }

    // Byte offset of inode `ino`'s record in snapshot `s`.
    std::uint64_t inode_off(const Snapshot& s, std::uint32_t ino) const {
        const std::uint64_t byte = std::uint64_t{ino - 1} * 128;
        return block_off(s.itab.data_blocks[static_cast<std::size_t>(byte / bs_)]) + byte % bs_;
    }

    void put16(Bytes& b, std::size_t off, std::uint16_t v) const {
        if (e_ == Endian::Little) {
            b[off] = static_cast<std::uint8_t>(v & 0xFF);
            b[off + 1] = static_cast<std::uint8_t>(v >> 8);
        } else {
            b[off] = static_cast<std::uint8_t>(v >> 8);
            b[off + 1] = static_cast<std::uint8_t>(v & 0xFF);
        }
    }
    void put32(Bytes& b, std::size_t off, std::uint32_t v) const {
        for (std::size_t i = 0; i < 4; ++i) {
            const unsigned shift = e_ == Endian::Little ? 8u * static_cast<unsigned>(i)
                                                        : 8u * static_cast<unsigned>(3 - i);
            b[off + i] = static_cast<std::uint8_t>((v >> shift) & 0xFF);
        }
    }
    void put64(Bytes& b, std::size_t off, std::uint64_t v) const {
        for (std::size_t i = 0; i < 8; ++i) {
            const unsigned shift = e_ == Endian::Little ? 8u * static_cast<unsigned>(i)
                                                        : 8u * static_cast<unsigned>(7 - i);
            b[off + i] = static_cast<std::uint8_t>((v >> shift) & 0xFF);
        }
    }

   private:
    void put32_le(std::size_t off, std::uint32_t v) {
        for (std::size_t i = 0; i < 4; ++i)
            img_[off + i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF);
    }
    void set_bit(std::uint64_t bit) {
        bitmap_[static_cast<std::size_t>(bit / 8)] |= static_cast<std::uint8_t>(1u << (bit % 8));
    }

    Endian e_;
    std::uint32_t bs_, nb_;
    std::uint64_t data_start_ = 0, tail_ = 0;
    std::uint32_t next_ = 0;
    Bytes img_;
    Bytes bitmap_;
};

// The test image. Inodes: 1 root, 2 hello.txt, 3 sub, 4 the long-named
// file, 5 link, 6 big.bin (hole in the middle), 7 gone.txt (only in the
// previous snapshot; its record survives in the current table with status
// 2), 8 sub/nested.txt (mode changed between snapshots), 9 tty, 10 new.txt
// (current only), 11 deep.bin (two levels of indirection), 12 an unnamed
// deleted record whose block is still free, 13 one whose block was reused,
// 14 sub/fifo. Snapshot 5 is the primary superblock, snapshot 6 (current)
// the second one, so the serial rule, not the position, must pick it.
struct TestImage {
    Bytes bytes;
    std::uint64_t sb_old = 0, sb_new = 0;
    std::uint64_t data_start = 0;
    std::uint32_t bs = 0;
    std::uint64_t root_dir_off_new = 0, sub_dir_off_new = 0;
    std::uint64_t hello_inode_off_new = 0, big_inode_off_new = 0, ino13_block_off = 0;
    std::string long_name;
    Bytes big_content, deep_content;
};

const std::string kLongName = "this_is_a_rather_long_file_name_exceeding_27_bytes.txt";

TestImage build_image(Endian e, std::uint32_t bs = 1024, std::uint32_t nb = 400) {
    Builder b(e, bs, nb);
    TestImage t;
    t.bs = bs;
    t.data_start = b.data_start();
    t.long_name = kLongName;

    Snapshot old;
    old.serial = 5;
    old.itab_levels = 2;
    old.inodes.resize(32);
    Snapshot cur;
    cur.serial = 6;
    cur.itab_levels = 1;
    old.longnames = {kLongName};
    cur.longnames = {kLongName};

    auto set = [&](BInode& in, std::uint16_t mode, std::uint32_t when, std::uint32_t uid = 0,
                   std::uint32_t gid = 0) {
        in.mode = mode;
        in.uid = uid;
        in.gid = gid;
        in.ftime = when - 10;
        in.mtime = when;
        in.atime = when + 1;
        in.ctime = when + 2;
    };

    // Old snapshot.
    const BTree hello_v1 = b.put_data(bytes_of("hello v1\n"));
    set(old.inodes[1], kIfReg | 0644, 1700000002u);
    Builder::assign(old.inodes[1], hello_v1);

    const BTree nested = b.put_data(bytes_of("nested\n"));
    set(old.inodes[7], kIfReg | 0644, 1700000008u, 1000, 100);
    Builder::assign(old.inodes[7], nested);

    set(old.inodes[13], kIfFifo | 0600, 1700000014u);

    const BTree sub_dir =
        b.put_data(b.dir_bytes({{3, "."}, {1, ".."}, {8, "nested.txt"}, {14, "fifo"}}));
    set(old.inodes[2], kIfDir | 0750, 1700000003u, 5, 6);
    Builder::assign(old.inodes[2], sub_dir);

    const BTree longf = b.put_data(bytes_of("long\n"));
    set(old.inodes[3], kIfReg | 0640, 1700000004u);
    Builder::assign(old.inodes[3], longf);

    const BTree link = b.put_data(bytes_of("sub/nested.txt"));
    set(old.inodes[4], kIfLnk | 0777, 1700000005u);
    Builder::assign(old.inodes[4], link);

    Bytes blk_a(bs, 0);
    for (std::size_t i = 0; i < blk_a.size(); ++i) blk_a[i] = static_cast<std::uint8_t>(i * 7 + 1);
    Bytes blk_c(100, 0);
    for (std::size_t i = 0; i < blk_c.size(); ++i) blk_c[i] = static_cast<std::uint8_t>(0xC0 + i);
    const BTree big = b.put_blocks({blk_a, std::nullopt, blk_c}, 2 * std::uint64_t{bs} + 100);
    t.big_content = blk_a;
    t.big_content.insert(t.big_content.end(), bs, 0);
    t.big_content.insert(t.big_content.end(), blk_c.begin(), blk_c.end());
    set(old.inodes[5], kIfReg | 0600, 1700000006u);
    Builder::assign(old.inodes[5], big);

    const BTree gone = b.put_data(bytes_of("to be deleted\n"));
    set(old.inodes[6], kIfReg | 0644, 1700000007u);
    Builder::assign(old.inodes[6], gone);

    set(old.inodes[8], kIfChr | 0620, 1700000009u);
    old.inodes[8].ext_mode = 0x0102;

    Bytes deep(bs + 17, 0);
    for (std::size_t i = 0; i < deep.size(); ++i) deep[i] = static_cast<std::uint8_t>(i ^ 0x5A);
    t.deep_content = deep;
    const BTree deep_t = b.put_data(deep, 2);
    set(old.inodes[10], kIfReg | 0444, 1700000011u);
    Builder::assign(old.inodes[10], deep_t);

    const BTree root_old = b.put_data(b.dir_bytes({{1, "."},
                                                   {1, ".."},
                                                   {2, "hello.txt"},
                                                   {3, "sub"},
                                                   {4, kLongName, 0},
                                                   {5, "link"},
                                                   {6, "big.bin"},
                                                   {7, "gone.txt"},
                                                   {9, "tty"},
                                                   {11, "deep.bin"}}));
    set(old.inodes[0], kIfDir | 0755, 1700000001u);
    old.inodes[0].status = 1;
    Builder::assign(old.inodes[0], root_old);
    b.write_superblock(0x2000, old);

    // Current snapshot: copy-on-write from the old one.
    cur.inodes = old.inodes;
    const BTree hello_v2 = b.put_data(bytes_of("hello v2!\n"));
    b.free_block(hello_v1.data_blocks[0]);
    set(cur.inodes[1], kIfReg | 0644, 1700000022u);
    Builder::assign(cur.inodes[1], hello_v2);

    cur.inodes[7].mode = kIfReg | 0600;  // chmod: same content, different metadata
    cur.inodes[7].ctime = 1700000028u;

    cur.inodes[6].status = 2;  // gone.txt unlinked; record kept, block freed
    b.free_block(gone.data_blocks[0]);

    const BTree newf = b.put_data(bytes_of("brand new\n"));
    set(cur.inodes[9], kIfReg | 0644, 1700000030u);
    Builder::assign(cur.inodes[9], newf);

    const BTree orphan = b.put_data(bytes_of("orphan data\n"));
    b.free_block(orphan.data_blocks[0]);
    set(cur.inodes[11], kIfReg | 0644, 1700000012u);
    Builder::assign(cur.inodes[11], orphan);
    cur.inodes[11].status = 2;

    set(cur.inodes[12], kIfReg | 0644, 1700000013u);
    cur.inodes[12].status = 2;
    cur.inodes[12].size = 10;
    cur.inodes[12].ptr[0] = newf.data_blocks[0];  // reused by new.txt
    t.ino13_block_off = b.block_off(newf.data_blocks[0]);

    const BTree root_new = b.put_data(b.dir_bytes({{1, "."},
                                                   {1, ".."},
                                                   {2, "hello.txt"},
                                                   {3, "sub"},
                                                   {4, kLongName, 0},
                                                   {5, "link"},
                                                   {6, "big.bin"},
                                                   {0, ""},
                                                   {9, "tty"},
                                                   {11, "deep.bin"},
                                                   {10, "new.txt"}}));
    b.free_block(root_old.data_blocks[0]);
    set(cur.inodes[0], kIfDir | 0755, 1700000021u);
    cur.inodes[0].status = 1;
    Builder::assign(cur.inodes[0], root_new);
    b.write_superblock(b.second_sb_off(), cur);

    t.sb_old = old.sb_off;
    t.sb_new = cur.sb_off;
    t.root_dir_off_new = b.block_off(root_new.data_blocks[0]);
    t.sub_dir_off_new = b.block_off(sub_dir.data_blocks[0]);
    t.hello_inode_off_new = b.inode_off(cur, 2);
    t.big_inode_off_new = b.inode_off(cur, 6);
    t.bytes = b.image();
    return t;
}

// ------------------------------------------------------------------ walking

struct Walked {
    Status open_status;
    Status status;
    WalkResult result;
    std::map<std::string, EntryResult> live;
    std::vector<EntryResult> history;
    FilesystemInfo info;
};

WalkOptions history_opts() {
    WalkOptions o;
    o.history = true;
    return o;
}

Walked walk_listing(const Span& span, bool hash = true, WalkOptions opts = {}) {
    Walked w;
    Qnx6Reader r;
    w.open_status = r.open(span);
    if (!w.open_status) {
        w.status = w.open_status;
        return w;
    }
    w.info = r.info();
    ListingSink sink(hash, opts.limits);
    w.status = r.walk(sink, opts, w.result);
    for (const EntryResult& e : w.result.entries_out) {
        if (e.meta.superseded || e.meta.deleted)
            w.history.push_back(e);
        else
            w.live[e.meta.path] = e;
    }
    return w;
}

const EntryResult* find_hist(const Walked& w, const std::string& path, bool deleted) {
    for (const EntryResult& e : w.history)
        if (e.meta.path == path && e.meta.deleted == deleted) return &e;
    return nullptr;
}

// ------------------------------------------------------------------ synthetic

class Qnx6Synth : public ::testing::TestWithParam<Endian> {};

TEST_P(Qnx6Synth, LiveTreeAndMetadata) {
    const Endian e = GetParam();
    const TestImage img = build_image(e);
    const Walked w = walk_listing(span_of(img.bytes));
    ASSERT_TRUE(w.open_status.ok) << w.open_status.error;
    ASSERT_TRUE(w.status.ok) << w.status.error << join_diags(w.result.diagnostics);
    for (const Diagnostic& d : w.result.diagnostics)
        EXPECT_NE(d.severity, Severity::Warning) << d.code << ": " << d.message;
    EXPECT_EQ(w.info.endian, e);
    EXPECT_EQ(w.info.attrs.at("endian"), e == Endian::Little ? "little" : "big");
    EXPECT_EQ(w.info.attrs.at("serial"), "6");
    EXPECT_EQ(w.info.attrs.at("second_serial"), "5");
    EXPECT_EQ(w.info.attrs.at("current_superblock"), "secondary");
    EXPECT_EQ(w.info.attrs.at("blocksize"), "1024");
    EXPECT_EQ(w.info.attrs.at("num_blocks"), "400");
    EXPECT_EQ(w.info.attrs.at("root_levels"), "1");
    EXPECT_EQ(w.info.attrs.at("longfile_count"), "1");
    EXPECT_EQ(w.info.attrs.at("superblock_crc"), "ok");
    EXPECT_EQ(w.info.block_size, 1024u);
    EXPECT_EQ(w.info.size, img.bytes.size());

    std::vector<std::string> order;
    for (const EntryResult& r : w.result.entries_out) order.push_back(r.meta.path);
    const std::vector<std::string> expect{"hello.txt", "sub",    "sub/nested.txt", "sub/fifo",
                                          kLongName,   "link",   "big.bin",        "tty",
                                          "deep.bin",  "new.txt"};
    EXPECT_EQ(order, expect);
    EXPECT_EQ(w.result.entries, 10u);
    EXPECT_EQ(w.result.files, 6u);
    EXPECT_EQ(w.result.dirs, 1u);
    EXPECT_EQ(w.result.symlinks, 1u);
    EXPECT_EQ(w.result.others, 2u);
    EXPECT_EQ(w.result.superseded, 0u);
    EXPECT_EQ(w.result.deleted, 0u);
    EXPECT_FALSE(w.result.truncated);

    const EntryResult& hello = w.live.at("hello.txt");
    EXPECT_EQ(hello.meta.kind, EntryKind::Regular);
    EXPECT_EQ(hello.meta.mode, 0644u);
    EXPECT_EQ(hello.meta.size, 10u);
    EXPECT_EQ(hello.meta.inode, 2u);
    EXPECT_EQ(hello.meta.nlink, 1u);
    EXPECT_EQ(hello.meta.version, 6u);
    EXPECT_EQ(hello.meta.mtime.value_or(0), 1700000022);
    EXPECT_EQ(hello.meta.atime.value_or(0), 1700000023);
    EXPECT_EQ(hello.meta.ctime.value_or(0), 1700000024);
    EXPECT_EQ(hello.meta.crtime.value_or(0), 1700000012);
    EXPECT_EQ(hello.meta.extra.at("status"), "0x3");
    EXPECT_EQ(hello.digests.sha256, sha256_of(bytes_of("hello v2!\n")));
    EXPECT_FALSE(hello.truncated);

    const EntryResult& sub = w.live.at("sub");
    EXPECT_EQ(sub.meta.kind, EntryKind::Directory);
    EXPECT_EQ(sub.meta.mode, 0750u);
    EXPECT_EQ(sub.meta.uid, 5u);
    EXPECT_EQ(sub.meta.gid, 6u);
    EXPECT_EQ(sub.meta.size, 0u);

    const EntryResult& nested = w.live.at("sub/nested.txt");
    EXPECT_EQ(nested.meta.mode, 0600u);
    EXPECT_EQ(nested.meta.uid, 1000u);
    EXPECT_EQ(nested.meta.gid, 100u);
    EXPECT_EQ(nested.digests.sha256, sha256_of(bytes_of("nested\n")));
    EXPECT_EQ(w.live.at("sub/fifo").meta.kind, EntryKind::Fifo);

    const EntryResult& longf = w.live.at(kLongName);
    EXPECT_EQ(longf.meta.inode, 4u);
    EXPECT_EQ(longf.digests.sha256, sha256_of(bytes_of("long\n")));

    const EntryResult& link = w.live.at("link");
    EXPECT_EQ(link.meta.kind, EntryKind::Symlink);
    EXPECT_EQ(link.meta.link_target, "sub/nested.txt");
    EXPECT_EQ(link.meta.size, 14u);
    EXPECT_EQ(link.meta.mode, 0777u);

    const EntryResult& big = w.live.at("big.bin");
    EXPECT_EQ(big.meta.size, 2u * 1024u + 100u);
    EXPECT_EQ(big.digests.bytes, 2u * 1024u + 100u);
    EXPECT_EQ(big.digests.sha256, sha256_of(img.big_content));
    EXPECT_FALSE(big.truncated);

    const EntryResult& tty = w.live.at("tty");
    EXPECT_EQ(tty.meta.kind, EntryKind::CharDevice);
    EXPECT_EQ(tty.meta.mode, 0620u);
    EXPECT_EQ(tty.meta.extra.at("ext_mode"), "0x102");

    const EntryResult& deep = w.live.at("deep.bin");
    EXPECT_EQ(deep.meta.extra.at("levels"), "2");
    EXPECT_EQ(deep.digests.sha256, sha256_of(img.deep_content));
    EXPECT_EQ(w.live.at("new.txt").digests.sha256, sha256_of(bytes_of("brand new\n")));
}

TEST_P(Qnx6Synth, HistoryFromTheOtherSnapshotAndTheInodeTable) {
    const Endian e = GetParam();
    const TestImage img = build_image(e);
    const Walked w = walk_listing(span_of(img.bytes), true, history_opts());
    ASSERT_TRUE(w.status.ok) << w.status.error;
    // The live part is identical to a plain walk.
    const Walked plain = walk_listing(span_of(img.bytes));
    EXPECT_EQ(plain.live.size(), w.live.size());
    for (const auto& [path, entry] : plain.live) {
        ASSERT_EQ(w.live.count(path), 1u) << path;
        EXPECT_EQ(w.live.at(path).digests.sha256, entry.digests.sha256) << path;
    }
    std::vector<std::string> hist;
    for (const EntryResult& h : w.history)
        hist.push_back(h.meta.path + (h.meta.deleted ? " deleted" : " superseded") + " v" +
                       std::to_string(h.meta.version));
    const std::vector<std::string> expect{"hello.txt superseded v5", "sub/nested.txt superseded v5",
                                          "gone.txt deleted v5", "lost+found/#12 deleted v6",
                                          "lost+found/#13 deleted v6"};
    EXPECT_EQ(hist, expect) << join_diags(w.result.diagnostics);
    EXPECT_EQ(w.result.superseded, 2u);
    EXPECT_EQ(w.result.deleted, 3u);

    const EntryResult* h1 = find_hist(w, "hello.txt", false);
    ASSERT_NE(h1, nullptr);
    EXPECT_EQ(h1->meta.inode, 2u);
    EXPECT_EQ(h1->meta.mtime.value_or(0), 1700000002);
    EXPECT_EQ(h1->digests.sha256, sha256_of(bytes_of("hello v1\n")));
    EXPECT_FALSE(h1->truncated);

    const EntryResult* n1 = find_hist(w, "sub/nested.txt", false);
    ASSERT_NE(n1, nullptr);
    EXPECT_EQ(n1->meta.mode, 0644u);
    EXPECT_EQ(n1->digests.sha256, sha256_of(bytes_of("nested\n")));

    const EntryResult* g = find_hist(w, "gone.txt", true);
    ASSERT_NE(g, nullptr);
    EXPECT_EQ(g->meta.inode, 7u);
    EXPECT_EQ(g->digests.sha256, sha256_of(bytes_of("to be deleted\n")));
    EXPECT_FALSE(g->truncated);

    const EntryResult* o = find_hist(w, "lost+found/#12", true);
    ASSERT_NE(o, nullptr);
    EXPECT_EQ(o->meta.extra.at("record"), "inode-table");
    EXPECT_EQ(o->meta.extra.at("orphan"), "true");
    EXPECT_EQ(o->meta.extra.at("status"), "0x2");
    EXPECT_EQ(o->digests.sha256, sha256_of(bytes_of("orphan data\n")));
    EXPECT_FALSE(o->truncated);

    const EntryResult* r = find_hist(w, "lost+found/#13", true);
    ASSERT_NE(r, nullptr);
    EXPECT_TRUE(r->truncated);
    EXPECT_TRUE(has_code(r->diagnostics, "qnx6-deleted-blocks-reused"))
        << join_diags(r->diagnostics);
    EXPECT_EQ(r->digests.sha256, sha256_of(Bytes(10, 0)));
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx6-deleted-blocks-reused"));
}

INSTANTIATE_TEST_SUITE_P(ByteOrders, Qnx6Synth, ::testing::Values(Endian::Little, Endian::Big));

TEST(Qnx6Synth, DiskSinkWritesTreeAndVersions) {
    TempDir tmp;
    std::unique_ptr<DiskSink> sink;
    ASSERT_TRUE(DiskSink::open((tmp.path() / "out").string(), {}, sink).ok);
    const TestImage img = build_image(Endian::Little);
    Qnx6Reader r;
    ASSERT_TRUE(r.open(span_of(img.bytes)).ok);
    WalkResult out;
    ASSERT_TRUE(r.walk(*sink, history_opts(), out).ok);
    const stdfs::path root = tmp.path() / "out";
    EXPECT_TRUE(stdfs::is_regular_file(root / "hello.txt"));
    EXPECT_TRUE(stdfs::is_directory(root / "sub"));
    EXPECT_TRUE(stdfs::is_symlink(root / "link"));
    EXPECT_EQ(stdfs::read_symlink(root / "link").string(), "sub/nested.txt");
    EXPECT_TRUE(stdfs::is_regular_file(root / kLongName));
    EXPECT_EQ(stdfs::file_size(root / "big.bin"), 2u * 1024u + 100u);
    EXPECT_TRUE(stdfs::is_regular_file(root / ".omnitrace-versions" / "hello.txt" / "v5"));
    EXPECT_TRUE(stdfs::is_regular_file(root / ".omnitrace-versions" / "gone.txt" / "v5"));
    EXPECT_TRUE(stdfs::is_regular_file(root / ".omnitrace-versions" / "lost+found" / "#12" / "v6"));
    std::ifstream in(root / ".omnitrace-versions" / "hello.txt" / "v5", std::ios::binary);
    const std::string v5((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_EQ(v5, "hello v1\n");
}

TEST(Qnx6Synth, RegistryCreatesReader) {
    auto r = FilesystemRegistry::instance().create("qnx6");
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->format(), "qnx6");
}

TEST(Qnx6Synth, OpenRejectsNonInstances) {
    Qnx6Reader r;
    EXPECT_FALSE(r.open(span_of(Bytes(64, 0))).ok);
    EXPECT_FALSE(r.open(span_of(Bytes(0x8000, 0xFF))).ok);
    Bytes b(0x8000, 0);
    b[0x2000] = 0x22;
    b[0x2001] = 0x11;
    b[0x2002] = 0x19;
    b[0x2003] = 0x68;  // magic, zero blocksize
    const Status s = r.open(span_of(b));
    EXPECT_FALSE(s.ok);
    EXPECT_EQ(s.error.rfind("qnx6-no-superblock", 0), 0u) << s.error;
    WalkResult out;
    ListingSink sink;
    EXPECT_FALSE(r.walk(sink, {}, out).ok);
}

TEST(Qnx6Synth, MetadataOnlyWalk) {
    const TestImage img = build_image(Endian::Little);
    WalkOptions o;
    o.extract_data = false;
    const Walked w = walk_listing(span_of(img.bytes), true, o);
    ASSERT_TRUE(w.status.ok);
    EXPECT_EQ(w.live.size(), 10u);
    EXPECT_EQ(w.live.at("big.bin").meta.size, 2u * 1024u + 100u);
    EXPECT_EQ(w.live.at("big.bin").digests.bytes, 0u);
    EXPECT_EQ(w.result.bytes, 0u);
}

TEST(Qnx6Synth, DeterministicAcrossWalks) {
    const TestImage img = build_image(Endian::Little);
    Qnx6Reader r;
    ASSERT_TRUE(r.open(span_of(img.bytes)).ok);
    std::vector<std::string> a, b;
    for (int i = 0; i < 2; ++i) {
        ListingSink sink(true);
        WalkResult out;
        ASSERT_TRUE(r.walk(sink, history_opts(), out).ok);
        for (const EntryResult& e : out.entries_out)
            (i == 0 ? a : b)
                .push_back(e.meta.path + "|" + e.digests.sha256 + std::to_string(e.meta.version));
    }
    EXPECT_EQ(a, b);
}

TEST(Qnx6Synth, SerialRuleIgnoresPosition) {
    // Same image with the serials swapped: the primary (serial 6 now) wins
    // and the tree it describes is the old one.
    TestImage img = build_image(Endian::Little);
    auto put_serial = [&](std::uint64_t at, std::uint64_t serial) {
        for (std::size_t i = 0; i < 8; ++i)
            img.bytes[static_cast<std::size_t>(at + 8 + i)] =
                static_cast<std::uint8_t>((serial >> (8 * i)) & 0xFF);
        std::uint32_t crc = sb_crc(img.bytes.data() + at + 8, 504);
        for (std::size_t i = 0; i < 4; ++i)
            img.bytes[static_cast<std::size_t>(at + 4 + i)] =
                static_cast<std::uint8_t>((crc >> (8 * i)) & 0xFF);
    };
    put_serial(img.sb_old, 6);
    put_serial(img.sb_new, 5);
    const Walked w = walk_listing(span_of(img.bytes), true, history_opts());
    ASSERT_TRUE(w.status.ok);
    EXPECT_EQ(w.info.attrs.at("current_superblock"), "primary");
    EXPECT_EQ(w.live.count("gone.txt"), 1u);
    EXPECT_EQ(w.live.count("new.txt"), 0u);
    EXPECT_EQ(w.live.at("hello.txt").digests.sha256, sha256_of(bytes_of("hello v1\n")));
    const EntryResult* nw = find_hist(w, "new.txt", true);
    ASSERT_NE(nw, nullptr);
    EXPECT_EQ(nw->meta.version, 5u);
}

TEST(Qnx6History, VersionCapDropsHistory) {
    const TestImage img = build_image(Endian::Little);
    WalkOptions o = history_opts();
    o.limits.max_versions_per_entry = 0;
    const Walked w = walk_listing(span_of(img.bytes), true, o);
    ASSERT_TRUE(w.status.ok);
    EXPECT_EQ(w.history.size(), 0u);
    EXPECT_EQ(w.live.size(), 10u);
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx6-limit-versions"));
    EXPECT_FALSE(w.result.truncated);
}

TEST(Qnx6History, SingleSuperblockHasNoSnapshotHistory) {
    TestImage img = build_image(Endian::Little);
    // Destroy the primary superblock's magic: only the second (current) one remains.
    img.bytes[static_cast<std::size_t>(img.sb_old)] = 0;
    const Walked w = walk_listing(span_of(img.bytes), true, history_opts());
    ASSERT_TRUE(w.open_status.ok) << w.open_status.error;
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx6-superblock-single"));
    EXPECT_EQ(w.info.attrs.at("second_superblock_offset"), "none");
    EXPECT_EQ(w.live.size(), 10u);
    // No previous snapshot, so gone.txt has no name: it is an orphan record.
    std::vector<std::string> hist;
    for (const EntryResult& h : w.history) hist.push_back(h.meta.path);
    EXPECT_EQ(hist,
              (std::vector<std::string>{"lost+found/#7", "lost+found/#12", "lost+found/#13"}));
}

// ------------------------------------------------------------------ hostile

TEST(Qnx6Hostile, TruncationNeverCrashes) {
    const TestImage img = build_image(Endian::Little);
    std::vector<std::size_t> cuts;
    for (std::size_t cut = 0; cut < 0x4200; cut += 97) cuts.push_back(cut);
    for (std::size_t cut = 0x4200; cut < img.bytes.size(); cut += 1021) cuts.push_back(cut);
    for (const std::size_t cut : cuts) {
        Bytes b(img.bytes.begin(), img.bytes.begin() + static_cast<std::ptrdiff_t>(cut));
        const Walked w = walk_listing(span_of(b), true, history_opts());
        (void)w;
    }
}

TEST(Qnx6Hostile, SeededByteFlipsNeverCrash) {
    const TestImage img = build_image(Endian::Little);
    std::mt19937 rng(1234);
    for (int round = 0; round < 60; ++round) {
        Bytes b = img.bytes;
        const int flips = 1 + static_cast<int>(rng() % 24);
        for (int i = 0; i < flips; ++i) {
            // Flip inside the metadata area more often than in the data.
            const std::size_t at =
                (rng() % 4 == 0) ? rng() % b.size() : 0x2000 + rng() % (b.size() - 0x2000) / 8;
            b[at] ^= static_cast<std::uint8_t>(1u << (rng() % 8));
        }
        const Walked w = walk_listing(span_of(b), true, history_opts());
        (void)w;
    }
}

TEST(Qnx6Hostile, SevenLevelsInBothSuperblocksFailsOpen) {
    TestImage img = build_image(Endian::Little);
    img.bytes[static_cast<std::size_t>(img.sb_old + 72 + 72)] = 7;
    img.bytes[static_cast<std::size_t>(img.sb_new + 72 + 72)] = 7;
    Qnx6Reader r;
    const Status s = r.open(span_of(img.bytes));
    EXPECT_FALSE(s.ok);
    EXPECT_EQ(s.error.rfind("qnx6-no-superblock", 0), 0u) << s.error;
}

TEST(Qnx6Hostile, SevenLevelsInOneSuperblockFallsBackToTheOther) {
    TestImage img = build_image(Endian::Little);
    img.bytes[static_cast<std::size_t>(img.sb_new + 72 + 72)] = 7;
    const Walked w = walk_listing(span_of(img.bytes), true, history_opts());
    ASSERT_TRUE(w.open_status.ok) << w.open_status.error;
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx6-bad-superblock"));
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx6-superblock-single"));
    EXPECT_EQ(w.info.attrs.at("serial"), "5");
    EXPECT_EQ(w.live.count("gone.txt"), 1u);
}

TEST(Qnx6Hostile, SevenLevelsInAnInodeIsOutOfRange) {
    TestImage img = build_image(Endian::Little);
    img.bytes[static_cast<std::size_t>(img.hello_inode_off_new + 100)] = 7;
    const Walked w = walk_listing(span_of(img.bytes));
    ASSERT_TRUE(w.status.ok);
    const EntryResult& hello = w.live.at("hello.txt");
    EXPECT_TRUE(hello.truncated);
    EXPECT_TRUE(has_code(hello.diagnostics, "qnx6-block-out-of-range"));
    EXPECT_EQ(hello.digests.bytes, 10u);  // zero-filled to size
}

TEST(Qnx6Hostile, BlockPointerPastImage) {
    TestImage img = build_image(Endian::Little);
    for (std::size_t i = 0; i < 4; ++i)
        img.bytes[static_cast<std::size_t>(img.big_inode_off_new + 36 + i)] = 0x7F;
    const Walked w = walk_listing(span_of(img.bytes));
    ASSERT_TRUE(w.status.ok);
    const EntryResult& big = w.live.at("big.bin");
    EXPECT_TRUE(big.truncated);
    EXPECT_TRUE(has_code(big.diagnostics, "qnx6-block-out-of-range"));
    EXPECT_EQ(big.digests.bytes, 2u * 1024u + 100u);
    // Other entries are unaffected.
    EXPECT_EQ(w.live.at("hello.txt").digests.sha256, sha256_of(bytes_of("hello v2!\n")));
}

TEST(Qnx6Hostile, DirentLengthZeroAndSlashInName) {
    TestImage img = build_image(Endian::Little);
    img.bytes[static_cast<std::size_t>(img.root_dir_off_new + 2 * 32 + 4)] = 0;    // hello.txt
    img.bytes[static_cast<std::size_t>(img.root_dir_off_new + 3 * 32 + 5)] = '/';  // sub
    img.bytes[static_cast<std::size_t>(img.root_dir_off_new + 5 * 32 + 4)] = 28;   // link
    const Walked w = walk_listing(span_of(img.bytes));
    ASSERT_TRUE(w.status.ok);
    EXPECT_EQ(w.live.count("hello.txt"), 0u);
    EXPECT_EQ(w.live.count("sub"), 0u);
    EXPECT_EQ(w.live.count("link"), 0u);
    EXPECT_EQ(w.live.count("big.bin"), 1u);
    std::size_t n = 0;
    for (const Diagnostic& d : w.result.diagnostics) n += d.code == "qnx6-dirent-corrupt";
    EXPECT_EQ(n, 3u);
}

TEST(Qnx6Hostile, LongNameIndexPastTable) {
    TestImage img = build_image(Endian::Little);
    const std::size_t at = static_cast<std::size_t>(img.root_dir_off_new + 4 * 32 + 8);
    img.bytes[at] = 0xE8;  // index 1000
    img.bytes[at + 1] = 0x03;
    const Walked w = walk_listing(span_of(img.bytes));
    ASSERT_TRUE(w.status.ok);
    EXPECT_EQ(w.live.count(kLongName), 0u);
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx6-longfile-corrupt"));
    EXPECT_EQ(w.live.size(), 9u);
}

TEST(Qnx6Hostile, LongNameChecksumMismatchKeepsTheName) {
    TestImage img = build_image(Endian::Little);
    img.bytes[static_cast<std::size_t>(img.root_dir_off_new + 4 * 32 + 12)] ^= 0x55;
    const Walked w = walk_listing(span_of(img.bytes));
    ASSERT_TRUE(w.status.ok);
    EXPECT_EQ(w.live.count(kLongName), 1u);
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx6-longfile-checksum"));
}

TEST(Qnx6Hostile, SelfReferencingDirectory) {
    TestImage img = build_image(Endian::Little);
    // sub/fifo -> inode 3 (sub itself) and root's "tty" -> inode 1 (root).
    img.bytes[static_cast<std::size_t>(img.sub_dir_off_new + 3 * 32)] = 3;
    img.bytes[static_cast<std::size_t>(img.root_dir_off_new + 8 * 32)] = 1;
    const Walked w = walk_listing(span_of(img.bytes));
    ASSERT_TRUE(w.status.ok);
    std::size_t loops = 0;
    for (const Diagnostic& d : w.result.diagnostics) loops += d.code == "qnx6-dir-loop";
    EXPECT_EQ(loops, 2u);
    EXPECT_EQ(w.live.count("sub/fifo"), 0u);
    EXPECT_EQ(w.live.count("tty"), 0u);
    EXPECT_EQ(w.live.count("new.txt"), 1u);
}

TEST(Qnx6Hostile, HugeNumBlocksIsTruncatedNotFatal) {
    TestImage img = build_image(Endian::Little);
    for (std::size_t i = 0; i < 4; ++i)
        img.bytes[static_cast<std::size_t>(img.sb_new + 60 + i)] = 0xFF;
    const std::uint32_t crc = sb_crc(img.bytes.data() + img.sb_new + 8, 504);
    for (std::size_t i = 0; i < 4; ++i)
        img.bytes[static_cast<std::size_t>(img.sb_new + 4 + i)] =
            static_cast<std::uint8_t>((crc >> (8 * i)) & 0xFF);
    const Walked w = walk_listing(span_of(img.bytes));
    ASSERT_TRUE(w.open_status.ok) << w.open_status.error;
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx6-truncated"));
    EXPECT_EQ(w.info.attrs.at("truncated"), "true");
    EXPECT_EQ(w.info.attrs.at("serial"), "6");
    EXPECT_EQ(w.live.count("hello.txt"), 1u);
}

TEST(Qnx6Hostile, HugeDirectorySizeEndsWithTheNodeBudget) {
    // A directory whose inode claims 2^56 bytes of data behind 16 direct
    // pointers: every block past the first is a hole or unmapped. Each
    // directory block counts against max_nodes_per_fs, so the walk stops
    // there instead of spinning over 2^46 empty blocks, and an unmapped
    // block is reported once per directory, not once per block.
    TestImage img = build_image(Endian::Little);
    // Inode 3 ("sub") sits 128 bytes after inode 2 in the same table block.
    const std::size_t sub = static_cast<std::size_t>(img.hello_inode_off_new + 128);
    img.bytes[sub + 7] = 0x01;  // size |= 1 << 56 (little-endian)
    WalkOptions o;
    o.limits.max_nodes_per_fs = 200;
    const Walked w = walk_listing(span_of(img.bytes), true, o);
    ASSERT_TRUE(w.status.ok);
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx6-limit-nodes"))
        << join_diags(w.result.diagnostics);
    EXPECT_TRUE(w.result.truncated);
    EXPECT_LT(w.result.diagnostics.size(), 20u) << join_diags(w.result.diagnostics);
    EXPECT_EQ(w.live.count("sub/nested.txt"), 1u);
    EXPECT_EQ(w.live.count("sub/fifo"), 1u);

    // The same size with a pointer past the data area: one report, then
    // the budget ends the directory.
    img.bytes[sub + 36 + 4] = 0xFF;  // ptr[1] = 0x0000FFFF (> num_blocks 400)
    img.bytes[sub + 36 + 5] = 0xFF;
    img.bytes[sub + 36 + 6] = 0;
    img.bytes[sub + 36 + 7] = 0;
    const Walked w2 = walk_listing(span_of(img.bytes), true, o);
    ASSERT_TRUE(w2.status.ok);
    std::size_t corrupt = 0;
    for (const Diagnostic& d : w2.result.diagnostics)
        corrupt += d.code == "qnx6-inode-tree-corrupt";
    EXPECT_EQ(corrupt, 1u) << join_diags(w2.result.diagnostics);
    EXPECT_TRUE(has_code(w2.result.diagnostics, "qnx6-limit-nodes"));
}

TEST(Qnx6Hostile, BothSuperblockCrcsBad) {
    TestImage img = build_image(Endian::Little);
    img.bytes[static_cast<std::size_t>(img.sb_old + 20)] ^= 1;
    img.bytes[static_cast<std::size_t>(img.sb_new + 20)] ^= 1;
    const Walked w = walk_listing(span_of(img.bytes), true, history_opts());
    ASSERT_TRUE(w.open_status.ok) << w.open_status.error;
    std::size_t bad = 0;
    for (const Diagnostic& d : w.result.diagnostics) bad += d.code == "qnx6-superblock-bad-crc";
    EXPECT_EQ(bad, 2u);
    EXPECT_EQ(w.info.attrs.at("superblock_crc"), "bad");
    EXPECT_EQ(w.info.attrs.at("serial"), "6");  // higher serial still wins
    EXPECT_EQ(w.live.size(), 10u);
}

TEST(Qnx6Hostile, BadCrcLosesToGoodCrc) {
    TestImage img = build_image(Endian::Little);
    img.bytes[static_cast<std::size_t>(img.sb_new + 20)] ^= 1;  // the newer one is corrupt
    const Walked w = walk_listing(span_of(img.bytes));
    ASSERT_TRUE(w.open_status.ok);
    EXPECT_EQ(w.info.attrs.at("serial"), "5");
    EXPECT_EQ(w.live.count("gone.txt"), 1u);
}

TEST(Qnx6Hostile, NodeFileAndByteLimits) {
    const TestImage img = build_image(Endian::Little);
    {
        WalkOptions o;
        o.limits.max_nodes_per_fs = 3;
        const Walked w = walk_listing(span_of(img.bytes), true, o);
        ASSERT_TRUE(w.status.ok);
        EXPECT_TRUE(w.result.truncated);
        EXPECT_TRUE(has_code(w.result.diagnostics, "qnx6-limit-nodes"));
        EXPECT_LE(w.live.size(), 3u);
    }
    {
        WalkOptions o;
        o.limits.max_files = 2;
        const Walked w = walk_listing(span_of(img.bytes), true, o);
        EXPECT_TRUE(w.result.truncated);
        EXPECT_TRUE(has_code(w.result.diagnostics, "qnx6-limit-files"));
        EXPECT_EQ(w.live.size(), 2u);
    }
    {
        WalkOptions o;
        o.limits.max_file_bytes = 100;
        const Walked w = walk_listing(span_of(img.bytes), true, o);
        const EntryResult& big = w.live.at("big.bin");
        EXPECT_TRUE(big.truncated);
        EXPECT_TRUE(has_code(big.diagnostics, "qnx6-limit-file-bytes"));
        EXPECT_EQ(big.digests.bytes, 100u);
    }
}

TEST(Qnx6Hostile, NoMapSourceStillWalks) {
    // A Source that cannot map: every read goes through Span::read.
    class NoMapSource final : public Source {
       public:
        explicit NoMapSource(Bytes b) : bytes_(std::move(b)) {}
        std::uint64_t size() const override { return bytes_.size(); }
        std::string id() const override { return "nomap"; }
        std::size_t read(std::uint64_t off, std::span<std::uint8_t> out) const override {
            if (off >= bytes_.size()) return 0;
            const std::size_t n =
                std::min<std::size_t>(out.size(), bytes_.size() - static_cast<std::size_t>(off));
            std::memcpy(out.data(), bytes_.data() + off, n);
            return n;
        }
        std::span<const std::uint8_t> map(std::uint64_t, std::size_t) const override { return {}; }

       private:
        Bytes bytes_;
    };
    const TestImage img = build_image(Endian::Big);
    const Walked w =
        walk_listing(Span::whole(std::make_shared<NoMapSource>(img.bytes)), true, history_opts());
    ASSERT_TRUE(w.status.ok);
    EXPECT_EQ(w.live.size(), 10u);
    EXPECT_EQ(w.live.at("deep.bin").digests.sha256, sha256_of(img.deep_content));
}

// ------------------------------------------------------------------ corpus

const std::string kCorpusImage =
    "/home/wrongbaud/projects/omnitrace-v2/corpus/qnx-example/flash/UserData.BIN";
const std::string kVenvPython = "/home/wrongbaud/magnet-scratch/qnx-utils/.venv/bin/python";
const std::string kQnxmountDir = "/home/wrongbaud/magnet-scratch/qnxmount";

bool qnxmount_available() {
    return tool_exists(kVenvPython) && stdfs::exists(kQnxmountDir + "/qnxmount/__main__.py") &&
           (tool_exists("/usr/bin/fusermount") || tool_exists("/bin/fusermount")) &&
           tool_exists("/usr/bin/find") && tool_exists("/usr/bin/sha256sum");
}

std::string shq(const std::string& s) {
    std::string q = "'";
    for (const char c : s) q += c == '\'' ? std::string("'\\''") : std::string(1, c);
    return q + "'";
}

// Mount `image` (at byte `offset`) with qnxmount in the background and wait
// for the mount to appear. Empty on failure, otherwise the mountpoint.
class QnxMount {
   public:
    QnxMount(const std::string& image, std::uint64_t offset, const stdfs::path& dir) {
        mnt_ = dir / "mnt";
        stdfs::create_directories(mnt_);
        const std::string log = (dir / "qnxmount.log").string();
        const std::string cmd = "PYTHONPATH=" + shq(kQnxmountDir) + " " + shq(kVenvPython) +
                                " -m qnxmount qnx6 -o " + std::to_string(offset) + " " +
                                shq(image) + " " + shq(mnt_.string()) + " >" + shq(log) + " 2>&1 &";
        (void)run(cmd);
        for (int i = 0; i < 300; ++i) {
            if (run("mountpoint -q " + shq(mnt_.string())) == 0) {
                ok_ = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    ~QnxMount() {
        if (!ok_) return;
        for (int i = 0; i < 50; ++i) {
            if (run("fusermount -u " + shq(mnt_.string()) + " 2>/dev/null") == 0) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
    bool ok() const { return ok_; }
    const stdfs::path& path() const { return mnt_; }

   private:
    stdfs::path mnt_;
    bool ok_ = false;
};

struct RefEntry {
    char type = 0;  // f d l c b p s
    std::uint32_t mode = 0, uid = 0, gid = 0;
    std::uint64_t size = 0;
    std::int64_t mtime = 0;
    std::string link;
    std::string sha256;
};

// Listing of the mount through find(1) and sha256sum(1), keyed by path.
std::map<std::string, RefEntry> reference_listing(const stdfs::path& mnt, const stdfs::path& dir,
                                                  int maxdepth, bool hashes) {
    std::map<std::string, RefEntry> out;
    const std::string list = (dir / "list.txt").string();
    std::string cmd = "cd " + shq(mnt.string()) + " && find . -mindepth 1";
    if (maxdepth > 0) cmd += " -maxdepth " + std::to_string(maxdepth);
    cmd += " -printf '%P\\t%y\\t%m\\t%U\\t%G\\t%s\\t%T@\\t%l\\n' > " + shq(list);
    if (run(cmd) != 0) return out;
    std::ifstream in(list);
    std::string line;
    while (std::getline(in, line)) {
        std::vector<std::string> f;
        std::size_t start = 0;
        for (;;) {
            const std::size_t tab = line.find('\t', start);
            f.push_back(
                line.substr(start, tab == std::string::npos ? std::string::npos : tab - start));
            if (tab == std::string::npos) break;
            start = tab + 1;
        }
        if (f.size() < 7) continue;
        RefEntry r;
        r.type = f[1].empty() ? '?' : f[1][0];
        r.mode = static_cast<std::uint32_t>(std::stoul(f[2], nullptr, 8));
        r.uid = static_cast<std::uint32_t>(std::stoul(f[3]));
        r.gid = static_cast<std::uint32_t>(std::stoul(f[4]));
        r.size = std::stoull(f[5]);
        r.mtime = static_cast<std::int64_t>(std::stod(f[6]));
        r.link = f.size() > 7 ? f[7] : "";
        out[f[0]] = r;
    }
    if (hashes) {
        const std::string hl = (dir / "hashes.txt").string();
        if (run("cd " + shq(mnt.string()) + " && find . -type f -exec sha256sum {} + > " +
                shq(hl)) != 0)
            return out;
        std::ifstream hin(hl);
        while (std::getline(hin, line)) {
            if (line.size() < 67) continue;
            const std::string h = line.substr(0, 64);
            std::string p = line.substr(66);
            if (p.rfind("./", 0) == 0) p = p.substr(2);
            const auto it = out.find(p);
            if (it != out.end()) it->second.sha256 = h;
        }
    }
    return out;
}

void compare_with_reference(const std::map<std::string, RefEntry>& ref,
                            const std::vector<EntryResult>& ours, bool hashes) {
    std::map<std::string, const EntryResult*> by_path;
    for (const EntryResult& e : ours)
        if (!e.meta.deleted && !e.meta.superseded) by_path[e.meta.path] = &e;
    for (const auto& [path, r] : ref) {
        const auto it = by_path.find(path);
        ASSERT_NE(it, by_path.end()) << "missing: " << path;
        const FileMeta& m = it->second->meta;
        const EntryKind want = r.type == 'f'   ? EntryKind::Regular
                               : r.type == 'd' ? EntryKind::Directory
                               : r.type == 'l' ? EntryKind::Symlink
                               : r.type == 'c' ? EntryKind::CharDevice
                               : r.type == 'b' ? EntryKind::BlockDevice
                               : r.type == 'p' ? EntryKind::Fifo
                               : r.type == 's' ? EntryKind::Socket
                                               : EntryKind::Unknown;
        EXPECT_EQ(m.kind, want) << path;
        EXPECT_EQ(m.mode, r.mode) << path;
        EXPECT_EQ(m.uid, r.uid) << path;
        EXPECT_EQ(m.gid, r.gid) << path;
        EXPECT_EQ(m.mtime.value_or(-1), r.mtime) << path;
        if (r.type == 'f') {
            EXPECT_EQ(m.size, r.size) << path;
            EXPECT_FALSE(it->second->truncated) << path << join_diags(it->second->diagnostics);
            if (hashes) {
                EXPECT_EQ(it->second->digests.sha256, r.sha256) << path;
            }
        }
        if (r.type == 'l') {
            EXPECT_EQ(m.link_target, r.link) << path;
        }
    }
}

struct CorpusPart {
    const char* name;
    std::uint64_t offset, length;
};

class Qnx6Corpus : public ::testing::TestWithParam<CorpusPart> {};

TEST_P(Qnx6Corpus, MatchesQnxmount) {
    const CorpusPart part = GetParam();
    if (!stdfs::exists(kCorpusImage)) GTEST_SKIP() << "corpus image missing: " << kCorpusImage;
    if (!qnxmount_available()) GTEST_SKIP() << "qnxmount, its venv, fusermount or find missing";
    std::shared_ptr<MappedFile> mf;
    ASSERT_TRUE(MappedFile::open(kCorpusImage, mf).ok);
    const Span slice = Span::whole(mf).sub(part.offset, part.length);

    TempDir tmp;
    // qnxmount trusts the boot block's superblock pointers, which are garbage
    // on dps_os; give it a copy of the slice with the pointers corrected.
    // The reader is run on the untouched bytes.
    const stdfs::path copy = tmp.path() / (std::string(part.name) + ".bin");
    {
        std::ofstream out(copy, std::ios::binary);
        std::vector<std::uint8_t> buf(1 << 20);
        for (std::uint64_t pos = 0; pos < slice.size();) {
            const std::size_t n = slice.read(pos, std::span<std::uint8_t>(buf.data(), buf.size()));
            if (n == 0) break;
            if (pos == 0) {
                const std::uint32_t bs =
                    slice.at<std::uint32_t>(0x2000 + 48, Endian::Little).value_or(4096);
                const std::uint32_t nb =
                    slice.at<std::uint32_t>(0x2000 + 60, Endian::Little).value_or(0);
                const std::uint64_t ds = (0x3000 + std::uint64_t{bs} - 1) / bs * bs;
                const std::uint64_t second = (ds + std::uint64_t{nb} * bs) / 512;
                const std::uint32_t s0 = 16, s1 = static_cast<std::uint32_t>(second);
                for (std::size_t i = 0; i < 4; ++i) {
                    buf[8 + i] = static_cast<std::uint8_t>((s0 >> (8 * i)) & 0xFF);
                    buf[12 + i] = static_cast<std::uint8_t>((s1 >> (8 * i)) & 0xFF);
                }
            }
            out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(n));
            pos += n;
        }
    }
    QnxMount mount(copy.string(), 0, tmp.path());
    if (!mount.ok()) GTEST_SKIP() << "qnxmount could not mount " << copy;
    const auto ref = reference_listing(mount.path(), tmp.path(), 0, true);
    ASSERT_FALSE(ref.empty());

    std::unique_ptr<DiskSink> sink;
    ASSERT_TRUE(DiskSink::open((tmp.path() / "out").string(), {}, sink).ok);
    Qnx6Reader r;
    ASSERT_TRUE(r.open(slice).ok);
    WalkResult out;
    ASSERT_TRUE(r.walk(*sink, {}, out).ok);
    EXPECT_FALSE(out.truncated) << join_diags(out.diagnostics);
    for (const Diagnostic& d : out.diagnostics)
        EXPECT_NE(d.severity, Severity::Error) << d.code << ": " << d.message;
    EXPECT_EQ(out.entries, ref.size());
    compare_with_reference(ref, out.entries_out, true);
    // diff -r against the mount (symlinks compared as links).
    EXPECT_EQ(run("diff -r --no-dereference " + shq(mount.path().string()) + " " +
                  shq((tmp.path() / "out").string()) + " >/dev/null"),
              0);

    // History walk must keep the live part identical.
    ListingSink hsink(true);
    WalkResult hist;
    ASSERT_TRUE(r.walk(hsink, history_opts(), hist).ok);
    compare_with_reference(ref, hist.entries_out, true);
    EXPECT_GE(hist.entries, out.entries);
}

INSTANTIATE_TEST_SUITE_P(Partitions, Qnx6Corpus,
                         ::testing::Values(CorpusPart{"dps_mfg", 0x800000, 4u << 20},
                                           CorpusPart{"dps_os", 0x1000000, 24u << 20}),
                         [](const ::testing::TestParamInfo<CorpusPart>& i) {
                             return std::string(i.param.name);
                         });

TEST(Qnx6Corpus, StorageTopTwoLevelsMatchQnxmount) {
    if (!stdfs::exists(kCorpusImage)) GTEST_SKIP() << "corpus image missing: " << kCorpusImage;
    if (!qnxmount_available()) GTEST_SKIP() << "qnxmount, its venv, fusermount or find missing";
    constexpr std::uint64_t kStorage = 0x16800000;
    std::shared_ptr<MappedFile> mf;
    ASSERT_TRUE(MappedFile::open(kCorpusImage, mf).ok);
    const Span part = Span::whole(mf).sub(kStorage);

    TempDir tmp;
    QnxMount mount(kCorpusImage, kStorage, tmp.path());
    if (!mount.ok()) GTEST_SKIP() << "qnxmount could not mount the storage partition";
    const auto ref = reference_listing(mount.path(), tmp.path(), 2, false);
    ASSERT_FALSE(ref.empty());

    Qnx6Reader r;
    ASSERT_TRUE(r.open(part).ok);
    const FilesystemInfo info = r.info();
    EXPECT_EQ(info.attrs.at("blocksize"), "4096");
    EXPECT_EQ(info.attrs.at("num_blocks"), "3724795");
    EXPECT_EQ(info.attrs.at("root_levels"), "1");
    WalkOptions o;
    o.extract_data = false;
    ListingSink sink(false);
    WalkResult out;
    ASSERT_TRUE(r.walk(sink, o, out).ok);
    EXPECT_FALSE(out.truncated) << join_diags(out.diagnostics);
    std::vector<EntryResult> top;
    for (const EntryResult& e : out.entries_out)
        if (std::count(e.meta.path.begin(), e.meta.path.end(), '/') < 2) top.push_back(e);
    EXPECT_EQ(top.size(), ref.size());
    compare_with_reference(ref, top, false);
}

}  // namespace
}  // namespace omnitrace::fs
