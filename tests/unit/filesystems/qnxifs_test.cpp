// qnxifs_test.cpp — QnxIfsReader.
//
// Coverage:
//   1. Images assembled byte by byte in the test with correct checksums, in
//      both byte orders: a directory, files (one spanning several compressed
//      blocks), the boot script, a symlink, devices, a fifo; uncompressed
//      and UCL-compressed with a minimal NRV2B encoder written for the tests.
//   2. Hostile images: truncation at every offset, hdr_dir_size past the
//      image, a file past the image, a path without NUL, 0xffff/0xffffffff
//      sizes everywhere, a compressed block past the buffer, a ratio bomb,
//      every Limits guard. Nothing may crash; run this binary under ASan.
//   3. Corpus (skipped when absent): the ifs_a and ifs_recovery partitions
//      of the qnx-example image against `dumpifs` (listing and extracted
//      bytes), and the false-positive magics in the auto-ivi splash partition.
#include "../../../src/filesystems/qnxifs/QnxIfsReader.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "omnitrace/core/Hash.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/filesystems/Filesystem.h"

#ifndef _WIN32
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
        path_ =
            base / ("omnitrace-qnxifs-" + std::to_string(pid) + "-" + std::to_string(counter++));
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

Bytes slurp(const stdfs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

Span span_of(Bytes bytes, const std::string& label = "img") {
    return Span::whole(std::make_shared<MemorySource>(std::move(bytes), label));
}

Bytes pseudo_random(std::size_t n, std::uint64_t seed) {
    Bytes v(n);
    std::uint64_t x = seed | 1;
    for (std::size_t i = 0; i < n; ++i) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        v[i] = static_cast<std::uint8_t>((x * 0x2545F4914F6CDD1Dull) >> 56);
    }
    return v;
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

constexpr std::uint32_t kIfReg = 0100000, kIfDir = 0040000, kIfLnk = 0120000, kIfChr = 0020000,
                        kIfBlk = 0060000, kIfFifo = 0010000, kIfSock = 0140000, kIfNam = 0050000;
constexpr std::uint32_t kInoFlagMask = 0xe0000000u;

// ------------------------------------------------------------------ NRV2B encoder (tests only)

// The NRV2B bit stream, writer side: bits fill a byte reserved when the first
// of its eight bits is written; stored bytes that follow land after it, which
// is where the decoder reloads its bit buffer. Same encoder as
// tests/unit/core/ucl_test.cpp.
struct BitStream {
    Bytes out;
    std::size_t bit_pos = 0;
    unsigned bits_left = 0;

    void put_bit(std::uint64_t b) {
        if (bits_left == 0) {
            bit_pos = out.size();
            out.push_back(0);
            bits_left = 8;
        }
        --bits_left;
        if (b != 0) out[bit_pos] |= static_cast<std::uint8_t>(1u << bits_left);
    }
    void put_byte(std::uint8_t b) { out.push_back(b); }
    void put_prefix(std::uint64_t v) {
        int top = 63;
        while (top > 0 && ((v >> top) & 1) == 0) --top;
        for (int k = top - 1; k >= 0; --k) {
            put_bit((v >> k) & 1);
            put_bit(k == 0 ? 1 : 0);
        }
    }
    void put_end() {
        put_bit(0);
        put_prefix(0x1000002);
        put_byte(0xff);
    }
};

Bytes nrv2b_encode(const Bytes& in, std::size_t window = 4096) {
    BitStream s;
    std::uint64_t last_off = 1;
    std::size_t i = 0;
    while (i < in.size()) {
        std::size_t best_len = 0, best_off = 0;
        const std::size_t start = i > window ? i - window : 0;
        for (std::size_t j = start; j < i; ++j) {
            std::size_t l = 0;
            while (i + l < in.size() && in[j + l] == in[i + l] && l < 512) ++l;
            if (l > best_len) {
                best_len = l;
                best_off = i - j;
            }
        }
        const std::uint64_t extra = best_off > 0xd00 ? 1 : 0;
        if (best_len < 2 + extra) {
            s.put_bit(1);
            s.put_byte(in[i]);
            ++i;
            continue;
        }
        s.put_bit(0);
        if (best_off == last_off) {
            s.put_prefix(2);
        } else {
            s.put_prefix(((best_off - 1) >> 8) + 3);
            s.put_byte(static_cast<std::uint8_t>((best_off - 1) & 0xff));
            last_off = best_off;
        }
        const std::uint64_t t = best_len - 1 - extra;
        if (t <= 3) {
            s.put_bit((t >> 1) & 1);
            s.put_bit(t & 1);
        } else {
            s.put_bit(0);
            s.put_bit(0);
            s.put_prefix(t - 2);
        }
        i += best_len;
    }
    s.put_end();
    return s.out;
}

// A stream of `n` copies of one byte in a handful of bytes.
Bytes nrv2b_bomb(std::size_t n) {
    BitStream s;
    s.put_bit(1);
    s.put_byte('z');
    s.put_bit(0);
    s.put_prefix(3);
    s.put_byte(0);
    s.put_bit(0);
    s.put_bit(0);
    s.put_prefix(n - 1 - 3);
    s.put_end();
    return s.out;
}

// ------------------------------------------------------------------ image builder

enum class Kind { File, Dir, Symlink, Char, Block, Fifo, Sock, Nam };

struct Spec {
    Kind kind = Kind::File;
    std::string path;
    std::uint32_t perm = 0644;
    std::uint32_t uid = 0, gid = 0;
    std::uint32_t mtime = 1700000000u;
    std::uint32_t ino = 0;        // 0: assigned in order from 2
    std::uint32_t ino_flags = 0;  // IFS_INO_* bits
    Bytes data;                   // files
    std::string target;           // symlinks
    std::uint32_t dev = 0, rdev = 0;
    std::uint16_t extattr = 0;
};

struct IfsOptions {
    bool big = false;
    unsigned codec = 0;  // 0 none, 3 ucl (the only one the test encoder makes)
    std::string mountpoint = "/";
    std::uint32_t script_ino = 0;
    std::uint32_t boot_ino = 0;
    std::uint16_t machine = 183;
    std::size_t code_size = 508;
    std::size_t block_input = 32768;  // bytes of image per compressed block
    Bytes extra_block;                // appended before the terminator (bombs)
};

struct Built {
    Bytes img;
    Bytes image;  // the image filesystem, uncompressed
    std::uint64_t startup_size = 0, stored_size = 0, dir_offset = 0, hdr_dir_size = 0,
                  image_size = 0, comp_start = 0;
    std::vector<std::uint64_t> dirents;   // image-relative offset of every non-root dirent
    std::vector<std::uint64_t> data_off;  // image-relative data offset per spec (files)
    Endian e = Endian::Little;
};

void put16(Bytes& b, std::size_t off, std::uint16_t v, Endian e) {
    if (e == Endian::Little) {
        b[off] = static_cast<std::uint8_t>(v & 0xff);
        b[off + 1] = static_cast<std::uint8_t>(v >> 8);
    } else {
        b[off] = static_cast<std::uint8_t>(v >> 8);
        b[off + 1] = static_cast<std::uint8_t>(v & 0xff);
    }
}
void put32(Bytes& b, std::size_t off, std::uint32_t v, Endian e) {
    for (std::size_t i = 0; i < 4; ++i) {
        const unsigned shift =
            e == Endian::Little ? 8 * static_cast<unsigned>(i) : 8 * static_cast<unsigned>(3 - i);
        b[off + i] = static_cast<std::uint8_t>((v >> shift) & 0xff);
    }
}
std::uint32_t get32(const Bytes& b, std::size_t off, Endian e) {
    std::uint32_t v = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        const unsigned shift =
            e == Endian::Little ? 8 * static_cast<unsigned>(i) : 8 * static_cast<unsigned>(3 - i);
        v |= static_cast<std::uint32_t>(b[off + i]) << shift;
    }
    return v;
}
void pad4(Bytes& b) {
    while (b.size() % 4 != 0) b.push_back(0);
}
// Append a checksum word that makes the u32 sum of [from, end] zero.
void seal(Bytes& b, std::size_t from, Endian e) {
    pad4(b);
    std::uint32_t sum = 0;
    for (std::size_t o = from; o + 4 <= b.size(); o += 4) sum += get32(b, o, e);
    b.resize(b.size() + 4);
    put32(b, b.size() - 4, static_cast<std::uint32_t>(0u - sum), e);
}

std::uint32_t type_bits(Kind k) {
    switch (k) {
        case Kind::File:
            return kIfReg;
        case Kind::Dir:
            return kIfDir;
        case Kind::Symlink:
            return kIfLnk;
        case Kind::Char:
            return kIfChr;
        case Kind::Block:
            return kIfBlk;
        case Kind::Fifo:
            return kIfFifo;
        case Kind::Sock:
            return kIfSock;
        case Kind::Nam:
            return kIfNam;
    }
    return 0;
}

Built build_ifs(std::vector<Spec> specs, const IfsOptions& o = {}) {
    Built r;
    const Endian e = o.big ? Endian::Big : Endian::Little;
    r.e = e;
    std::uint32_t next_ino = 2;
    for (Spec& s : specs)
        if (s.ino == 0) s.ino = next_ino++;

    // Image header.
    Bytes& im = r.image;
    im.assign(88, 0);
    std::memcpy(im.data(), "imagefs", 7);
    im[7] = static_cast<std::uint8_t>((o.big ? 0x01 : 0x00) | 0x04);
    if (o.boot_ino != 0) put32(im, 20, o.boot_ino, e);
    put32(im, 36, o.script_ino, e);
    for (const char c : o.mountpoint) im.push_back(static_cast<std::uint8_t>(c));
    im.push_back(0);
    pad4(im);
    r.dir_offset = im.size();
    put32(im, 16, static_cast<std::uint32_t>(r.dir_offset), e);

    auto attr = [&](Bytes& d, std::uint16_t size, std::uint16_t extattr, std::uint32_t ino,
                    std::uint32_t mode, std::uint32_t gid, std::uint32_t uid, std::uint32_t mtime) {
        d.assign(24, 0);
        put16(d, 0, size, e);
        put16(d, 2, extattr, e);
        put32(d, 4, ino, e);
        put32(d, 8, mode, e);
        put32(d, 12, gid, e);
        put32(d, 16, uid, e);
        put32(d, 20, mtime, e);
    };
    // Root dirent: an empty path.
    {
        Bytes d;
        attr(d, 28, 0, 1, kIfDir | 0755, 0, 0, 1700000000u);
        d.resize(28, 0);
        im.insert(im.end(), d.begin(), d.end());
    }
    // Directory: sizes first, so file data offsets are known.
    std::vector<std::size_t> sizes;
    std::size_t dir_bytes = 0;
    for (const Spec& s : specs) {
        std::size_t body = 24 + s.path.size() + 1;
        if (s.kind == Kind::File) body += 8;
        if (s.kind == Kind::Symlink) body += 4 + s.target.size() + 1;
        if (s.kind >= Kind::Char) body += 8;
        body = (body + 3) & ~std::size_t{3};
        sizes.push_back(body);
        dir_bytes += body;
    }
    r.hdr_dir_size = im.size() + dir_bytes;
    std::uint64_t data_cursor = r.hdr_dir_size;
    r.data_off.assign(specs.size(), 0);
    for (std::size_t i = 0; i < specs.size(); ++i) {
        if (specs[i].kind != Kind::File) continue;
        r.data_off[i] = data_cursor;
        data_cursor += (specs[i].data.size() + 3) & ~std::size_t{3};
    }
    for (std::size_t i = 0; i < specs.size(); ++i) {
        const Spec& s = specs[i];
        Bytes d;
        attr(d, static_cast<std::uint16_t>(sizes[i]), s.extattr, s.ino | s.ino_flags,
             type_bits(s.kind) | s.perm, s.gid, s.uid, s.mtime);
        if (s.kind == Kind::File) {
            d.resize(32, 0);
            put32(d, 24, static_cast<std::uint32_t>(r.data_off[i]), e);
            put32(d, 28, static_cast<std::uint32_t>(s.data.size()), e);
        } else if (s.kind == Kind::Symlink) {
            d.resize(28, 0);
            put16(d, 24, static_cast<std::uint16_t>(s.path.size() + 1), e);
            put16(d, 26, static_cast<std::uint16_t>(s.target.size()), e);
        } else if (s.kind >= Kind::Char) {
            d.resize(32, 0);
            put32(d, 24, s.dev, e);
            put32(d, 28, s.rdev, e);
        }
        for (const char c : s.path) d.push_back(static_cast<std::uint8_t>(c));
        d.push_back(0);
        if (s.kind == Kind::Symlink) {
            for (const char c : s.target) d.push_back(static_cast<std::uint8_t>(c));
            d.push_back(0);
        }
        d.resize(sizes[i], 0);
        r.dirents.push_back(im.size());
        im.insert(im.end(), d.begin(), d.end());
    }
    for (std::size_t i = 0; i < specs.size(); ++i) {
        if (specs[i].kind != Kind::File) continue;
        im.insert(im.end(), specs[i].data.begin(), specs[i].data.end());
        pad4(im);
    }
    put32(im, 12, static_cast<std::uint32_t>(r.hdr_dir_size), e);
    put32(im, 8, static_cast<std::uint32_t>(im.size() + 4), e);
    seal(im, 0, e);
    r.image_size = im.size();

    // Startup header and code.
    Bytes& img = r.img;
    img.assign(256, 0);
    if (o.big) {
        img[0] = 0x00, img[1] = 0xff, img[2] = 0x7e, img[3] = 0xeb;
    } else {
        img[0] = 0xeb, img[1] = 0x7e, img[2] = 0xff, img[3] = 0x00;
    }
    put16(img, 4, 1, e);
    img[6] = static_cast<std::uint8_t>(0x01 | (o.big ? 0x02 : 0) | (o.codec << 2));
    img[7] = 0;
    put16(img, 8, 256, e);
    put16(img, 10, o.machine, e);
    put32(img, 12, 0x82301800u, e);
    put32(img, 16, 0, e);
    put32(img, 20, 0x82300000u, e);
    put32(img, 24, 0x82300000u, e);
    put32(img, 28, static_cast<std::uint32_t>(im.size() + 0x20000), e);
    r.startup_size = 256 + o.code_size + 4;
    put32(img, 32, static_cast<std::uint32_t>(r.startup_size), e);
    put32(img, 44, static_cast<std::uint32_t>(im.size()), e);
    for (std::size_t i = 0; i < o.code_size; ++i)
        img.push_back(static_cast<std::uint8_t>((i * 7 + 3) & 0xff));

    // Payload.
    Bytes payload;
    if (o.codec == 0) {
        payload = im;
    } else {
        for (std::size_t off = 0; off < im.size(); off += o.block_input) {
            const std::size_t n = std::min(o.block_input, im.size() - off);
            const Bytes enc =
                nrv2b_encode(Bytes(im.begin() + static_cast<std::ptrdiff_t>(off),
                                   im.begin() + static_cast<std::ptrdiff_t>(off + n)));
            payload.push_back(static_cast<std::uint8_t>(enc.size() >> 8));
            payload.push_back(static_cast<std::uint8_t>(enc.size() & 0xff));
            payload.insert(payload.end(), enc.begin(), enc.end());
        }
        if (!o.extra_block.empty()) {
            payload.push_back(static_cast<std::uint8_t>(o.extra_block.size() >> 8));
            payload.push_back(static_cast<std::uint8_t>(o.extra_block.size() & 0xff));
            payload.insert(payload.end(), o.extra_block.begin(), o.extra_block.end());
        }
        payload.push_back(0);
        payload.push_back(0);
    }
    r.stored_size = r.startup_size + payload.size() + (o.codec == 0 ? 0 : 4);
    if (o.codec != 0) r.stored_size = ((r.startup_size + payload.size() + 3) & ~3ull) + 4;
    put32(img, 36, static_cast<std::uint32_t>(r.stored_size), e);
    seal(img, 0, e);  // startup trailer
    r.comp_start = img.size();
    img.insert(img.end(), payload.begin(), payload.end());
    if (o.codec != 0) seal(img, r.comp_start, e);
    return r;
}

Spec mk(Kind kind, std::string path, std::uint32_t perm, std::uint32_t uid = 0,
        std::uint32_t gid = 0, std::uint32_t mtime = 1700000000u) {
    Spec s;
    s.kind = kind;
    s.path = std::move(path);
    s.perm = perm;
    s.uid = uid;
    s.gid = gid;
    s.mtime = mtime;
    return s;
}

// The tree every synthetic test uses.
std::vector<Spec> sample_specs() {
    std::vector<Spec> v;
    v.push_back(mk(Kind::Dir, "etc", 0755));
    v.push_back(mk(Kind::Dir, "proc/boot", 0755));
    Spec passwd = mk(Kind::File, "etc/passwd", 0644, 0, 0, 1700000001u);
    passwd.data = bytes_of("root:x:0:0:root:/:/bin/sh\n");
    v.push_back(passwd);
    Spec script = mk(Kind::File, "proc/boot/.script", 0444, 0, 0, 1700000002u);
    script.ino = 3;
    script.data = bytes_of("\x10\x00\x00\x00procnto-smp-instr\x00\x00\x00");
    v.push_back(script);
    Spec boot = mk(Kind::File, "proc/boot/procnto-smp-instr", 0755, 0, 0, 1700000003u);
    boot.ino = 2;
    boot.ino_flags = 0xe0000000u;  // processed, runonce, bootstrap
    boot.data = pseudo_random(70000, 5);
    v.push_back(boot);
    Spec big = mk(Kind::File, "proc/boot/libc.so.5", 0755, 170, 170, 1700000004u);
    big.data.reserve(200000);
    for (int i = 0; i < 4000; ++i) {
        const std::string line = "libc line " + std::to_string(i) + " of a text that repeats\n";
        big.data.insert(big.data.end(), line.begin(), line.end());
    }
    v.push_back(big);
    Spec empty = mk(Kind::File, "etc/empty", 0600, 5, 6, 1700000005u);
    v.push_back(empty);
    Spec link = mk(Kind::Symlink, "dev/console", 01777, 0, 0, 1700000006u);
    link.target = "/dev/null";
    v.push_back(link);
    Spec ser = mk(Kind::Char, "dev/ser1", 0666, 0, 0, 1700000007u);
    ser.dev = 0x00000401u;
    ser.rdev = (5u << 10) | 1u;
    v.push_back(ser);
    Spec blk = mk(Kind::Block, "dev/hd0", 0660, 0, 0, 1700000008u);
    blk.rdev = (8u << 10) | 3u;
    v.push_back(blk);
    Spec fifo = mk(Kind::Fifo, "dev/pipe", 0644, 0, 0, 1700000009u);
    v.push_back(fifo);
    Spec xattr = mk(Kind::File, "etc/xattr.txt", 0644, 0, 0, 1700000010u);
    xattr.extattr = 12;
    xattr.data = bytes_of("x");
    v.push_back(xattr);
    return v;
}

IfsOptions sample_options(bool big = false, unsigned codec = 0) {
    IfsOptions o;
    o.big = big;
    o.codec = codec;
    o.script_ino = 3;
    o.boot_ino = 0xe0000002u;
    return o;
}

struct Walked {
    Status open;
    Status status;
    WalkResult result;
    FilesystemInfo info;
    std::map<std::string, EntryResult> by_path;
};

Walked walk_listing(const Bytes& img, WalkOptions opts = {}, bool hash = true) {
    Walked w;
    QnxIfsReader r;
    w.open = r.open(span_of(img));
    if (!w.open) return w;
    ListingSink sink(hash, opts.limits);
    w.status = r.walk(sink, opts, w.result);
    w.info = r.info();  // after the walk: a walk with tighter caps re-decompresses
    for (const EntryResult& e : w.result.entries_out) w.by_path[e.meta.path] = e;
    return w;
}

// ------------------------------------------------------------------ registry

TEST(QnxIfs, RegistryCreatesReader) {
    auto r = FilesystemRegistry::instance().create("qnx-ifs");
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->format(), "qnx-ifs");
}

// ------------------------------------------------------------------ synthetic

void check_sample_tree(const Walked& w, const std::vector<Spec>& specs) {
    ASSERT_TRUE(w.open) << w.open.error;
    ASSERT_TRUE(w.status) << w.status.error;
    EXPECT_EQ(w.result.entries, specs.size());
    EXPECT_EQ(w.result.files, 6u);
    EXPECT_EQ(w.result.dirs, 2u);
    EXPECT_EQ(w.result.symlinks, 1u);
    EXPECT_EQ(w.result.others, 3u);
    EXPECT_FALSE(w.result.truncated) << join_diags(w.result.diagnostics);
    EXPECT_FALSE(has_code(w.result.diagnostics, "qnx-ifs-startup-checksum-bad"))
        << join_diags(w.result.diagnostics);
    EXPECT_FALSE(has_code(w.result.diagnostics, "qnx-ifs-image-checksum-bad"))
        << join_diags(w.result.diagnostics);
    // Stored order, exactly.
    ASSERT_EQ(w.result.entries_out.size(), specs.size());
    for (std::size_t i = 0; i < specs.size(); ++i)
        EXPECT_EQ(w.result.entries_out[i].meta.path, specs[i].path) << i;

    const EntryResult& etc = w.by_path.at("etc");
    EXPECT_EQ(etc.meta.kind, EntryKind::Directory);
    EXPECT_EQ(etc.meta.mode, 0755u);
    EXPECT_EQ(etc.meta.inode, 2u);

    const EntryResult& passwd = w.by_path.at("etc/passwd");
    EXPECT_EQ(passwd.meta.kind, EntryKind::Regular);
    EXPECT_EQ(passwd.meta.mode, 0644u);
    EXPECT_EQ(passwd.meta.size, 26u);
    EXPECT_EQ(passwd.digests.bytes, 26u);
    EXPECT_EQ(passwd.digests.sha256, sha256_of(bytes_of("root:x:0:0:root:/:/bin/sh\n")));
    EXPECT_EQ(passwd.meta.mtime, 1700000001);
    EXPECT_EQ(passwd.meta.nlink, 1u);
    EXPECT_FALSE(passwd.meta.mtime_nsec.has_value());
    EXPECT_FALSE(passwd.meta.ctime.has_value());
    EXPECT_EQ(passwd.meta.extra.count("script"), 0u);
    EXPECT_NE(passwd.meta.extra.at("data_offset"), "");

    const EntryResult& script = w.by_path.at("proc/boot/.script");
    EXPECT_EQ(script.meta.inode, 3u);
    EXPECT_EQ(script.meta.extra.at("script"), "true");
    EXPECT_EQ(script.meta.mode, 0444u);
    EXPECT_EQ(script.digests.sha256, sha256_of(specs[3].data));

    const EntryResult& boot = w.by_path.at("proc/boot/procnto-smp-instr");
    EXPECT_EQ(boot.meta.inode, 2u);  // flag bits stripped
    EXPECT_EQ(boot.meta.extra.at("bootstrap"), "true");
    EXPECT_EQ(boot.meta.extra.at("processed_elf"), "true");
    EXPECT_EQ(boot.meta.extra.at("runonce_elf"), "true");
    EXPECT_EQ(boot.meta.extra.at("boot"), "true");
    EXPECT_EQ(boot.meta.size, 70000u);
    EXPECT_EQ(boot.digests.sha256, sha256_of(specs[4].data));

    const EntryResult& libc = w.by_path.at("proc/boot/libc.so.5");
    EXPECT_EQ(libc.meta.uid, 170u);
    EXPECT_EQ(libc.meta.gid, 170u);
    EXPECT_EQ(libc.meta.size, specs[5].data.size());
    EXPECT_EQ(libc.digests.sha256, sha256_of(specs[5].data));

    const EntryResult& empty = w.by_path.at("etc/empty");
    EXPECT_EQ(empty.meta.size, 0u);
    EXPECT_EQ(empty.meta.uid, 5u);
    EXPECT_EQ(empty.meta.gid, 6u);
    EXPECT_EQ(empty.digests.bytes, 0u);

    const EntryResult& link = w.by_path.at("dev/console");
    EXPECT_EQ(link.meta.kind, EntryKind::Symlink);
    EXPECT_EQ(link.meta.link_target, "/dev/null");
    EXPECT_EQ(link.meta.size, 9u);
    EXPECT_EQ(link.meta.mode, 01777u);

    const EntryResult& ser = w.by_path.at("dev/ser1");
    EXPECT_EQ(ser.meta.kind, EntryKind::CharDevice);
    EXPECT_EQ(ser.meta.rdev_major, 5u);
    EXPECT_EQ(ser.meta.rdev_minor, 1u);
    EXPECT_EQ(ser.meta.extra.at("dev"), "0x401");
    EXPECT_EQ(ser.meta.extra.at("rdev"), "0x1401");

    const EntryResult& hd = w.by_path.at("dev/hd0");
    EXPECT_EQ(hd.meta.kind, EntryKind::BlockDevice);
    EXPECT_EQ(hd.meta.rdev_major, 8u);
    EXPECT_EQ(hd.meta.rdev_minor, 3u);
    EXPECT_EQ(w.by_path.at("dev/pipe").meta.kind, EntryKind::Fifo);
    EXPECT_EQ(w.by_path.at("etc/xattr.txt").meta.extra.at("extattr_offset"), "12");

    EXPECT_EQ(w.info.format, "qnx-ifs");
    EXPECT_EQ(w.info.label, "/");
    EXPECT_EQ(w.info.attrs.at("mountpoint"), "/");
    EXPECT_EQ(w.info.attrs.at("machine"), "aarch64");
    EXPECT_EQ(w.info.attrs.at("version"), "1");
    EXPECT_EQ(w.info.attrs.at("entries"), std::to_string(specs.size()));
    EXPECT_EQ(w.info.attrs.at("files"), "6");
    EXPECT_EQ(w.info.attrs.at("dirs"), "2");
    EXPECT_EQ(w.info.attrs.at("symlinks"), "1");
    EXPECT_EQ(w.info.attrs.at("devices"), "3");
    EXPECT_EQ(w.info.attrs.at("script_ino"), "3");
    EXPECT_EQ(w.info.attrs.at("boot_ino"), "2");
    EXPECT_EQ(w.info.attrs.at("startup_checksum"), "ok");
    EXPECT_EQ(w.info.attrs.at("image_checksum"), "ok");
    EXPECT_EQ(w.info.attrs.at("root_mode"), "0x1ed");
    EXPECT_EQ(w.info.attrs.at("root_mtime"), "1700000000");
}

TEST(QnxIfs, SyntheticUncompressedLittleEndian) {
    const std::vector<Spec> specs = sample_specs();
    const Built b = build_ifs(specs, sample_options());
    const Walked w = walk_listing(b.img);
    check_sample_tree(w, specs);
    EXPECT_EQ(w.info.compression, "");
    EXPECT_EQ(w.info.attrs.at("compressed"), "none");
    EXPECT_EQ(w.info.size, b.stored_size);
    EXPECT_EQ(w.info.attrs.at("startup_size"), std::to_string(b.startup_size));
    EXPECT_EQ(w.info.attrs.at("stored_size"), std::to_string(b.stored_size));
    EXPECT_EQ(w.info.attrs.at("image_size"), std::to_string(b.image_size));
    EXPECT_EQ(w.info.attrs.at("hdr_dir_size"), std::to_string(b.hdr_dir_size));
    EXPECT_EQ(w.info.endian, Endian::Little);
    EXPECT_EQ(
        w.by_path.at("etc/passwd").meta.extra.at("data_offset"), "0x" + [&] {
            std::ostringstream s;
            s << std::hex << b.data_off[2];
            return s.str();
        }());
}

TEST(QnxIfs, SyntheticUncompressedBigEndian) {
    const std::vector<Spec> specs = sample_specs();
    const Built b = build_ifs(specs, sample_options(true));
    const Walked w = walk_listing(b.img);
    check_sample_tree(w, specs);
    EXPECT_EQ(w.info.endian, Endian::Big);
    EXPECT_EQ(w.info.attrs.at("endian"), "big");
}

TEST(QnxIfs, SyntheticUclCompressed) {
    const std::vector<Spec> specs = sample_specs();
    const Built b = build_ifs(specs, sample_options(false, 3));
    EXPECT_LT(b.img.size(), b.startup_size + b.image.size());  // it did compress
    const Walked w = walk_listing(b.img);
    check_sample_tree(w, specs);
    EXPECT_EQ(w.info.compression, "ucl");
    EXPECT_EQ(w.info.attrs.at("compressed"), "ucl");
    EXPECT_GE(std::stoul(w.info.attrs.at("blocks")), 6u);
    EXPECT_EQ(w.info.attrs.at("decompressed_bytes"), std::to_string(b.image.size()));
    EXPECT_EQ(w.info.size, b.stored_size);
    EXPECT_EQ(w.info.attrs.at("image_checksum"), "ok");
}

TEST(QnxIfs, SyntheticUclCompressedBigEndian) {
    const std::vector<Spec> specs = sample_specs();
    const Built b = build_ifs(specs, sample_options(true, 3));
    const Walked w = walk_listing(b.img);
    check_sample_tree(w, specs);
    EXPECT_EQ(w.info.attrs.at("compressed"), "ucl");
}

TEST(QnxIfs, HistoryOptionIsAcceptedAndIgnored) {
    const std::vector<Spec> specs = sample_specs();
    const Built b = build_ifs(specs, sample_options());
    WalkOptions opts;
    opts.history = true;
    const Walked w = walk_listing(b.img, opts);
    check_sample_tree(w, specs);
    EXPECT_EQ(w.result.superseded, 0u);
    EXPECT_EQ(w.result.deleted, 0u);
    EXPECT_TRUE(w.result.diagnostics.empty()) << join_diags(w.result.diagnostics);
}

TEST(QnxIfs, MetadataOnlyWalkStreamsNothing) {
    const Built b = build_ifs(sample_specs(), sample_options(false, 3));
    WalkOptions opts;
    opts.extract_data = false;
    const Walked w = walk_listing(b.img, opts);
    ASSERT_TRUE(w.status) << w.status.error;
    EXPECT_EQ(w.result.bytes, 0u);
    EXPECT_EQ(w.by_path.at("proc/boot/libc.so.5").meta.size, sample_specs()[5].data.size());
    EXPECT_EQ(w.by_path.at("proc/boot/libc.so.5").digests.bytes, 0u);
}

TEST(QnxIfs, DiskSinkExtractsTree) {
    const std::vector<Spec> specs = sample_specs();
    const Built b = build_ifs(specs, sample_options(false, 3));
    TempDir tmp;
    QnxIfsReader r;
    ASSERT_TRUE(r.open(span_of(b.img)));
    std::unique_ptr<DiskSink> sink;
    ASSERT_TRUE(DiskSink::open((tmp.path() / "files").string(), {}, sink));
    WalkResult out;
    ASSERT_TRUE(r.walk(*sink, {}, out));
    EXPECT_EQ(out.entries, specs.size());
    EXPECT_EQ(slurp(tmp.path() / "files/etc/passwd"), bytes_of("root:x:0:0:root:/:/bin/sh\n"));
    EXPECT_EQ(slurp(tmp.path() / "files/proc/boot/procnto-smp-instr"), specs[4].data);
    EXPECT_EQ(slurp(tmp.path() / "files/proc/boot/libc.so.5"), specs[5].data);
    EXPECT_TRUE(stdfs::is_empty(tmp.path() / "files/etc/empty"));
    EXPECT_TRUE(stdfs::is_symlink(tmp.path() / "files/dev/console"));
    EXPECT_EQ(stdfs::read_symlink(tmp.path() / "files/dev/console").string(), "/dev/null");
    EXPECT_FALSE(stdfs::exists(tmp.path() / "files/dev/ser1"));  // specials recorded, not created
    for (const EntryResult& e : out.entries_out) {
        if (e.meta.kind == EntryKind::Regular) {
            EXPECT_TRUE(e.written) << e.meta.path;
        }
    }
}

TEST(QnxIfs, WalkIsDeterministic) {
    const Built b = build_ifs(sample_specs(), sample_options(false, 3));
    const Walked a = walk_listing(b.img);
    const Walked c = walk_listing(b.img);
    ASSERT_EQ(a.result.entries_out.size(), c.result.entries_out.size());
    for (std::size_t i = 0; i < a.result.entries_out.size(); ++i) {
        EXPECT_EQ(a.result.entries_out[i].meta.path, c.result.entries_out[i].meta.path);
        EXPECT_EQ(a.result.entries_out[i].digests.sha256, c.result.entries_out[i].digests.sha256);
    }
    EXPECT_EQ(join_diags(a.result.diagnostics), join_diags(c.result.diagnostics));
}

TEST(QnxIfs, NoMapSourceStillStreams) {
    // A Source that refuses to map forces the bytes() fallback everywhere.
    class NoMap final : public Source {
       public:
        explicit NoMap(Bytes b) : b_(std::move(b)) {}
        std::uint64_t size() const override { return b_.size(); }
        std::string id() const override { return "nomap"; }
        std::size_t read(std::uint64_t off, std::span<std::uint8_t> out) const override {
            if (off >= b_.size()) return 0;
            const std::size_t n =
                std::min<std::size_t>(out.size(), b_.size() - static_cast<std::size_t>(off));
            std::memcpy(out.data(), b_.data() + off, n);
            return n;
        }
        std::span<const std::uint8_t> map(std::uint64_t, std::size_t) const override { return {}; }

       private:
        Bytes b_;
    };
    const std::vector<Spec> specs = sample_specs();
    for (const unsigned codec : {0u, 3u}) {
        const Built b = build_ifs(specs, sample_options(false, codec));
        QnxIfsReader r;
        ASSERT_TRUE(r.open(Span::whole(std::make_shared<NoMap>(b.img))));
        ListingSink sink(true);
        WalkResult out;
        ASSERT_TRUE(r.walk(sink, {}, out));
        Walked w;
        w.open = Status::success();
        w.status = Status::success();
        w.result = out;
        w.info = r.info();
        for (const EntryResult& e : out.entries_out) w.by_path[e.meta.path] = e;
        check_sample_tree(w, specs);
    }
}

// ------------------------------------------------------------------ hostile

TEST(QnxIfs, OpenRejectsNonInstances) {
    QnxIfsReader r;
    EXPECT_FALSE(r.open(span_of({})));
    EXPECT_FALSE(r.open(span_of(Bytes(1024, 0))));
    Bytes magic_only = {0xeb, 0x7e, 0xff, 0x00};
    EXPECT_FALSE(r.open(span_of(magic_only)));
    Bytes b = build_ifs(sample_specs(), sample_options()).img;
    put16(b, 4, 2, Endian::Little);  // version
    Status st = r.open(span_of(b));
    EXPECT_FALSE(st);
    EXPECT_EQ(st.error.rfind("qnx-ifs-bad-header", 0), 0u) << st.error;
    b = build_ifs(sample_specs(), sample_options()).img;
    put16(b, 8, 128, Endian::Little);  // header_size
    EXPECT_FALSE(r.open(span_of(b)));
    b = build_ifs(sample_specs(), sample_options()).img;
    b[6] = static_cast<std::uint8_t>(b[6] | 0x1c);  // compression code 7
    st = r.open(span_of(b));
    EXPECT_FALSE(st);
    EXPECT_EQ(st.error.rfind("qnx-ifs-unsupported-compression", 0), 0u) << st.error;
    WalkResult out;
    ListingSink sink;
    EXPECT_FALSE(r.walk(sink, {}, out));  // walk before open
}

TEST(QnxIfs, TruncatedAtEveryOffsetNeverCrashes) {
    for (const unsigned codec : {0u, 3u}) {
        std::vector<Spec> specs = sample_specs();
        specs.erase(specs.begin() + 5);  // drop the 200 KB file: keeps the loop short
        specs[4].data = pseudo_random(3000, 5);
        const Built b = build_ifs(specs, sample_options(false, codec));
        for (std::size_t n = 0; n < b.img.size(); n += (n < 2048 ? 1 : 37)) {
            QnxIfsReader r;
            const Status st = r.open(
                span_of(Bytes(b.img.begin(), b.img.begin() + static_cast<std::ptrdiff_t>(n))));
            if (!st) continue;
            ListingSink sink(true);
            WalkResult out;
            (void)r.walk(sink, {}, out);
            (void)r.info();
            EXPECT_LE(out.entries, specs.size());
        }
    }
}

TEST(QnxIfs, HdrDirSizePastImage) {
    const Built b = build_ifs(sample_specs(), sample_options());
    Bytes img = b.img;
    put32(img, b.startup_size + 12, 0x7fffffff, Endian::Little);
    const Walked w = walk_listing(img);
    ASSERT_TRUE(w.open) << w.open.error;
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-image-truncated"))
        << join_diags(w.result.diagnostics);
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-image-checksum-bad"));
    EXPECT_TRUE(w.result.truncated);
    // The real directory still walks: the file data after it is now read as
    // dirents and rejected.
    EXPECT_GE(w.result.entries, 3u);
    EXPECT_EQ(w.by_path.at("etc/passwd").digests.bytes, 26u);

    img = b.img;
    put32(img, b.startup_size + 12, 0xffffffff, Endian::Little);
    put32(img, b.startup_size + 8, 0xffffffff, Endian::Little);
    const Walked w2 = walk_listing(img);
    ASSERT_TRUE(w2.open) << w2.open.error;
    EXPECT_TRUE(w2.result.truncated);

    img = b.img;
    put32(img, b.startup_size + 16, 0xffffffff, Endian::Little);  // dir_offset > hdr_dir_size
    QnxIfsReader r;
    const Status st = r.open(span_of(img));
    EXPECT_FALSE(st);
    EXPECT_EQ(st.error.rfind("qnx-ifs-bad-image-header", 0), 0u) << st.error;
}

TEST(QnxIfs, FileOffsetPastImage) {
    const Built b = build_ifs(sample_specs(), sample_options());
    // etc/passwd is specs[2]: dirent body offset at +24, size at +28.
    Bytes img = b.img;
    const std::size_t de = static_cast<std::size_t>(b.startup_size + b.dirents[2]);
    put32(img, de + 28, 0xffffffff, Endian::Little);  // negative size
    Walked w = walk_listing(img);
    ASSERT_TRUE(w.open) << w.open.error;
    const EntryResult& p = w.by_path.at("etc/passwd");
    EXPECT_TRUE(p.truncated);
    EXPECT_TRUE(has_code(p.diagnostics, "qnx-ifs-file-out-of-range")) << join_diags(p.diagnostics);
    EXPECT_EQ(p.meta.size, 0xffffffffu);
    EXPECT_LT(p.digests.bytes, b.image.size());
    EXPECT_GT(p.digests.bytes, 0u);  // the prefix inside the image was recovered
    EXPECT_EQ(w.result.entries, sample_specs().size());  // the rest of the walk continued

    img = b.img;
    put32(img, de + 24, 0xfffffff0, Endian::Little);  // offset past the image
    w = walk_listing(img);
    const EntryResult& q = w.by_path.at("etc/passwd");
    EXPECT_TRUE(q.truncated);
    EXPECT_TRUE(has_code(q.diagnostics, "qnx-ifs-file-out-of-range"));
    EXPECT_EQ(q.digests.bytes, 0u);
}

TEST(QnxIfs, PathWithoutNulIsSkipped) {
    const Built b = build_ifs(sample_specs(), sample_options());
    Bytes img = b.img;
    const std::size_t de = static_cast<std::size_t>(b.startup_size + b.dirents[2]);
    const std::size_t esize = static_cast<std::size_t>(img[de] | (img[de + 1] << 8));
    for (std::size_t o = de + 32; o < de + esize; ++o) img[o] = 'A';  // path and padding
    const Walked w = walk_listing(img);
    ASSERT_TRUE(w.open) << w.open.error;
    EXPECT_EQ(w.by_path.count("etc/passwd"), 0u);
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-dirent-corrupt"))
        << join_diags(w.result.diagnostics);
    EXPECT_EQ(w.result.entries, sample_specs().size() - 1);  // later entries survive
    EXPECT_EQ(w.by_path.count("dev/console"), 1u);
}

TEST(QnxIfs, DirentSizesAbsurd) {
    const Built b = build_ifs(sample_specs(), sample_options());
    const std::size_t de = static_cast<std::size_t>(b.startup_size + b.dirents[2]);
    Bytes img = b.img;
    put16(img, de, 0xffff, Endian::Little);  // runs past the directory
    Walked w = walk_listing(img);
    ASSERT_TRUE(w.open) << w.open.error;
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-dirent-corrupt"));
    EXPECT_TRUE(w.result.truncated);
    EXPECT_EQ(w.result.entries, 2u);  // the two directories before it

    img = b.img;
    put16(img, de, 4, Endian::Little);  // below the attr size
    w = walk_listing(img);
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-dirent-corrupt"));
    EXPECT_EQ(w.result.entries, 2u);

    img = b.img;
    put16(img, de, 0, Endian::Little);  // end marker: the rest is not read
    w = walk_listing(img);
    EXPECT_EQ(w.result.entries, 2u);
    EXPECT_FALSE(has_code(w.result.diagnostics, "qnx-ifs-dirent-corrupt"));

    // A symlink whose target lies outside its entry.
    img = b.img;
    const std::size_t link = static_cast<std::size_t>(b.startup_size + b.dirents[7]);
    put16(img, link + 26, 0xffff, Endian::Little);  // sym_size
    w = walk_listing(img);
    const EntryResult& l = w.by_path.at("dev/console");
    EXPECT_EQ(l.meta.link_target, "");
    EXPECT_TRUE(has_code(l.diagnostics, "qnx-ifs-dirent-corrupt"));
    img = b.img;
    put16(img, link + 24, 0xffff, Endian::Little);  // sym_offset
    w = walk_listing(img);
    EXPECT_TRUE(has_code(w.by_path.at("dev/console").diagnostics, "qnx-ifs-dirent-corrupt"));

    // An entry with a mode of no known type, and one with inode 0.
    img = b.img;
    put32(img, de + 8, 0170000 | 0644, Endian::Little);
    w = walk_listing(img);
    EXPECT_EQ(w.by_path.count("etc/passwd"), 0u);
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-dirent-corrupt"));
    img = b.img;
    put32(img, de + 4, 0, Endian::Little);
    w = walk_listing(img);
    EXPECT_EQ(w.by_path.count("etc/passwd"), 0u);
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-entry-skipped"));
    EXPECT_EQ(w.info.attrs.at("skipped_entries"), "1");
    EXPECT_EQ(w.result.entries, sample_specs().size() - 1);
}

TEST(QnxIfs, StartupSizesAbsurd) {
    const Built b = build_ifs(sample_specs(), sample_options());
    QnxIfsReader r;
    for (const std::uint32_t v : {0u, 4u, 255u, 257u, 0xffffffffu, 0x80000000u}) {
        Bytes img = b.img;
        put32(img, 32, v, Endian::Little);
        EXPECT_FALSE(r.open(span_of(img))) << v;
    }
    // stored_size lies: the reader trusts the structures, not the count.
    Bytes img = b.img;
    put32(img, 36, 0xffffffff, Endian::Little);
    const Walked w = walk_listing(img);
    ASSERT_TRUE(w.open);
    EXPECT_EQ(w.result.entries, sample_specs().size());
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-startup-checksum-bad"));
}

TEST(QnxIfs, ChecksumMismatchesAreReportedNotFatal) {
    const Built b = build_ifs(sample_specs(), sample_options());
    Bytes img = b.img;
    img[300] ^= 0x55;  // inside the startup code
    Walked w = walk_listing(img);
    ASSERT_TRUE(w.open);
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-startup-checksum-bad"));
    EXPECT_EQ(w.info.attrs.at("startup_checksum"), "mismatch");
    EXPECT_EQ(w.info.attrs.at("image_checksum"), "ok");
    EXPECT_EQ(w.result.entries, sample_specs().size());

    img = b.img;
    img[7] = 1;  // flags2 set after mkifs: the residual is exactly flags2 << 24
    w = walk_listing(img);
    ASSERT_TRUE(w.open);
    bool noted = false;
    for (const Diagnostic& d : w.result.diagnostics)
        if (d.code == "qnx-ifs-startup-checksum-bad" &&
            d.message.find("flags2") != std::string::npos)
            noted = true;
    EXPECT_TRUE(noted) << join_diags(w.result.diagnostics);

    img = b.img;
    img[static_cast<std::size_t>(b.startup_size + b.data_off[2])] ^= 0x01;  // file data
    w = walk_listing(img);
    ASSERT_TRUE(w.open);
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-image-checksum-bad"));
    EXPECT_EQ(w.info.attrs.at("image_checksum"), "mismatch");
    EXPECT_EQ(w.info.attrs.at("startup_checksum"), "ok");
}

TEST(QnxIfs, CompressedBlockPastBuffer) {
    // A small image in 512-byte blocks, so a 0xffff length always runs past
    // the data.
    std::vector<Spec> specs = sample_specs();
    specs.erase(specs.begin() + 4, specs.begin() + 6);
    IfsOptions o = sample_options(false, 3);
    o.block_input = 512;
    const Built b = build_ifs(specs, o);
    ASSERT_GT(b.image.size(), 512u);  // at least two blocks
    // First block length past the data: nothing decodes, no image header.
    Bytes img = b.img;
    img[static_cast<std::size_t>(b.comp_start)] = 0xff;
    img[static_cast<std::size_t>(b.comp_start) + 1] = 0xff;
    QnxIfsReader r;
    Status st = r.open(span_of(img));
    EXPECT_FALSE(st);
    EXPECT_EQ(st.error.rfind("qnx-ifs-no-image-header", 0), 0u) << st.error;

    // A later block's length past the data: the prefix decodes, the chain
    // has no terminator, the directory is cut.
    img = b.img;
    std::size_t pos = static_cast<std::size_t>(b.comp_start);
    const std::size_t first = static_cast<std::size_t>(img[pos]) << 8 | img[pos + 1];
    pos += 2 + first;
    img[pos] = 0xff;
    img[pos + 1] = 0xff;
    const Walked w = walk_listing(img);
    ASSERT_TRUE(w.open) << w.open.error;
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-image-truncated"))
        << join_diags(w.result.diagnostics);
    EXPECT_TRUE(w.result.truncated);
    EXPECT_EQ(w.info.attrs.at("blocks"), "1");
    EXPECT_EQ(w.info.attrs.at("decompressed_bytes"), "512");

    // A corrupt block (an offset code that never ends): the decoded prefix
    // is kept, the failure reported.
    img = b.img;
    const std::size_t second = static_cast<std::size_t>(img[pos]) << 8 | img[pos + 1];
    for (std::size_t i = pos + 2; i < pos + 2 + std::min<std::size_t>(64, second); ++i) img[i] = 0;
    const Walked w2 = walk_listing(img);
    ASSERT_TRUE(w2.open) << w2.open.error;
    EXPECT_TRUE(has_code(w2.result.diagnostics, "qnx-ifs-decompress-failed"))
        << join_diags(w2.result.diagnostics);
    EXPECT_TRUE(w2.result.truncated);
    EXPECT_EQ(w2.info.attrs.at("decompress_failed"), "true");
    EXPECT_EQ(w2.info.attrs.at("decompressed_bytes"), "512");
}

TEST(QnxIfs, RatioBombIsCapped) {
    // A bomb block after the real image: 4 MiB of 'z' from 12 bytes. The
    // default cap is max_decompress_ratio x compressed bytes.
    // A small image keeps the compressed byte count, and so the cap, low.
    std::vector<Spec> specs = sample_specs();
    specs.erase(specs.begin() + 4, specs.begin() + 6);
    IfsOptions o = sample_options(false, 3);
    o.extra_block = nrv2b_bomb(4u << 20);
    const Built b = build_ifs(specs, o);
    const Walked w = walk_listing(b.img);
    ASSERT_TRUE(w.open) << w.open.error;
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-decompress-cap"))
        << join_diags(w.result.diagnostics);
    EXPECT_TRUE(w.result.truncated);
    EXPECT_EQ(w.info.attrs.at("decompress_capped"), "true");
    EXPECT_LT(std::stoull(w.info.attrs.at("decompressed_bytes")), 4ull << 20);
    EXPECT_EQ(w.result.entries, specs.size());  // the directory was intact

    // max_file_bytes caps the whole decompressed image too.
    const Built plain = build_ifs(sample_specs(), sample_options(false, 3));
    WalkOptions opts;
    opts.limits.max_file_bytes = 4096;
    const Walked w2 = walk_listing(plain.img, opts);
    ASSERT_TRUE(w2.open);
    EXPECT_TRUE(has_code(w2.result.diagnostics, "qnx-ifs-decompress-cap"))
        << join_diags(w2.result.diagnostics);
    EXPECT_TRUE(w2.result.truncated);
    EXPECT_LE(std::stoull(w2.info.attrs.at("decompressed_bytes")), 4096u + 0u);
}

TEST(QnxIfs, CompressedBlockCountEndsWithTheNodeBudget) {
    // Every compressed block is a metadata record: a chain of millions of
    // tiny blocks ends with max_nodes_per_fs, not with the end of the data.
    IfsOptions o = sample_options(false, 3);
    o.block_input = 512;
    const Built b = build_ifs(sample_specs(), o);
    ASSERT_GT(b.image.size(), 3u * 512u);
    WalkOptions opts;
    opts.limits.max_nodes_per_fs = 2;
    const Walked w = walk_listing(b.img, opts);
    ASSERT_TRUE(w.open) << w.open.error;
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-limit-blocks"))
        << join_diags(w.result.diagnostics);
    EXPECT_TRUE(w.result.truncated);
    EXPECT_EQ(w.info.attrs.at("blocks"), "2");
    EXPECT_EQ(w.info.attrs.at("decompressed_bytes"), "1024");
    EXPECT_EQ(w.info.attrs.at("decompress_capped"), "true");
}

TEST(QnxIfs, StartupDiagnosticSurvivesReDecompression) {
    const Built b = build_ifs(sample_specs(), sample_options(false, 3));
    Bytes img = b.img;
    img[300] ^= 0x55;  // inside the startup code
    WalkOptions opts;
    opts.limits.max_file_bytes = 1u << 20;  // not the default: walk() decompresses again
    const Walked w = walk_listing(img, opts);
    ASSERT_TRUE(w.open) << w.open.error;
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-startup-checksum-bad"))
        << join_diags(w.result.diagnostics);
    EXPECT_EQ(w.info.attrs.at("startup_checksum"), "mismatch");
    EXPECT_EQ(w.result.entries, sample_specs().size());
}

TEST(QnxIfs, LimitsTrip) {
    const Built b = build_ifs(sample_specs(), sample_options());
    WalkOptions opts;
    opts.limits.max_files = 3;
    Walked w = walk_listing(b.img, opts);
    EXPECT_EQ(w.result.entries, 3u);
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-limit-files"));
    EXPECT_TRUE(w.result.truncated);

    opts = WalkOptions{};
    opts.limits.max_nodes_per_fs = 4;  // root + three entries
    w = walk_listing(b.img, opts);
    EXPECT_EQ(w.result.entries, 3u);
    EXPECT_TRUE(has_code(w.result.diagnostics, "qnx-ifs-limit-nodes"));
    EXPECT_TRUE(w.result.truncated);

    opts = WalkOptions{};
    opts.limits.max_file_bytes = 10;
    w = walk_listing(b.img, opts);
    const EntryResult& p = w.by_path.at("etc/passwd");
    EXPECT_TRUE(p.truncated);
    EXPECT_TRUE(has_code(p.diagnostics, "qnx-ifs-limit-file-bytes"));
    EXPECT_EQ(p.digests.bytes, 10u);
    EXPECT_EQ(w.result.entries, sample_specs().size());
}

TEST(QnxIfs, RandomFlipsNeverCrash) {
    const Built b = build_ifs(sample_specs(), sample_options(false, 3));
    Bytes rnd = pseudo_random(4000, 99);
    for (std::size_t k = 0; k + 2 < rnd.size(); k += 2) {
        Bytes img = b.img;
        const std::size_t at = (static_cast<std::size_t>(rnd[k]) << 8 | rnd[k + 1]) % img.size();
        img[at] ^= static_cast<std::uint8_t>(rnd[k + 2] | 1);
        QnxIfsReader r;
        if (!r.open(span_of(img))) continue;
        ListingSink sink(true);
        WalkResult out;
        (void)r.walk(sink, {}, out);
    }
}

// ------------------------------------------------------------------ corpus

const std::string kCorpus = "/home/wrongbaud/projects/omnitrace-v2/corpus/";
const char* kDumpifs = "/home/wrongbaud/magnet-scratch/qnx-utils/dumpifs-linux/dumpifs";
const std::string kDumpifsEnv = "LD_LIBRARY_PATH=/usr/local/lib ";

struct DumpEntry {
    std::string kind;  // file, dir, symlink, device
    std::uint64_t size = 0;
    std::string target;
    std::uint32_t mode = 0, uid = 0, gid = 0, ino = 0, mtime = 0;
    bool attrs = false;
};

// Parse `dumpifs -v` output into path -> entry.
std::map<std::string, DumpEntry> parse_dumpifs(const std::string& text) {
    std::map<std::string, DumpEntry> out;
    std::istringstream in(text);
    std::string line;
    std::string last;
    static const std::set<std::string> skip = {
        "Startup-header", "startup.*", "Image-header", "Image-directory",
        "Root-dirent",    "*.boot",    "Name"};
    auto hex_or = [](const std::string& s, std::uint64_t dflt) {
        if (s.empty() || s.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
            return dflt;
        return static_cast<std::uint64_t>(std::stoull(s, nullptr, 16));
    };
    while (std::getline(in, line)) {
        if (line.rfind("                       ", 0) == 0) {
            // attribute line for the previous entry
            if (last.empty()) continue;
            DumpEntry& d = out[last];
            std::istringstream fields(line);
            std::string f;
            while (fields >> f) {
                const auto eq = f.find('=');
                if (eq == std::string::npos) continue;
                const std::string k = f.substr(0, eq), v = f.substr(eq + 1);
                if (k == "gid") d.gid = static_cast<std::uint32_t>(std::stoul(v));
                if (k == "uid") d.uid = static_cast<std::uint32_t>(std::stoul(v));
                if (k == "mode") d.mode = static_cast<std::uint32_t>(std::stoul(v, nullptr, 8));
                if (k == "ino") d.ino = static_cast<std::uint32_t>(std::stoul(v));
                if (k == "mtime") d.mtime = static_cast<std::uint32_t>(std::stoul(v, nullptr, 16));
            }
            d.attrs = true;
            continue;
        }
        last.clear();
        if (line.size() < 20 || line[0] != ' ') continue;
        std::istringstream fields(line);
        std::string off, size, name;
        if (!(fields >> off >> size >> name)) continue;
        if (skip.count(name)) continue;
        DumpEntry d;
        std::string rest;
        std::getline(fields, rest);
        if (off == "----" && size == "----") {
            if (rest.find(" dev=") != std::string::npos) {
                d.kind = "device";
            } else {
                d.kind = "dir";
            }
        } else if (off == "----") {
            d.kind = "symlink";
            d.size = hex_or(size, 0);
            const auto arrow = rest.find("-> ");
            if (arrow != std::string::npos) d.target = rest.substr(arrow + 3);
        } else {
            if (hex_or(off, ~0ull) == ~0ull) continue;  // not a listing line
            d.kind = "file";
            d.size = hex_or(size, 0);
        }
        out[name] = d;
        last = name;
    }
    return out;
}

std::optional<Span> corpus_slice(const std::string& rel, std::uint64_t off, std::uint64_t len,
                                 std::shared_ptr<MappedFile>& keep) {
    const std::string path = kCorpus + rel;
    if (!stdfs::exists(path)) return std::nullopt;
    if (!MappedFile::open(path, keep)) return std::nullopt;
    return Span::whole(keep).sub(off, len);
}

void write_slice(const Span& s, const stdfs::path& to) {
    std::ofstream out(to, std::ios::binary);
    std::vector<std::uint8_t> buf(1 << 20);
    for (std::uint64_t off = 0; off < s.size();) {
        const std::size_t n = s.read(off, buf);
        if (n == 0) break;
        out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(n));
        off += n;
    }
}

const char* kind_word(EntryKind k) {
    switch (k) {
        case EntryKind::Regular:
            return "file";
        case EntryKind::Directory:
            return "dir";
        case EntryKind::Symlink:
            return "symlink";
        default:
            return "device";
    }
}

// Compare a walk against dumpifs -v; extract with dumpifs -x when `extract`.
void compare_with_dumpifs(const Span& slice, const std::string& name, bool extract,
                          const std::string& expect_codec) {
    QnxIfsReader r;
    const Status opened = r.open(slice);
    ASSERT_TRUE(opened) << opened.error;
    ListingSink sink(true);
    WalkResult out;
    ASSERT_TRUE(r.walk(sink, {}, out));
    const FilesystemInfo info = r.info();
    EXPECT_EQ(info.attrs.at("compressed"), expect_codec);
    EXPECT_FALSE(out.truncated) << join_diags(out.diagnostics);
    EXPECT_GT(out.entries, 100u);
    EXPECT_EQ(info.attrs.at("image_checksum"), "ok");
    std::cout << "[  corpus  ] " << name << ": " << out.entries << " entries, " << out.files
              << " files, codec " << info.attrs.at("compressed") << ", startup checksum "
              << info.attrs.at("startup_checksum") << ", machine " << info.attrs.at("machine")
              << "\n";
    for (const Diagnostic& d : out.diagnostics)
        EXPECT_EQ(d.code, "qnx-ifs-startup-checksum-bad") << d.code << ": " << d.message;

    if (!tool_exists(kDumpifs)) {
        std::cout << "[  corpus  ] dumpifs not found; listing not cross-checked\n";
        return;
    }
    TempDir tmp;
    const stdfs::path img = tmp.path() / (name + ".bin");
    write_slice(slice, img);
    const stdfs::path listing = tmp.path() / "listing.txt";
    ASSERT_EQ(run(kDumpifsEnv + std::string(kDumpifs) + " -v " + img.string() + " > " +
                  listing.string() + " 2>/dev/null"),
              0);
    const Bytes text = slurp(listing);
    const std::map<std::string, DumpEntry> ref =
        parse_dumpifs(std::string(text.begin(), text.end()));
    ASSERT_GT(ref.size(), 100u);
    std::map<std::string, const EntryResult*> mine;
    for (const EntryResult& e : out.entries_out) mine[e.meta.path] = &e;
    EXPECT_EQ(mine.size(), ref.size());
    for (const auto& [path, d] : ref) {
        const auto it = mine.find(path);
        ASSERT_NE(it, mine.end()) << "dumpifs lists " << path << " and the reader does not";
        const FileMeta& m = it->second->meta;
        EXPECT_EQ(kind_word(m.kind), d.kind) << path;
        if (d.kind == "file" || d.kind == "symlink") {
            EXPECT_EQ(m.size, d.size) << path;
        }
        if (d.kind == "symlink") {
            EXPECT_EQ(m.link_target, d.target) << path;
        }
        if (d.kind == "file") {
            EXPECT_EQ(it->second->digests.bytes, d.size) << path;
        }
        ASSERT_TRUE(d.attrs) << path;
        EXPECT_EQ(m.mode, d.mode) << path;
        EXPECT_EQ(m.uid, d.uid) << path;
        EXPECT_EQ(m.gid, d.gid) << path;
        EXPECT_EQ(m.inode, d.ino & ~kInoFlagMask) << path;
        EXPECT_EQ(m.mtime, static_cast<std::int64_t>(d.mtime)) << path;
    }
    for (const auto& [path, e] : mine)
        EXPECT_EQ(ref.count(path), 1u) << "the reader lists " << path << " and dumpifs does not";
    if (!extract) return;

    // dumpifs creates neither directories nor symlinks: pre-create the tree.
    const stdfs::path outdir = tmp.path() / "x";
    stdfs::create_directories(outdir);
    for (const auto& [path, e] : mine)
        if (e->meta.kind == EntryKind::Regular)
            stdfs::create_directories(outdir / stdfs::path(path).parent_path());
    ASSERT_EQ(run(kDumpifsEnv + std::string(kDumpifs) + " -x -d " + outdir.string() + " " +
                  img.string() + " > /dev/null 2>&1"),
              0);
    std::size_t compared = 0;
    for (const auto& [path, e] : mine) {
        if (e->meta.kind != EntryKind::Regular) continue;
        const stdfs::path f = outdir / path;
        ASSERT_TRUE(stdfs::exists(f)) << path;
        EXPECT_EQ(e->digests.sha256, Hasher::of(slurp(f)).sha256) << path;
        compared++;
    }
    EXPECT_GT(compared, 50u);
    std::cout << "[  corpus  ] " << name << ": " << compared
              << " files byte-identical to dumpifs\n";
}

TEST(QnxIfsCorpus, IfsAMatchesDumpifs) {
    std::shared_ptr<MappedFile> keep;
    const auto slice =
        corpus_slice("qnx-example/flash/UserData.BIN", 0x12800000, 32ull << 20, keep);
    if (!slice) GTEST_SKIP() << "corpus image missing";
    compare_with_dumpifs(*slice, "ifs_a", true, "ucl");
}

TEST(QnxIfsCorpus, IfsRecoveryMatchesDumpifsListing) {
    std::shared_ptr<MappedFile> keep;
    const auto slice =
        corpus_slice("qnx-example/flash/UserData.BIN", 0x2800000, 256ull << 20, keep);
    if (!slice) GTEST_SKIP() << "corpus image missing";
    compare_with_dumpifs(*slice, "ifs_recovery", false, "ucl");
}

TEST(QnxIfsCorpus, HyundaiSplashMagicsAreNotImages) {
    // Two startup-header magics inside the 2 MiB splash partition sit in
    // compressed data; neither has a header behind it.
    std::shared_ptr<MappedFile> keep;
    const auto part =
        corpus_slice("auto-ivi-example/flash/UserData.BIN", 0x6e904400, 2ull << 20, keep);
    if (!part) GTEST_SKIP() << "corpus image missing";
    static constexpr std::uint8_t kMagic[] = {0xeb, 0x7e, 0xff, 0x00};
    std::size_t hits = 0;
    for (std::uint64_t off = 0; off + 4 <= part->size(); ++off) {
        if (!part->matches_at(off, kMagic)) continue;
        hits++;
        QnxIfsReader r;
        const Status st = r.open(part->sub(off));
        EXPECT_FALSE(st) << "offset " << off;
        EXPECT_EQ(st.error.rfind("qnx-ifs-bad-header", 0), 0u) << st.error;
    }
    EXPECT_EQ(hits, 2u);
}

}  // namespace
}  // namespace omnitrace::fs
