// jffs2_test.cpp — Jffs2Reader.
//
// Coverage:
//   1. Images assembled node by node in the test (both byte orders) with a
//      Python-free builder that writes correct CRCs: multi-fragment files,
//      overlapping fragment versions, zlib / rtime / lzo fragments, unlink and
//      recreate, rename, a deleted directory whose children become orphans,
//      a node with a bad CRC, an obsolete node, xattrs, devices.
//   2. History: superseded versions, deletion records, unlink records, the
//      per-inode version cap.
//   3. Hostile images: truncation at every offset, totlen 0 and past the span,
//      nsize/csize/dsize past their bounds, version wrap, a self-parent loop,
//      the node limit, decompression bombs. Nothing may crash; run this
//      binary under ASan+UBSan.
//   4. Fixtures under tests/fixtures/out (tree and history sections) and the
//      router.bin corpus (skipped when absent).
#include "../../../src/filesystems/jffs2/Jffs2Reader.h"

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
#include <set>
#include <span>
#include <string>
#include <vector>

#include "omnitrace/core/Compression.h"
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
        path_ = base / ("omnitrace-jffs2-" + std::to_string(pid) + "-" + std::to_string(counter++));
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

std::vector<std::uint8_t> bytes_of(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

std::string sha256_of(const std::vector<std::uint8_t>& d) {
    return Hasher::of(d).sha256;
}

Span span_of(std::vector<std::uint8_t> bytes, const std::string& label = "img") {
    return Span::whole(std::make_shared<MemorySource>(std::move(bytes), label));
}

// JFFS2 crc32: reflected 0xEDB88320, seed 0, no final xor. Written
// independently of the reader so a shared mistake cannot hide.
std::uint32_t jcrc(const std::uint8_t* p, std::size_t n, std::uint32_t crc = 0) {
    for (std::size_t i = 0; i < n; ++i) {
        crc ^= p[i];
        for (int k = 0; k < 8; ++k) crc = (crc & 1u) ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
    }
    return crc;
}
std::uint32_t jcrc(const std::vector<std::uint8_t>& v) {
    return jcrc(v.data(), v.size());
}

constexpr std::uint32_t kIfReg = 0100000, kIfDir = 0040000, kIfLnk = 0120000, kIfChr = 0020000,
                        kIfBlk = 0060000, kIfFifo = 0010000;
constexpr std::uint8_t kDtReg = 8, kDtDir = 4, kDtLnk = 10, kDtChr = 2, kDtBlk = 6, kDtFifo = 1;

// ------------------------------------------------------------------ image builder

struct InodeSpec {
    std::uint32_t ino = 0, version = 0, mode = kIfReg | 0644, isize = 0, offset = 0;
    std::uint16_t uid = 0, gid = 0;
    std::uint32_t atime = 1700000000u, mtime = 1700000000u, ctime = 1700000000u;
    std::uint8_t compr = 0;
    std::uint32_t dsize = 0;              // 0: len(data) for compr none
    std::vector<std::uint8_t> data;       // stored payload (compressed for compr != 0)
    bool bad_node_crc = false;            // corrupt node_crc
    bool bad_data_crc = false;            // corrupt data_crc
    bool obsolete = false;                // clear the ACCURATE bit in place
    std::optional<std::uint32_t> totlen;  // override totlen
    std::optional<std::uint32_t> csize;   // override csize
};

struct DirentSpec {
    std::uint32_t pino = 1, version = 0, ino = 0, mctime = 1700000000u;
    std::string name;
    std::uint8_t type = kDtReg;
    bool bad_node_crc = false;
    bool bad_name_crc = false;
    bool obsolete = false;
    std::optional<std::uint8_t> nsize;  // override nsize
};

class Builder {
   public:
    explicit Builder(Endian e = Endian::Little) : e_(e) {}

    void u8(std::uint8_t v) { img_.push_back(v); }
    void u16(std::uint16_t v) {
        if (e_ == Endian::Little) {
            u8(static_cast<std::uint8_t>(v & 0xff));
            u8(static_cast<std::uint8_t>(v >> 8));
        } else {
            u8(static_cast<std::uint8_t>(v >> 8));
            u8(static_cast<std::uint8_t>(v & 0xff));
        }
    }
    void u32(std::uint32_t v) {
        if (e_ == Endian::Little) {
            u16(static_cast<std::uint16_t>(v & 0xffff));
            u16(static_cast<std::uint16_t>(v >> 16));
        } else {
            u16(static_cast<std::uint16_t>(v >> 16));
            u16(static_cast<std::uint16_t>(v & 0xffff));
        }
    }
    void patch_u32(std::size_t at, std::uint32_t v) {
        const std::size_t end = img_.size();
        u32(v);
        std::copy(img_.begin() + static_cast<std::ptrdiff_t>(end), img_.end(),
                  img_.begin() + static_cast<std::ptrdiff_t>(at));
        img_.resize(end);
    }
    void align() {
        while (img_.size() % 4) u8(0xFF);
    }
    void erased(std::size_t n) { img_.insert(img_.end(), n, 0xFF); }
    void raw(const std::vector<std::uint8_t>& b) { img_.insert(img_.end(), b.begin(), b.end()); }

    // Header with hdr_crc; returns the node offset.
    std::size_t header(std::uint16_t type, std::uint32_t totlen, bool obsolete = false) {
        align();
        const std::size_t off = img_.size();
        u16(0x1985);
        u16(type);
        u32(totlen);
        const std::uint32_t crc = jcrc(img_.data() + off, 8);
        if (obsolete) {
            // Obsoleted in place: the CRC stays as computed with the bit set.
            const std::uint16_t t = static_cast<std::uint16_t>(type & ~0x2000u);
            const std::size_t end = img_.size();
            u16(t);
            img_[off + 2] = img_[end];
            img_[off + 3] = img_[end + 1];
            img_.resize(end);
        }
        u32(crc);
        return off;
    }

    std::size_t cleanmarker() { return header(0x2003, 12); }
    std::size_t padding(std::uint32_t totlen) {
        const std::size_t off = header(0x2004, totlen);
        img_.insert(img_.end(), totlen - 12, 0);
        return off;
    }

    std::size_t inode(const InodeSpec& s) {
        const std::uint32_t dsize =
            s.dsize != 0 || s.compr != 0 ? s.dsize : static_cast<std::uint32_t>(s.data.size());
        const std::uint32_t csize = s.csize ? *s.csize : static_cast<std::uint32_t>(s.data.size());
        const std::uint32_t totlen =
            s.totlen ? *s.totlen : static_cast<std::uint32_t>(68 + s.data.size());
        const std::size_t off = header(0xE002, totlen, s.obsolete);
        u32(s.ino);
        u32(s.version);
        u32(s.mode);
        u16(s.uid);
        u16(s.gid);
        u32(s.isize);
        u32(s.atime);
        u32(s.mtime);
        u32(s.ctime);
        u32(s.offset);
        u32(csize);
        u32(dsize);
        u8(s.compr);
        u8(0);   // usercompr
        u16(0);  // flags
        std::uint32_t data_crc = jcrc(s.data);
        if (s.bad_data_crc) data_crc ^= 0xDEADBEEFu;
        u32(data_crc);
        std::uint32_t node_crc = jcrc(img_.data() + off, 60);
        if (s.bad_node_crc) node_crc ^= 1u;
        u32(node_crc);
        raw(s.data);
        return off;
    }

    std::size_t dirent(const DirentSpec& s) {
        const std::uint32_t totlen = static_cast<std::uint32_t>(40 + s.name.size());
        const std::size_t off = header(0xE001, totlen, s.obsolete);
        u32(s.pino);
        u32(s.version);
        u32(s.ino);
        u32(s.mctime);
        u8(s.nsize ? *s.nsize : static_cast<std::uint8_t>(s.name.size()));
        u8(s.type);
        u8(0);
        u8(0);
        std::uint32_t node_crc = jcrc(img_.data() + off, 32);
        if (s.bad_node_crc) node_crc ^= 1u;
        u32(node_crc);
        std::uint32_t name_crc = jcrc(bytes_of(s.name));
        if (s.bad_name_crc) name_crc ^= 1u;
        u32(name_crc);
        raw(bytes_of(s.name));
        return off;
    }

    // xattr node: xid, version, prefix, name, value. xref: ino -> xid.
    std::size_t xattr(std::uint32_t xid, std::uint32_t version, std::uint8_t prefix,
                      const std::string& name, const std::string& value) {
        std::vector<std::uint8_t> data = bytes_of(name);
        data.push_back(0);
        const std::vector<std::uint8_t> v = bytes_of(value);
        data.insert(data.end(), v.begin(), v.end());
        const std::size_t off = header(0xE008, static_cast<std::uint32_t>(32 + data.size()));
        u32(xid);
        u32(version);
        u8(prefix);
        u8(static_cast<std::uint8_t>(name.size()));
        u16(static_cast<std::uint16_t>(value.size()));
        u32(jcrc(data));
        u32(jcrc(img_.data() + off, 28));
        raw(data);
        return off;
    }
    std::size_t xref(std::uint32_t ino, std::uint32_t xid, std::uint32_t xseqno) {
        const std::size_t off = header(0xE009, 28);
        u32(ino);
        u32(xid);
        u32(xseqno);
        u32(jcrc(img_.data() + off, 24));
        return off;
    }

    // Convenience: a regular file at `offset` in one uncompressed node.
    std::size_t file_node(std::uint32_t ino, std::uint32_t version, const std::string& data,
                          std::uint32_t isize, std::uint32_t offset = 0, std::uint32_t mode = 0644,
                          std::uint32_t when = 1700000000u) {
        InodeSpec s;
        s.ino = ino;
        s.version = version;
        s.mode = kIfReg | mode;
        s.isize = isize;
        s.offset = offset;
        s.data = bytes_of(data);
        s.atime = s.mtime = s.ctime = when;
        return inode(s);
    }
    std::size_t dir_node(std::uint32_t ino, std::uint32_t version, std::uint32_t mode = 0755,
                         std::uint32_t when = 1700000000u) {
        InodeSpec s;
        s.ino = ino;
        s.version = version;
        s.mode = kIfDir | mode;
        s.atime = s.mtime = s.ctime = when;
        return inode(s);
    }
    std::size_t link(std::uint32_t pino, std::uint32_t version, std::uint32_t ino,
                     const std::string& name, std::uint8_t type = kDtReg,
                     std::uint32_t when = 1700000000u) {
        DirentSpec d;
        d.pino = pino;
        d.version = version;
        d.ino = ino;
        d.name = name;
        d.type = type;
        d.mctime = when;
        return dirent(d);
    }
    std::size_t unlink(std::uint32_t pino, std::uint32_t version, const std::string& name,
                       std::uint8_t type = kDtReg, std::uint32_t when = 1700000000u) {
        return link(pino, version, 0, name, type, when);
    }

    std::vector<std::uint8_t> build() {
        align();
        return img_;
    }
    std::vector<std::uint8_t>& bytes() { return img_; }

   private:
    Endian e_;
    std::vector<std::uint8_t> img_;
};

// zlib stream with one stored (uncompressed) deflate block: valid input for
// Codec::Zlib without linking zlib into the test.
std::vector<std::uint8_t> zlib_stored(const std::vector<std::uint8_t>& in) {
    std::vector<std::uint8_t> out = {0x78, 0x01, 0x01};
    const std::uint16_t len = static_cast<std::uint16_t>(in.size());
    out.push_back(static_cast<std::uint8_t>(len & 0xff));
    out.push_back(static_cast<std::uint8_t>(len >> 8));
    out.push_back(static_cast<std::uint8_t>(~len & 0xff));
    out.push_back(static_cast<std::uint8_t>((~len >> 8) & 0xff));
    out.insert(out.end(), in.begin(), in.end());
    std::uint32_t a = 1, b = 0;
    for (const std::uint8_t c : in) {
        a = (a + c) % 65521;
        b = (b + a) % 65521;
    }
    const std::uint32_t adler = (b << 16) | a;
    for (int i = 3; i >= 0; --i)
        out.push_back(static_cast<std::uint8_t>((adler >> (8 * i)) & 0xff));
    return out;
}

// ------------------------------------------------------------------ walking

struct Walked {
    Status open_status;
    Status status;
    WalkResult result;
    std::map<std::string, EntryResult> live;  // path -> live entry
    std::vector<EntryResult> history;         // superseded or deleted, in order
    FilesystemInfo info;
};

Walked walk_listing(const Span& span, bool hash = true, WalkOptions opts = {}) {
    Walked w;
    Jffs2Reader r;
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

WalkOptions history_opts() {
    WalkOptions o;
    o.history = true;
    return o;
}

const EntryResult* find_version(const Walked& w, const std::string& path, std::uint64_t version,
                                bool deleted) {
    for (const EntryResult& e : w.history)
        if (e.meta.path == path && e.meta.version == version && e.meta.deleted == deleted)
            return &e;
    return nullptr;
}

// A small but complete image: root children hello.txt (two fragments), sub/
// with a symlink, a char device (old 2-byte encoding), a block device (new
// 4-byte encoding) and a fifo.
std::vector<std::uint8_t> synth_image(Endian e) {
    Builder b(e);
    b.cleanmarker();
    b.dir_node(1, 1, 0755, 1700000001u);
    // hello.txt = "hello " + "world\n": two nodes, second at offset 6
    b.file_node(2, 1, "hello ", 6, 0, 0644, 1700000002u);
    b.file_node(2, 2, "world\n", 12, 6, 0644, 1700000003u);
    b.link(1, 1, 2, "hello.txt", kDtReg, 1700000002u);
    // sub/
    b.dir_node(3, 1, 0700, 1700000004u);
    b.link(1, 2, 3, "sub", kDtDir, 1700000004u);
    {
        InodeSpec s;
        s.ino = 4;
        s.version = 1;
        s.mode = kIfLnk | 0777;
        s.data = bytes_of("../hello.txt");
        s.isize = 12;
        s.uid = 1000;
        s.gid = 100;
        s.mtime = s.ctime = s.atime = 1700000005u;
        b.inode(s);
        b.link(3, 1, 4, "link", kDtLnk, 1700000005u);
    }
    {
        InodeSpec s;  // char device 5:1, old encoding (major << 8 | minor)
        s.ino = 5;
        s.version = 1;
        s.mode = kIfChr | 0600;
        s.data = e == Endian::Little ? std::vector<std::uint8_t>{0x01, 0x05}
                                     : std::vector<std::uint8_t>{0x05, 0x01};
        s.isize = 2;
        b.inode(s);
        b.link(1, 3, 5, "dev", kDtChr);
    }
    {
        InodeSpec s;  // block device 8:17, new encoding (minor & 0xff | major << 8 | ...)
        s.ino = 6;
        s.version = 1;
        s.mode = kIfBlk | 0660;
        const std::uint32_t v = (8u << 8) | 17u;  // new_encode_dev(8, 17)
        s.data = e == Endian::Little
                     ? std::vector<std::uint8_t>{static_cast<std::uint8_t>(v & 0xff),
                                                 static_cast<std::uint8_t>((v >> 8) & 0xff),
                                                 static_cast<std::uint8_t>((v >> 16) & 0xff),
                                                 static_cast<std::uint8_t>(v >> 24)}
                     : std::vector<std::uint8_t>{static_cast<std::uint8_t>(v >> 24),
                                                 static_cast<std::uint8_t>((v >> 16) & 0xff),
                                                 static_cast<std::uint8_t>((v >> 8) & 0xff),
                                                 static_cast<std::uint8_t>(v & 0xff)};
        s.isize = 4;
        b.inode(s);
        b.link(1, 4, 6, "blk", kDtBlk);
    }
    {
        InodeSpec s;
        s.ino = 7;
        s.version = 1;
        s.mode = kIfFifo | 0644;
        b.inode(s);
        b.link(3, 2, 7, "fifo", kDtFifo);
    }
    b.erased(64);
    return b.build();
}

// ------------------------------------------------------------------ synthetic

class Jffs2Synth : public ::testing::TestWithParam<Endian> {};

TEST_P(Jffs2Synth, LiveTreeAndMetadata) {
    const Endian e = GetParam();
    const Walked w = walk_listing(span_of(synth_image(e)));
    ASSERT_TRUE(w.status.ok) << w.status.error << join_diags(w.result.diagnostics);
    EXPECT_EQ(w.info.endian, e);
    EXPECT_EQ(w.info.attrs.at("endian"), e == Endian::Little ? "little" : "big");
    EXPECT_EQ(w.info.attrs.at("cleanmarkers"), "1");
    EXPECT_EQ(w.info.attrs.at("inode_nodes"), "8");
    EXPECT_EQ(w.info.attrs.at("dirent_nodes"), "6");
    for (const Diagnostic& d : w.result.diagnostics)
        EXPECT_NE(d.severity, Severity::Warning) << d.code << ": " << d.message;
    EXPECT_EQ(w.result.entries, 6u);
    EXPECT_EQ(w.result.files, 1u);
    EXPECT_EQ(w.result.dirs, 1u);
    EXPECT_EQ(w.result.symlinks, 1u);
    EXPECT_EQ(w.result.others, 3u);
    EXPECT_EQ(w.result.superseded, 0u);
    EXPECT_EQ(w.result.deleted, 0u);

    // Deterministic order: names sorted bytewise within a directory, depth first.
    std::vector<std::string> order;
    for (const EntryResult& r : w.result.entries_out) order.push_back(r.meta.path);
    ASSERT_EQ(order.size(), 6u);
    EXPECT_EQ(order[0], "blk");
    EXPECT_EQ(order[1], "dev");
    EXPECT_EQ(order[2], "hello.txt");
    EXPECT_EQ(order[3], "sub");
    EXPECT_EQ(order[4], "sub/fifo");
    EXPECT_EQ(order[5], "sub/link");

    const EntryResult& hello = w.live.at("hello.txt");
    EXPECT_EQ(hello.meta.kind, EntryKind::Regular);
    EXPECT_EQ(hello.meta.mode, 0644u);
    EXPECT_EQ(hello.meta.size, 12u);
    EXPECT_EQ(hello.meta.inode, 2u);
    EXPECT_EQ(hello.meta.nlink, 1u);
    EXPECT_EQ(hello.meta.version, 2u);
    EXPECT_EQ(hello.meta.mtime.value_or(0), 1700000003);
    EXPECT_EQ(hello.meta.atime.value_or(0), 1700000003);
    EXPECT_EQ(hello.meta.ctime.value_or(0), 1700000003);
    EXPECT_EQ(hello.meta.extra.at("nodes"), "2");
    EXPECT_EQ(hello.meta.extra.at("compression"), "none");
    EXPECT_EQ(hello.digests.sha256, sha256_of(bytes_of("hello world\n")));
    EXPECT_FALSE(hello.truncated);

    const EntryResult& sub = w.live.at("sub");
    EXPECT_EQ(sub.meta.kind, EntryKind::Directory);
    EXPECT_EQ(sub.meta.mode, 0700u);
    EXPECT_EQ(sub.meta.inode, 3u);
    EXPECT_EQ(sub.meta.size, 0u);

    const EntryResult& link = w.live.at("sub/link");
    EXPECT_EQ(link.meta.kind, EntryKind::Symlink);
    EXPECT_EQ(link.meta.link_target, "../hello.txt");
    EXPECT_EQ(link.meta.size, 12u);
    EXPECT_EQ(link.meta.uid, 1000u);
    EXPECT_EQ(link.meta.gid, 100u);
    EXPECT_EQ(link.meta.mode, 0777u);

    const EntryResult& dev = w.live.at("dev");
    EXPECT_EQ(dev.meta.kind, EntryKind::CharDevice);
    EXPECT_EQ(dev.meta.rdev_major, 5u);
    EXPECT_EQ(dev.meta.rdev_minor, 1u);
    const EntryResult& blk = w.live.at("blk");
    EXPECT_EQ(blk.meta.kind, EntryKind::BlockDevice);
    EXPECT_EQ(blk.meta.rdev_major, 8u);
    EXPECT_EQ(blk.meta.rdev_minor, 17u);
    EXPECT_EQ(w.live.at("sub/fifo").meta.kind, EntryKind::Fifo);
}

INSTANTIATE_TEST_SUITE_P(ByteOrders, Jffs2Synth, ::testing::Values(Endian::Little, Endian::Big));

TEST(Jffs2Synth, DiskSinkWritesTheTree) {
    TempDir tmp;
    std::unique_ptr<DiskSink> sink;
    ASSERT_TRUE(DiskSink::open((tmp.path() / "out").string(), {}, sink).ok);
    Jffs2Reader r;
    ASSERT_TRUE(r.open(span_of(synth_image(Endian::Little))).ok);
    WalkResult out;
    ASSERT_TRUE(r.walk(*sink, {}, out).ok);
    std::ifstream in(tmp.path() / "out" / "hello.txt", std::ios::binary);
    const std::string got((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_EQ(got, "hello world\n");
    EXPECT_TRUE(stdfs::is_directory(tmp.path() / "out" / "sub"));
    EXPECT_TRUE(stdfs::is_symlink(tmp.path() / "out" / "sub" / "link"));
}

TEST(Jffs2Synth, RegistryCreatesReader) {
    auto r = FilesystemRegistry::instance().create("jffs2");
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->format(), "jffs2");
}

TEST(Jffs2Synth, OpenRejectsNonInstances) {
    Jffs2Reader r;
    EXPECT_FALSE(r.open(span_of({})).ok);
    EXPECT_FALSE(r.open(span_of(std::vector<std::uint8_t>(4096, 0xFF))).ok);
    EXPECT_FALSE(r.open(span_of(bytes_of("this is not a jffs2 image at all, sorry"))).ok);
    std::vector<std::uint8_t> bad_crc = {0x85, 0x19, 0x03, 0x20, 12, 0, 0, 0, 1, 2, 3, 4};
    EXPECT_FALSE(r.open(span_of(bad_crc)).ok);
    WalkResult out;
    ListingSink sink;
    EXPECT_FALSE(r.walk(sink, {}, out).ok);  // walk before open
}

TEST(Jffs2Synth, OverlappingFragmentVersions) {
    Builder b;
    b.dir_node(1, 1);
    b.file_node(2, 1, "AAAAAAAAAA", 10, 0, 0644, 100);
    b.file_node(2, 2, "bb", 10, 3, 0644, 200);
    b.file_node(2, 3, "cccc", 12, 8, 0644, 300);  // extends the file
    b.link(1, 1, 2, "f");
    const Walked w = walk_listing(span_of(b.build()), true, history_opts());
    ASSERT_TRUE(w.status.ok) << w.status.error;
    const EntryResult& f = w.live.at("f");
    EXPECT_EQ(f.meta.size, 12u);
    EXPECT_EQ(f.digests.sha256, sha256_of(bytes_of("AAAbbAAAcccc")));
    EXPECT_EQ(f.meta.version, 3u);
    EXPECT_EQ(f.meta.mtime.value_or(0), 300);
    EXPECT_EQ(w.result.superseded, 2u);
    const EntryResult* v1 = find_version(w, "f", 1, false);
    ASSERT_NE(v1, nullptr);
    EXPECT_TRUE(v1->meta.superseded);
    EXPECT_EQ(v1->meta.size, 10u);
    EXPECT_EQ(v1->meta.mtime.value_or(0), 100);
    EXPECT_EQ(v1->digests.sha256, sha256_of(bytes_of("AAAAAAAAAA")));
    const EntryResult* v2 = find_version(w, "f", 2, false);
    ASSERT_NE(v2, nullptr);
    EXPECT_EQ(v2->digests.sha256, sha256_of(bytes_of("AAAbbAAAAA")));
    // Without history nothing historical is emitted.
    const Walked plain = walk_listing(span_of(b.build()));
    EXPECT_EQ(plain.result.superseded, 0u);
    EXPECT_TRUE(plain.history.empty());
}

TEST(Jffs2Synth, OneWriteSplitIntoPagesIsOneVersion) {
    Builder b;
    b.dir_node(1, 1);
    // One write of "abcdefghij" split into three nodes with the same times.
    b.file_node(2, 1, "abcd", 4, 0, 0644, 100);
    b.file_node(2, 2, "efgh", 8, 4, 0644, 100);
    b.file_node(2, 3, "ij", 10, 8, 0644, 100);
    // A later append is a new write (different mtime).
    b.file_node(2, 4, "KL", 12, 10, 0644, 200);
    // A metadata-only node (chmod) is a version of its own.
    {
        InodeSpec s;
        s.ino = 2;
        s.version = 5;
        s.mode = kIfReg | 0600;
        s.isize = 12;
        s.mtime = 200;
        s.ctime = 300;
        b.inode(s);
    }
    b.link(1, 1, 2, "f");
    const Walked w = walk_listing(span_of(b.build()), true, history_opts());
    ASSERT_TRUE(w.status.ok);
    EXPECT_EQ(w.live.at("f").meta.mode, 0600u);
    EXPECT_EQ(w.live.at("f").digests.sha256, sha256_of(bytes_of("abcdefghijKL")));
    EXPECT_EQ(w.result.superseded, 2u);
    const EntryResult* v3 = find_version(w, "f", 3, false);
    ASSERT_NE(v3, nullptr) << "the run v1..v3 is one version, named after its last node";
    EXPECT_EQ(v3->digests.sha256, sha256_of(bytes_of("abcdefghij")));
    EXPECT_EQ(v3->meta.extra.at("nodes"), "3");
    const EntryResult* v4 = find_version(w, "f", 4, false);
    ASSERT_NE(v4, nullptr);
    EXPECT_EQ(v4->meta.mode, 0644u);
    EXPECT_EQ(v4->digests.sha256, sha256_of(bytes_of("abcdefghijKL")));
    EXPECT_EQ(find_version(w, "f", 1, false), nullptr);
    EXPECT_EQ(find_version(w, "f", 2, false), nullptr);
}

TEST(Jffs2Synth, TruncateThenRewriteAndHoles) {
    Builder b;
    b.dir_node(1, 1);
    b.file_node(2, 1, "0123456789", 10, 0);
    {
        InodeSpec t;  // truncate to 0: metadata-only node with isize 0
        t.ino = 2;
        t.version = 2;
        t.isize = 0;
        b.inode(t);
    }
    b.file_node(2, 3, "xy", 6, 4);  // hole [0,4) then "xy"
    b.link(1, 1, 2, "f");
    const Walked w = walk_listing(span_of(b.build()), true, history_opts());
    ASSERT_TRUE(w.status.ok);
    const EntryResult& f = w.live.at("f");
    EXPECT_EQ(f.meta.size, 6u);
    EXPECT_EQ(f.digests.sha256, sha256_of({0, 0, 0, 0, 'x', 'y'}));
    const EntryResult* v2 = find_version(w, "f", 2, false);
    ASSERT_NE(v2, nullptr);
    EXPECT_EQ(v2->meta.size, 0u);
    // isize beyond the data: zero-filled, noted.
    Builder c;
    c.dir_node(1, 1);
    c.file_node(2, 1, "ab", 5, 0);
    c.link(1, 1, 2, "g");
    const Walked w2 = walk_listing(span_of(c.build()));
    const EntryResult& g = w2.live.at("g");
    EXPECT_EQ(g.digests.sha256, sha256_of({'a', 'b', 0, 0, 0}));
    EXPECT_TRUE(has_code(g.diagnostics, "jffs2-isize-exceeds-data"));
}

TEST(Jffs2Synth, CompressedFragments) {
    Builder b;
    b.dir_node(1, 1);
    // zlib (stored block) at [0,8)
    {
        InodeSpec s;
        s.ino = 2;
        s.version = 1;
        s.compr = 6;
        s.data = zlib_stored(bytes_of("zlibzlib"));
        s.dsize = 8;
        s.isize = 8;
        b.inode(s);
    }
    // rtime: (value, repeat) pairs; "AAAA" = 41 00 41 02
    {
        InodeSpec s;
        s.ino = 2;
        s.version = 2;
        s.compr = 2;
        s.offset = 8;
        s.data = {0x41, 0x00, 0x41, 0x02};
        s.dsize = 4;
        s.isize = 12;
        b.inode(s);
    }
    // lzo: literal run of 5 ("hello") then the EOF marker
    {
        InodeSpec s;
        s.ino = 2;
        s.version = 3;
        s.compr = 7;
        s.offset = 12;
        s.data = {0x16, 'h', 'e', 'l', 'l', 'o', 0x11, 0x00, 0x00};
        s.dsize = 5;
        s.isize = 17;
        b.inode(s);
    }
    // zero: 3 bytes of zeros with no payload
    {
        InodeSpec s;
        s.ino = 2;
        s.version = 4;
        s.compr = 1;
        s.offset = 17;
        s.dsize = 3;
        s.isize = 20;
        b.inode(s);
    }
    b.link(1, 1, 2, "mixed");
    const Walked w = walk_listing(span_of(b.build()));
    ASSERT_TRUE(w.status.ok);
    for (const Diagnostic& d : w.result.diagnostics)
        EXPECT_NE(d.severity, Severity::Warning) << d.code << ": " << d.message;
    const EntryResult& m = w.live.at("mixed");
    EXPECT_EQ(m.meta.size, 20u);
    EXPECT_FALSE(m.truncated) << join_diags(m.diagnostics);
    EXPECT_EQ(m.digests.sha256,
              sha256_of(bytes_of(std::string("zlibzlibAAAAhello") + std::string(3, '\0'))));
    EXPECT_EQ(m.meta.extra.at("compression"), "zero,rtime,zlib,lzo");
    EXPECT_EQ(w.info.compression, "zero,rtime,zlib,lzo");
}

TEST(Jffs2Synth, UnsupportedCompressionZeroFillsAndMarks) {
    Builder b;
    b.dir_node(1, 1);
    InodeSpec s;
    s.ino = 2;
    s.version = 1;
    s.compr = 5;  // dynrubin
    s.data = {1, 2, 3, 4};
    s.dsize = 4;
    s.isize = 4;
    b.inode(s);
    b.link(1, 1, 2, "rubin");
    const Walked w = walk_listing(span_of(b.build()));
    const EntryResult& r = w.live.at("rubin");
    EXPECT_TRUE(r.truncated);
    EXPECT_TRUE(has_code(r.diagnostics, "jffs2-unsupported-compression"));
    EXPECT_TRUE(has_code(w.result.diagnostics, "jffs2-unsupported-compression"));
    EXPECT_EQ(r.digests.sha256, sha256_of({0, 0, 0, 0}));
    // A corrupt zlib stream: decompress failure, same handling.
    Builder c;
    c.dir_node(1, 1);
    s.compr = 6;
    s.data = {0x78, 0x9c, 0xff, 0xff, 0xff};
    c.inode(s);
    c.link(1, 1, 2, "z");
    const Walked w2 = walk_listing(span_of(c.build()));
    EXPECT_TRUE(has_code(w2.live.at("z").diagnostics, "jffs2-decompress-failed"));
    EXPECT_TRUE(w2.live.at("z").truncated);
}

TEST(Jffs2Synth, UnlinkThenRecreateWithNewInode) {
    Builder b;
    b.dir_node(1, 1);
    b.file_node(2, 1, "first", 5, 0, 0644, 100);
    b.link(1, 1, 2, "f", kDtReg, 100);
    b.unlink(1, 2, "f", kDtReg, 200);
    b.file_node(3, 1, "second!", 7, 0, 0644, 300);
    b.link(1, 3, 3, "f", kDtReg, 300);
    const Walked w = walk_listing(span_of(b.build()), true, history_opts());
    ASSERT_TRUE(w.status.ok);
    ASSERT_EQ(w.live.count("f"), 1u);
    EXPECT_EQ(w.live.at("f").meta.inode, 3u);
    EXPECT_EQ(w.live.at("f").digests.sha256, sha256_of(bytes_of("second!")));
    EXPECT_EQ(w.result.deleted, 1u);
    EXPECT_EQ(w.result.superseded, 0u);
    ASSERT_EQ(w.history.size(), 1u);
    const EntryResult& d = w.history[0];
    EXPECT_TRUE(d.meta.deleted);
    EXPECT_FALSE(d.meta.superseded);
    EXPECT_EQ(d.meta.path, "f");
    EXPECT_EQ(d.meta.inode, 2u);
    EXPECT_EQ(d.meta.version, 1u);
    EXPECT_EQ(d.meta.nlink, 0u);
    EXPECT_EQ(d.digests.sha256, sha256_of(bytes_of("first")));
    EXPECT_EQ(w.info.attrs.at("inodes_live"), "2");  // root and ino 3
    EXPECT_EQ(w.info.attrs.at("inodes_deleted"), "1");
}

TEST(Jffs2Synth, UnlinkRecordWhenNoInodeNodeRemains) {
    Builder b;
    b.dir_node(1, 1);
    b.link(1, 1, 9, "gone", kDtReg, 100);  // inode 9 has no nodes at all
    b.unlink(1, 2, "gone", kDtReg, 200);
    const Walked w = walk_listing(span_of(b.build()), true, history_opts());
    ASSERT_TRUE(w.status.ok);
    EXPECT_TRUE(w.live.empty());
    ASSERT_EQ(w.history.size(), 1u);
    const EntryResult& u = w.history[0];
    EXPECT_TRUE(u.meta.deleted);
    EXPECT_EQ(u.meta.path, "gone");
    EXPECT_EQ(u.meta.size, 0u);
    EXPECT_EQ(u.meta.version, 2u);
    EXPECT_EQ(u.meta.mtime.value_or(0), 200);
    EXPECT_EQ(u.meta.extra.at("record"), "unlink");
    EXPECT_EQ(w.info.attrs.at("unlink_dirents"), "1");
}

TEST(Jffs2Synth, RenameKeepsInodeLiveAndRecordsOldName) {
    Builder b;
    b.dir_node(1, 1);
    b.file_node(2, 1, "data", 4);
    b.link(1, 1, 2, "old", kDtReg, 100);
    b.link(1, 2, 2, "new", kDtReg, 200);
    b.unlink(1, 3, "old", kDtReg, 200);
    const Walked w = walk_listing(span_of(b.build()), true, history_opts());
    ASSERT_TRUE(w.status.ok);
    ASSERT_EQ(w.live.size(), 1u);
    EXPECT_EQ(w.live.count("new"), 1u);
    EXPECT_EQ(w.live.at("new").meta.nlink, 1u);
    // The inode is live, so the old name is an unlink record only.
    ASSERT_EQ(w.history.size(), 1u);
    EXPECT_EQ(w.history[0].meta.path, "old");
    EXPECT_EQ(w.history[0].meta.extra.at("record"), "unlink");
    EXPECT_EQ(w.result.deleted, 1u);
    // Rename over an existing target: the target's inode loses its only name.
    Builder c;
    c.dir_node(1, 1);
    c.file_node(2, 1, "src", 3);
    c.file_node(3, 1, "dst", 3);
    c.link(1, 1, 2, "a", kDtReg, 100);
    c.link(1, 2, 3, "b", kDtReg, 100);
    c.link(1, 3, 2, "b", kDtReg, 200);  // a -> b
    c.unlink(1, 4, "a", kDtReg, 200);
    const Walked w2 = walk_listing(span_of(c.build()), true, history_opts());
    EXPECT_EQ(w2.live.at("b").meta.inode, 2u);
    const EntryResult* lost = find_version(w2, "b", 1, true);
    ASSERT_NE(lost, nullptr);
    EXPECT_EQ(lost->meta.inode, 3u);
    EXPECT_EQ(lost->digests.sha256, sha256_of(bytes_of("dst")));
}

TEST(Jffs2Synth, DeletedDirectoryChildrenKeepTheirPath) {
    Builder b;
    b.dir_node(1, 1);
    b.dir_node(2, 1, 0755, 100);
    b.link(1, 1, 2, "d", kDtDir, 100);
    b.file_node(3, 1, "child", 5);
    b.link(2, 1, 3, "c", kDtReg, 100);
    b.unlink(2, 2, "c", kDtReg, 200);
    b.unlink(1, 2, "d", kDtDir, 201);
    const Walked w = walk_listing(span_of(b.build()), true, history_opts());
    ASSERT_TRUE(w.status.ok);
    EXPECT_TRUE(w.live.empty());
    const EntryResult* d = find_version(w, "d", 1, true);
    ASSERT_NE(d, nullptr);
    EXPECT_EQ(d->meta.kind, EntryKind::Directory);
    const EntryResult* c = find_version(w, "d/c", 1, true);
    ASSERT_NE(c, nullptr);
    EXPECT_EQ(c->digests.sha256, sha256_of(bytes_of("child")));
    EXPECT_EQ(w.result.deleted, 2u);  // the unlink records are covered by the inodes
    // A file whose parent was never named anywhere: lost+found.
    Builder o;
    o.dir_node(1, 1);
    o.file_node(7, 1, "orphan", 6);
    o.file_node(8, 1, "nameless-parent", 15);
    o.link(42, 1, 8, "x", kDtReg);
    const Walked w2 = walk_listing(span_of(o.build()), true, history_opts());
    ASSERT_NE(find_version(w2, "lost+found/#7", 1, true), nullptr);
    ASSERT_NE(find_version(w2, "lost+found/#42/x", 1, true), nullptr);
    EXPECT_TRUE(has_code(w2.result.diagnostics, "jffs2-orphan-inode"));
    EXPECT_EQ(find_version(w2, "lost+found/#7", 1, true)->meta.extra.at("orphan"), "true");
}

TEST(Jffs2Synth, BadCrcNodesAreHistoryOnly) {
    Builder b;
    b.dir_node(1, 1);
    b.file_node(2, 1, "good", 4, 0, 0644, 100);
    {
        InodeSpec s;
        s.ino = 2;
        s.version = 2;
        s.isize = 3;
        s.data = bytes_of("bad");
        s.bad_node_crc = true;
        b.inode(s);
    }
    {
        InodeSpec s;
        s.ino = 2;
        s.version = 3;
        s.isize = 5;
        s.data = bytes_of("worse");
        s.bad_data_crc = true;
        b.inode(s);
    }
    b.link(1, 1, 2, "f");
    DirentSpec bd;  // a dirent with a bad node_crc must not create a name
    bd.pino = 1;
    bd.version = 5;
    bd.ino = 2;
    bd.name = "phantom";
    bd.bad_node_crc = true;
    b.dirent(bd);
    DirentSpec bn;  // and one with a bad name_crc
    bn.pino = 1;
    bn.version = 6;
    bn.ino = 2;
    bn.name = "garbled";
    bn.bad_name_crc = true;
    b.dirent(bn);
    const Walked w = walk_listing(span_of(b.build()), true, history_opts());
    ASSERT_TRUE(w.status.ok);
    EXPECT_TRUE(has_code(w.result.diagnostics, "jffs2-node-crc-mismatch"));
    EXPECT_TRUE(has_code(w.result.diagnostics, "jffs2-data-crc-mismatch"));
    EXPECT_TRUE(has_code(w.result.diagnostics, "jffs2-name-crc-mismatch"));
    ASSERT_EQ(w.live.size(), 1u);
    const EntryResult& f = w.live.at("f");
    EXPECT_EQ(f.meta.version, 1u);
    EXPECT_EQ(f.digests.sha256, sha256_of(bytes_of("good")));
    EXPECT_EQ(f.meta.extra.count("crc"), 0u);
    EXPECT_EQ(w.info.attrs.at("crc_failures"), "4");
    // History keeps both bad states, flagged.
    const EntryResult* v2 = find_version(w, "f", 2, false);
    ASSERT_NE(v2, nullptr);
    EXPECT_EQ(v2->meta.extra.at("crc"), "bad");
    EXPECT_EQ(v2->digests.sha256, sha256_of(bytes_of("bad")));
    const EntryResult* v3 = find_version(w, "f", 3, false);
    ASSERT_NE(v3, nullptr);
    EXPECT_EQ(v3->meta.extra.at("crc"), "bad");
    EXPECT_EQ(v3->meta.extra.at("newer_than_live"), "true");
    EXPECT_EQ(v3->digests.sha256, sha256_of(bytes_of("worse")));
}

TEST(Jffs2Synth, ObsoleteNodesAreHistoryOnly) {
    Builder b;
    b.dir_node(1, 1);
    {
        InodeSpec s;
        s.ino = 2;
        s.version = 1;
        s.isize = 3;
        s.data = bytes_of("old");
        s.obsolete = true;
        b.inode(s);
    }
    b.file_node(2, 2, "new", 3);
    DirentSpec od;  // an obsoleted dirent for a name that no longer exists
    od.pino = 1;
    od.version = 1;
    od.ino = 2;
    od.name = "was";
    od.obsolete = true;
    b.dirent(od);
    b.link(1, 2, 2, "f");
    const Walked w = walk_listing(span_of(b.build()), true, history_opts());
    ASSERT_TRUE(w.status.ok) << w.status.error;
    EXPECT_EQ(w.info.attrs.at("obsolete_nodes"), "2");
    ASSERT_EQ(w.live.size(), 1u);
    EXPECT_EQ(w.live.at("f").digests.sha256, sha256_of(bytes_of("new")));
    EXPECT_EQ(w.live.at("f").meta.extra.count("obsolete"), 0u);
    const EntryResult* v1 = find_version(w, "f", 1, false);
    ASSERT_NE(v1, nullptr);
    EXPECT_EQ(v1->meta.extra.at("obsolete"), "true");
    EXPECT_EQ(v1->digests.sha256, sha256_of(bytes_of("old")));
}

TEST(Jffs2Synth, HardLinksAndXattrs) {
    Builder b;
    b.dir_node(1, 1);
    b.file_node(2, 1, "shared", 6);
    b.link(1, 1, 2, "a");
    b.link(1, 2, 2, "b");
    b.xattr(7, 1, 1, "comment", "hi");                 // user.comment
    b.xattr(8, 1, 2, "selinux", "system_u:object_r");  // security.selinux
    b.xref(2, 7, 1);
    b.xref(2, 8, 2);
    b.xref(2, 99, 3);  // xid with no xattr node
    const Walked w = walk_listing(span_of(b.build()), true, history_opts());
    ASSERT_TRUE(w.status.ok);
    EXPECT_EQ(w.live.at("a").meta.nlink, 2u);
    EXPECT_EQ(w.live.at("b").meta.nlink, 2u);
    EXPECT_EQ(w.live.at("a").meta.extra.at("xattrs"), "#99,security.selinux,user.comment");
    EXPECT_EQ(w.info.attrs.at("xattr_nodes"), "2");
    EXPECT_EQ(w.info.attrs.at("xref_nodes"), "3");
    EXPECT_TRUE(w.history.empty());
}

TEST(Jffs2Synth, NameOnlyEntryWhenInodeNodesAreMissing) {
    Builder b;
    b.dir_node(1, 1);
    b.link(1, 1, 5, "ghost", kDtReg, 123);
    b.link(1, 2, 6, "dir", kDtDir, 124);
    b.file_node(7, 1, "in ghost dir", 12);
    b.link(6, 1, 7, "child", kDtReg);
    const Walked w = walk_listing(span_of(b.build()));
    ASSERT_TRUE(w.status.ok);
    EXPECT_TRUE(has_code(w.result.diagnostics, "jffs2-missing-inode"));
    ASSERT_EQ(w.live.count("ghost"), 1u);
    EXPECT_EQ(w.live.at("ghost").meta.inode, 5u);
    EXPECT_EQ(w.live.at("ghost").meta.size, 0u);
    EXPECT_EQ(w.live.at("ghost").meta.mtime.value_or(0), 123);
    ASSERT_EQ(w.live.count("dir/child"), 1u);
}

TEST(Jffs2Synth, MetadataOnlyWalk) {
    WalkOptions o;
    o.extract_data = false;
    const Walked w = walk_listing(span_of(synth_image(Endian::Little)), true, o);
    ASSERT_TRUE(w.status.ok);
    EXPECT_EQ(w.live.at("hello.txt").meta.size, 12u);
    EXPECT_EQ(w.live.at("hello.txt").digests.bytes, 0u);
    EXPECT_EQ(w.result.bytes, 0u);
}

// ------------------------------------------------------------------ history limits

TEST(Jffs2History, VersionCapKeepsNewest) {
    Builder b;
    b.dir_node(1, 1);
    for (std::uint32_t v = 1; v <= 6; ++v)
        b.file_node(2, v, std::string(1, static_cast<char>('a' + v)), 1, 0, 0644, v);
    b.link(1, 1, 2, "f");
    WalkOptions o = history_opts();
    o.limits.max_nodes_per_fs = 78125 * 2;  // cap = 2 versions per inode
    const Walked w = walk_listing(span_of(b.build()), true, o);
    ASSERT_TRUE(w.status.ok);
    EXPECT_EQ(w.result.superseded, 2u);
    EXPECT_TRUE(has_code(w.result.diagnostics, "jffs2-limit-versions"));
    EXPECT_FALSE(w.result.truncated);  // history-only cap: the live tree is complete
    ASSERT_NE(find_version(w, "f", 4, false), nullptr);
    ASSERT_NE(find_version(w, "f", 5, false), nullptr);
    EXPECT_EQ(find_version(w, "f", 3, false), nullptr);
    EXPECT_EQ(find_version(w, "f", 5, false)->meta.extra.at("versions_dropped"), "3");
    // Default limits: every version.
    const Walked all = walk_listing(span_of(b.build()), true, history_opts());
    EXPECT_EQ(all.result.superseded, 5u);
    EXPECT_FALSE(has_code(all.result.diagnostics, "jffs2-limit-versions"));
}

TEST(Jffs2History, DiskSinkPlacesVersions) {
    Builder b;
    b.dir_node(1, 1);
    b.file_node(2, 1, "v1", 2);
    b.file_node(2, 2, "v2", 2);
    b.link(1, 1, 2, "cfg");
    b.file_node(3, 1, "bye", 3);
    b.link(1, 2, 3, "del");
    b.unlink(1, 3, "del");
    TempDir tmp;
    std::unique_ptr<DiskSink> sink;
    ASSERT_TRUE(DiskSink::open((tmp.path() / "out").string(), {}, sink).ok);
    Jffs2Reader r;
    ASSERT_TRUE(r.open(span_of(b.build())).ok);
    WalkResult out;
    ASSERT_TRUE(r.walk(*sink, history_opts(), out).ok);
    EXPECT_EQ(out.superseded, 1u);
    EXPECT_EQ(out.deleted, 1u);
    EXPECT_TRUE(stdfs::exists(tmp.path() / "out" / "cfg"));
    EXPECT_FALSE(stdfs::exists(tmp.path() / "out" / "del"));
    EXPECT_TRUE(stdfs::exists(tmp.path() / "out" / ".omnitrace-versions" / "cfg" / "v1"));
    EXPECT_TRUE(stdfs::exists(tmp.path() / "out" / ".omnitrace-versions" / "del" / "v1"));
}

// ------------------------------------------------------------------ hostile

TEST(Jffs2Hostile, TruncationAtEveryOffsetNeverCrashes) {
    const std::vector<std::uint8_t> img = synth_image(Endian::Little);
    for (std::size_t n = 0; n <= img.size(); n += 1) {
        std::vector<std::uint8_t> cut(img.begin(), img.begin() + static_cast<std::ptrdiff_t>(n));
        const Walked w = walk_listing(span_of(cut), true, history_opts());
        if (!w.open_status) continue;
        EXPECT_TRUE(w.status.ok) << n;
    }
}

TEST(Jffs2Hostile, SeededByteFlipsNeverCrash) {
    const std::vector<std::uint8_t> img = synth_image(Endian::Big);
    std::uint64_t x = 0x9E3779B97F4A7C15ull;
    for (int round = 0; round < 300; ++round) {
        std::vector<std::uint8_t> bad = img;
        for (int k = 0; k < 4; ++k) {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            const std::uint64_t r = x * 0x2545F4914F6CDD1Dull;
            bad[static_cast<std::size_t>(r % bad.size())] ^= static_cast<std::uint8_t>(r >> 56);
        }
        // A flipped isize legitimately yields a large sparse file; keep the
        // zero-fill small so the run stays fast (the cap is exercised elsewhere).
        WalkOptions o = history_opts();
        o.limits.max_file_bytes = 1 << 16;
        (void)walk_listing(span_of(bad), true, o);
    }
}

TEST(Jffs2Hostile, BadLengthsAreSkipped) {
    Builder b;
    b.dir_node(1, 1);
    b.file_node(2, 1, "ok", 2);
    b.link(1, 1, 2, "ok");
    {
        InodeSpec s;  // totlen 0
        s.ino = 3;
        s.version = 1;
        s.data = bytes_of("zero");
        s.isize = 4;
        s.totlen = 0;
        b.inode(s);
    }
    {
        InodeSpec s;  // totlen past the span
        s.ino = 4;
        s.version = 1;
        s.data = bytes_of("past");
        s.isize = 4;
        s.totlen = 0x7FFFFFFF;
        b.inode(s);
    }
    {
        InodeSpec s;  // csize past totlen
        s.ino = 5;
        s.version = 1;
        s.data = bytes_of("cs");
        s.isize = 2;
        s.csize = 1000;
        b.inode(s);
        b.link(1, 2, 5, "csize");
    }
    {
        DirentSpec d;  // nsize past totlen
        d.pino = 1;
        d.version = 3;
        d.ino = 2;
        d.name = "n";
        d.nsize = 200;
        b.dirent(d);
    }
    {
        InodeSpec s;  // dsize huge for an uncompressed node
        s.ino = 6;
        s.version = 1;
        s.data = bytes_of("small");
        s.dsize = 0xFFFFFFFFu;
        s.isize = 0xFFFFFFFFu;
        b.inode(s);
        b.link(1, 4, 6, "huge");
    }
    b.file_node(7, 1, "tail", 4);
    b.link(1, 5, 7, "tail");
    WalkOptions o;
    o.limits.max_file_bytes = 4096;
    const Walked w = walk_listing(span_of(b.build()), true, o);
    ASSERT_TRUE(w.open_status.ok) << w.open_status.error;
    ASSERT_TRUE(w.status.ok);
    EXPECT_TRUE(has_code(w.result.diagnostics, "jffs2-node-truncated"));
    EXPECT_TRUE(has_code(w.result.diagnostics, "jffs2-node-malformed"));
    EXPECT_EQ(w.live.count("ok"), 1u);
    EXPECT_EQ(w.live.count("tail"), 1u);  // scanning resumed after the bad nodes
    EXPECT_EQ(w.live.at("tail").digests.sha256, sha256_of(bytes_of("tail")));
    ASSERT_EQ(w.live.count("huge"), 1u);
    EXPECT_TRUE(w.live.at("huge").truncated);
    EXPECT_TRUE(has_code(w.live.at("huge").diagnostics, "jffs2-limit-file-bytes"));
    EXPECT_EQ(w.live.at("huge").digests.bytes, 4096u);
}

TEST(Jffs2Hostile, DecompressionBombIsCapped) {
    Builder b;
    b.dir_node(1, 1);
    InodeSpec s;  // 20 bytes claiming 1 GiB
    s.ino = 2;
    s.version = 1;
    s.compr = 6;
    s.data = zlib_stored(bytes_of("0123456789ab"));
    s.dsize = 1u << 30;
    s.isize = 1u << 30;
    b.inode(s);
    b.link(1, 1, 2, "bomb");
    WalkOptions o;
    o.limits.max_file_bytes = 1 << 20;
    const Walked w = walk_listing(span_of(b.build()), true, o);
    ASSERT_TRUE(w.status.ok);
    const EntryResult& e = w.live.at("bomb");
    EXPECT_TRUE(e.truncated);
    EXPECT_TRUE(has_code(e.diagnostics, "jffs2-limit-file-bytes"));
    EXPECT_EQ(e.digests.bytes, 1u << 20);
    // Within max_file_bytes but past the ratio: refused before decoding.
    s.dsize = 100000;
    s.isize = 100000;
    Builder c;
    c.dir_node(1, 1);
    c.inode(s);
    c.link(1, 1, 2, "ratio");
    const Walked w2 = walk_listing(span_of(c.build()), true, o);
    EXPECT_TRUE(has_code(w2.live.at("ratio").diagnostics, "jffs2-limit-decompress-ratio"));
    EXPECT_TRUE(w2.live.at("ratio").truncated);
    EXPECT_EQ(w2.live.at("ratio").digests.bytes, 100000u);
}

TEST(Jffs2Hostile, VersionWrapAndSelfParentLoop) {
    Builder b;
    b.dir_node(1, 1);
    b.file_node(2, 0xFFFFFFFFu, "max", 3);
    b.file_node(2, 0, "min", 3);
    b.link(1, 0xFFFFFFFFu, 2, "f");
    b.dir_node(3, 1);
    b.link(1, 1, 3, "d", kDtDir);
    b.link(3, 1, 3, "self", kDtDir);  // d/self -> d
    b.link(3, 2, 1, "up", kDtDir);    // d/up -> root
    const Walked w = walk_listing(span_of(b.build()), true, history_opts());
    ASSERT_TRUE(w.status.ok);
    EXPECT_EQ(w.live.at("f").digests.sha256, sha256_of(bytes_of("max")));  // highest u32 wins
    EXPECT_EQ(w.live.count("d"), 1u);
    EXPECT_EQ(w.live.count("d/self"), 0u);
    EXPECT_EQ(w.live.count("d/up"), 0u);
    EXPECT_TRUE(has_code(w.result.diagnostics, "jffs2-dir-loop"));
}

TEST(Jffs2Hostile, NodeLimitStopsTheScan) {
    Builder b;
    b.dir_node(1, 1);
    for (std::uint32_t i = 0; i < 300; ++i) {
        b.file_node(2 + i, 1, "x", 1);
        b.link(1, i + 1, 2 + i, "f" + std::to_string(i));
    }
    WalkOptions o;
    o.limits.max_nodes_per_fs = 101;
    const Walked w = walk_listing(span_of(b.build()), true, o);
    ASSERT_TRUE(w.status.ok);
    EXPECT_TRUE(w.result.truncated);
    EXPECT_TRUE(has_code(w.result.diagnostics, "jffs2-limit-nodes"));
    EXPECT_EQ(w.info.attrs.at("nodes"), "601");  // info() came from open() with default limits
    EXPECT_EQ(w.live.size(), 50u);
    WalkOptions f;
    f.limits.max_files = 10;
    const Walked w2 = walk_listing(span_of(b.build()), true, f);
    EXPECT_TRUE(has_code(w2.result.diagnostics, "jffs2-limit-files"));
    EXPECT_EQ(w2.result.entries, 10u);
}

TEST(Jffs2Hostile, BadEntryNamesAreSkipped) {
    Builder b;
    b.dir_node(1, 1);
    b.file_node(2, 1, "x", 1);
    b.link(1, 1, 2, "a/b");
    b.link(1, 2, 2, "..");
    b.link(1, 3, 2, std::string("n\0l", 3));
    b.link(1, 4, 2, "fine");
    const Walked w = walk_listing(span_of(b.build()));
    ASSERT_TRUE(w.status.ok);
    EXPECT_EQ(w.live.size(), 1u);
    EXPECT_EQ(w.live.count("fine"), 1u);
    EXPECT_TRUE(has_code(w.result.diagnostics, "jffs2-bad-entry-name"));
}

// ------------------------------------------------------------------ fixtures

// Crude parser for the flat `tree:` section and the `history:` lists of a
// fixture's expected.yaml (one `- path:` per entry, scalar `key: value` lines).
struct Expected {
    std::map<std::string, std::map<std::string, std::string>> tree;
    std::map<std::string, std::vector<std::map<std::string, std::string>>> history;
    bool squashed = false;  // built with mkfs.jffs2 -q (--squash): owners are root on disk
};

Expected read_expected(const stdfs::path& yaml) {
    Expected out;
    std::ifstream in(yaml);
    std::string line;
    std::string section;    // "tree" or "history"
    std::string hist_list;  // superseded / deleted / current / ...
    std::map<std::string, std::string>* cur = nullptr;
    auto unquote = [](std::string v) {
        if (v.size() >= 2 && v.front() == '\'' && v.back() == '\'') v = v.substr(1, v.size() - 2);
        return v;
    };
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (line == "  - -q") out.squashed = true;
        if (line[0] != ' ' && line[0] != '-') {
            section = line == "tree:" ? "tree" : line == "history:" ? "history" : "";
            cur = nullptr;
            continue;
        }
        if (section == "tree") {
            if (line.rfind("- path: ", 0) == 0) {
                const std::string p = unquote(line.substr(8));
                cur = &out.tree[p];
                (*cur)["path"] = p;
                continue;
            }
            const auto colon = line.find(": ");
            if (cur && colon != std::string::npos && line.rfind("  ", 0) == 0)
                (*cur)[line.substr(2, colon - 2)] = unquote(line.substr(colon + 2));
        } else if (section == "history") {
            if (line.rfind("  ", 0) == 0 && line[2] != ' ' && line[2] != '-' &&
                line.back() == ':') {
                hist_list = line.substr(2, line.size() - 3);
                cur = nullptr;
                continue;
            }
            if (line.rfind("  - ", 0) == 0 && line.rfind("  - path: ", 0) != 0) {
                cur = nullptr;  // a list of something other than entries
                continue;
            }
            if (line.rfind("  - path: ", 0) == 0) {
                out.history[hist_list].push_back({});
                cur = &out.history[hist_list].back();
                (*cur)["path"] = unquote(line.substr(10));
                continue;
            }
            const auto colon = line.find(": ");
            if (cur && colon != std::string::npos && line.rfind("    ", 0) == 0)
                (*cur)[line.substr(4, colon - 4)] = unquote(line.substr(colon + 2));
        }
    }
    return out;
}

class Jffs2Fixture : public ::testing::TestWithParam<std::string> {};

TEST_P(Jffs2Fixture, MatchesExpectedYaml) {
    const std::string name = GetParam();
    const stdfs::path dir = stdfs::path(OMNITRACE_TEST_DATA_DIR) / "out";
    const stdfs::path img = dir / (name + ".img");
    const stdfs::path yaml = dir / (name + ".expected.yaml");
    if (!stdfs::exists(img) || !stdfs::exists(yaml))
        GTEST_SKIP() << "fixture " << name << " not built";
    const Expected expected = read_expected(yaml);
    ASSERT_FALSE(expected.tree.empty());

    std::shared_ptr<MappedFile> mf;
    ASSERT_TRUE(MappedFile::open(img.string(), mf).ok);
    const Walked w = walk_listing(Span::whole(mf), true, history_opts());
    ASSERT_TRUE(w.status.ok) << w.status.error << "\n" << join_diags(w.result.diagnostics);
    EXPECT_EQ(w.info.attrs.at("erase_size"), "65536");
    EXPECT_EQ(w.info.endian, name == "jffs2-be" ? Endian::Big : Endian::Little);

    // tests/fixtures/generate.py (before its node_crc fix) computed the
    // node_crc of the two inode nodes it appends to jffs2-history over 64
    // bytes; the kernel (fs/jffs2/scan.c) and mkfs.jffs2 use
    // sizeof(jffs2_raw_inode) - 8 = 60. A reader with kernel semantics
    // rejects those two nodes for the live tree and keeps them as history
    // with crc=bad. Detect that state and check the strict expectation.
    const bool fixture_bad_crc =
        name == "jffs2-history" && has_code(w.result.diagnostics, "jffs2-node-crc-mismatch");
    for (const Diagnostic& d : w.result.diagnostics) {
        if (fixture_bad_crc && d.code == "jffs2-node-crc-mismatch") continue;
        EXPECT_NE(d.severity, Severity::Warning) << d.code << ": " << d.message;
    }
    EXPECT_EQ(w.live.size(), expected.tree.size());
    for (const auto& [path, fields] : expected.tree) {
        const auto it = w.live.find(path);
        ASSERT_NE(it, w.live.end()) << "missing " << path;
        const FileMeta& m = it->second.meta;
        const std::string kind = fields.at("kind");
        EXPECT_EQ(std::string(entry_kind_name(m.kind)), kind) << path;
        EXPECT_EQ(m.mode, static_cast<std::uint32_t>(std::stoul(fields.at("mode"), nullptr, 8)))
            << path;
        if (expected.squashed) {
            // mkfs.jffs2's -q is --squash, not quiet: every owner on disk is
            // root although expected.yaml records the staged 1000/100.
            EXPECT_EQ(m.uid, 0u) << path;
            EXPECT_EQ(m.gid, 0u) << path;
        } else {
            EXPECT_EQ(m.uid, static_cast<std::uint32_t>(std::stoul(fields.at("uid")))) << path;
            EXPECT_EQ(m.gid, static_cast<std::uint32_t>(std::stoul(fields.at("gid")))) << path;
        }
        if (fixture_bad_crc && path == "history/config.txt") {
            // Live tree shows the mkfs version (the only node with a valid CRC).
            const auto& v1 = expected.history.at("superseded").at(0);
            EXPECT_EQ(m.size, std::stoull(v1.at("size")));
            EXPECT_EQ(it->second.digests.sha256, v1.at("sha256"));
            EXPECT_EQ(m.mtime.value_or(-1), std::stoll(v1.at("mtime")));
            continue;
        }
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
        EXPECT_FALSE(it->second.truncated) << path << join_diags(it->second.diagnostics);
    }

    // History section.
    if (!expected.history.count("superseded")) {
        // A pristine mkfs image: files written in one node have no history;
        // multi-node files yield prefix versions but nothing is deleted.
        EXPECT_EQ(w.result.deleted, 0u);
        return;
    }
    for (const auto& s : expected.history.at("superseded")) {
        const std::uint64_t version = std::stoull(s.at("version"));
        // In the bad-CRC state the mkfs version is the live entry, checked above.
        if (fixture_bad_crc && &s == &expected.history.at("superseded").front()) continue;
        const EntryResult* e = find_version(w, s.at("path"), version, false);
        ASSERT_NE(e, nullptr) << s.at("path") << " v" << version;
        EXPECT_EQ(e->meta.inode, std::stoull(s.at("inode")));
        EXPECT_EQ(e->meta.size, std::stoull(s.at("size")));
        EXPECT_EQ(e->digests.sha256, s.at("sha256")) << s.at("path") << " v" << version;
        EXPECT_EQ(e->meta.mtime.value_or(-1), std::stoll(s.at("mtime")));
        if (fixture_bad_crc && version != 1) {
            EXPECT_EQ(e->meta.extra.at("crc"), "bad");
        }
    }
    if (fixture_bad_crc) {
        // The newest appended node is history too, flagged as newer than live.
        const auto& c = expected.history.at("current").at(0);
        const EntryResult* e = find_version(w, c.at("path"), std::stoull(c.at("version")), false);
        ASSERT_NE(e, nullptr);
        EXPECT_EQ(e->digests.sha256, c.at("sha256"));
        EXPECT_EQ(e->meta.extra.at("crc"), "bad");
        EXPECT_EQ(e->meta.extra.at("newer_than_live"), "true");
    }
    for (const auto& d : expected.history.at("deleted")) {
        const EntryResult* e = nullptr;
        for (const EntryResult& h : w.history)
            if (h.meta.deleted && !h.meta.superseded && h.meta.path == d.at("path")) e = &h;
        ASSERT_NE(e, nullptr) << d.at("path");
        EXPECT_EQ(e->meta.inode, std::stoull(d.at("inode")));
        EXPECT_EQ(e->meta.size, std::stoull(d.at("size")));
        EXPECT_EQ(e->digests.sha256, d.at("sha256"));
        EXPECT_EQ(e->meta.mtime.value_or(-1), std::stoll(d.at("mtime")));
        EXPECT_EQ(e->meta.extra.count("record"), 0u);  // the inode itself, not just the unlink
        EXPECT_EQ(w.live.count(d.at("path")), 0u);
    }
    EXPECT_GE(w.result.deleted, expected.history.at("deleted").size());
}

INSTANTIATE_TEST_SUITE_P(Images, Jffs2Fixture,
                         ::testing::Values("jffs2-le", "jffs2-be", "jffs2-history"));

// ------------------------------------------------------------------ corpus: router.bin

// Independent minimal reassembly of one inode: newest node wins per byte,
// truncated to the newest isize. Used to cross-check the reader's sha256.
std::optional<std::vector<std::uint8_t>> reassemble(const std::vector<std::uint8_t>& img,
                                                    std::uint32_t want_ino) {
    struct N {
        std::uint32_t version, offset, csize, dsize, isize;
        std::uint8_t compr;
        std::size_t data;
    };
    std::vector<N> nodes;
    auto le16 = [&](std::size_t o) {
        return static_cast<std::uint16_t>(img[o] | (img[o + 1] << 8));
    };
    auto le32 = [&](std::size_t o) {
        return static_cast<std::uint32_t>(img[o]) | (static_cast<std::uint32_t>(img[o + 1]) << 8) |
               (static_cast<std::uint32_t>(img[o + 2]) << 16) |
               (static_cast<std::uint32_t>(img[o + 3]) << 24);
    };
    for (std::size_t off = 0; off + 12 <= img.size();) {
        if (le16(off) != 0x1985) {
            off += 4;
            continue;
        }
        const std::uint32_t totlen = le32(off + 4);
        if (totlen < 12 || totlen > img.size() - off) {
            off += 4;
            continue;
        }
        if ((le16(off + 2) | 0x2000) == 0xE002 && totlen >= 68 && le32(off + 12) == want_ino)
            nodes.push_back({le32(off + 16), le32(off + 44), le32(off + 48), le32(off + 52),
                             le32(off + 28), img[off + 56], off + 68});
        off += (totlen + 3) & ~3u;
    }
    std::sort(nodes.begin(), nodes.end(),
              [](const N& a, const N& b) { return a.version < b.version; });
    std::vector<std::uint8_t> file;
    std::uint32_t isize = 0;
    for (const N& n : nodes) {
        isize = n.isize;
        if (n.dsize == 0) continue;
        std::vector<std::uint8_t> d;
        const std::span<const std::uint8_t> in(img.data() + n.data, n.csize);
        if (n.compr == 0) {
            d.assign(in.begin(), in.end());
        } else if (n.compr == 6) {
            if (!compress::decompress_exact(compress::Codec::Zlib, in, d, n.dsize))
                return std::nullopt;
        } else if (n.compr == 8) {
            std::vector<std::uint8_t> framed = {0, 0x00, 0x20, 0, 0};
            for (int i = 0; i < 8; ++i)
                framed.push_back(static_cast<std::uint8_t>(
                    (static_cast<std::uint64_t>(n.dsize) >> (8 * i)) & 0xff));
            framed.insert(framed.end(), in.begin(), in.end());
            if (!compress::decompress_exact(compress::Codec::Lzma, framed, d, n.dsize))
                return std::nullopt;
        } else {
            return std::nullopt;
        }
        if (file.size() < n.offset + n.dsize) file.resize(n.offset + n.dsize, 0);
        std::copy(d.begin(), d.end(), file.begin() + static_cast<std::ptrdiff_t>(n.offset));
    }
    file.resize(isize, 0);
    return file;
}

TEST(Jffs2Corpus, RouterOverlayLiveAndHistory) {
    const stdfs::path bin =
        "/home/wrongbaud/projects/omnitrace-v2/corpus/router-example/flash/router.bin";
    if (!stdfs::exists(bin)) GTEST_SKIP() << "corpus file missing: " << bin;
    std::shared_ptr<MappedFile> mf;
    ASSERT_TRUE(MappedFile::open(bin.string(), mf).ok);
    const Span part = Span::whole(mf).sub(0xc60000, 3735564);

    TempDir tmp;
    std::unique_ptr<DiskSink> sink;
    ASSERT_TRUE(DiskSink::open((tmp.path() / "live").string(), {}, sink).ok);
    Jffs2Reader r;
    ASSERT_TRUE(r.open(part).ok);
    const FilesystemInfo info = r.info();
    EXPECT_EQ(info.attrs.at("erase_size"), "65536");
    EXPECT_EQ(info.attrs.at("inodes_live"), "82");
    EXPECT_EQ(info.attrs.at("inodes_deleted"), "248");
    EXPECT_EQ(info.attrs.at("inodes_multi_version"), "239");
    EXPECT_EQ(info.attrs.at("unlink_dirents"), "381");
    WalkResult live;
    ASSERT_TRUE(r.walk(*sink, {}, live).ok);
    EXPECT_FALSE(live.truncated) << join_diags(live.diagnostics);
    std::map<std::string, const EntryResult*> by_path;
    std::set<std::uint64_t> live_inodes;
    for (const EntryResult& e : live.entries_out) {
        by_path[e.meta.path] = &e;
        live_inodes.insert(e.meta.inode);
    }
    EXPECT_EQ(live_inodes.size(), 82u);
    EXPECT_EQ(by_path.count("upper/etc/dropbear"), 1u);
    const auto lua = by_path.find("upper/usr/lib/lua/luci/controller/admin/network.lua");
    ASSERT_NE(lua, by_path.end());
    EXPECT_EQ(lua->second->meta.size, 10975u);
    EXPECT_FALSE(lua->second->truncated) << join_diags(lua->second->diagnostics);
    EXPECT_EQ(lua->second->meta.extra.at("compression"), "lzma");
    // Cross-check against the independent reassembly.
    const auto raw = part.bytes(0, static_cast<std::size_t>(part.size()));
    ASSERT_TRUE(raw.has_value());
    const auto expect = reassemble(*raw, static_cast<std::uint32_t>(lua->second->meta.inode));
    ASSERT_TRUE(expect.has_value());
    EXPECT_EQ(expect->size(), 10975u);
    EXPECT_EQ(lua->second->digests.sha256, sha256_of(*expect));
    EXPECT_EQ(std::string(expect->begin(), expect->begin() + 30), "-- Copyright 2008 Steven Barth");
    std::ifstream in(lua->second->host_path, std::ios::binary);
    const std::vector<std::uint8_t> on_disk((std::istreambuf_iterator<char>(in)),
                                            std::istreambuf_iterator<char>());
    EXPECT_EQ(on_disk, *expect);

    // History walk.
    ListingSink hsink(true);
    WalkResult hist;
    ASSERT_TRUE(r.walk(hsink, history_opts(), hist).ok);
    EXPECT_GE(hist.deleted, 240u);
    std::set<std::uint64_t> superseded_inodes;
    std::uint64_t deleted_records = 0, superseded_entries = 0;
    for (const EntryResult& e : hist.entries_out) {
        if (e.meta.superseded) {
            superseded_inodes.insert(e.meta.inode);
            superseded_entries++;
        }
        if (e.meta.deleted) deleted_records++;
    }
    EXPECT_GE(superseded_inodes.size(), 230u);
    EXPECT_EQ(deleted_records, hist.deleted);
    EXPECT_EQ(superseded_entries, hist.superseded);
    EXPECT_EQ(hist.entries, hist.entries_out.size());
    // Live part of the history walk is identical to the plain walk.
    std::uint64_t live_in_hist = 0;
    for (const EntryResult& e : hist.entries_out)
        if (!e.meta.deleted && !e.meta.superseded) live_in_hist++;
    EXPECT_EQ(live_in_hist, live.entries);
}

}  // namespace
}  // namespace omnitrace::fs
