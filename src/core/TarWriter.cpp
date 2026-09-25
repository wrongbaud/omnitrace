// TarWriter.cpp — see the header.
//
// The format is ustar with pax extended headers where a field will not fit:
//
//   name 100  mode 8  uid 8  gid 8  size 12  mtime 12  chksum 8  typeflag 1
//   linkname 100  magic 6 ("ustar\0")  version 2 ("00")  uname 32  gname 32
//   devmajor 8  devminor 8  prefix 155
//
// A pax header is an ordinary entry of type 'x' whose data is a run of
// "<len> <key>=<value>\n" records, and it applies to the entry that follows.
// It is used here for a path or link target longer than the fixed field and
// for anything that is not valid UTF-8 -- QNX and Windows filesystems both
// carry names that are neither, and a reader that mangles them loses the only
// record of what the file was called.
#include "TarWriter.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace omnitrace::detail {

namespace {

constexpr std::size_t kBlock = 512;

void put_field(char* dst, std::size_t n, const std::string& s) {
    std::memset(dst, 0, n);
    std::memcpy(dst, s.data(), std::min(n, s.size()));
}

/// Octal, NUL terminated, right aligned in `n` bytes -- the tar convention.
void put_octal(char* dst, std::size_t n, std::uint64_t v) {
    std::string s;
    do {
        s.insert(s.begin(), static_cast<char>('0' + (v & 7u)));
        v >>= 3;
    } while (v != 0);
    if (s.size() > n - 1) s = std::string(n - 1, '7');  // saturate rather than overflow
    std::memset(dst, '0', n - 1);
    dst[n - 1] = '\0';
    std::memcpy(dst + (n - 1 - s.size()), s.data(), s.size());
}

void set_checksum(char* h) {
    std::memset(h + 148, ' ', 8);  // the checksum is computed with its own field blank
    unsigned sum = 0;
    for (std::size_t i = 0; i < kBlock; ++i) sum += static_cast<unsigned char>(h[i]);
    put_octal(h + 148, 7, sum);
    h[155] = ' ';
}

bool is_utf8(const std::string& s) {
    std::size_t i = 0;
    while (i < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        std::size_t n = 0;
        if (c < 0x80)
            n = 0;
        else if ((c & 0xE0) == 0xC0)
            n = 1;
        else if ((c & 0xF0) == 0xE0)
            n = 2;
        else if ((c & 0xF8) == 0xF0)
            n = 3;
        else
            return false;
        if (i + n >= s.size() + (n == 0 ? 1 : 0)) return false;
        for (std::size_t k = 1; k <= n; ++k)
            if ((static_cast<unsigned char>(s[i + k]) & 0xC0) != 0x80) return false;
        i += n + 1;
    }
    return true;
}

char type_of(EntryKind k) {
    switch (k) {
        case EntryKind::Directory:
            return '5';
        case EntryKind::Symlink:
            return '2';
        case EntryKind::CharDevice:
            return '3';
        case EntryKind::BlockDevice:
            return '4';
        case EntryKind::Fifo:
            return '6';
        default:
            return '0';
    }
}

}  // namespace

struct TarWriter::Impl {
    std::FILE* f = nullptr;
    bool finished = false;
    // The open entry: where its header sits, so the size can be patched in.
    bool in_file = false;
    long header_at = 0;
    std::uint64_t written = 0;
    char header[kBlock] = {};

    Status put(const void* p, std::size_t n) {
        if (n == 0) return Status::success();
        if (std::fwrite(p, 1, n, f) != n) return Status::fail("sink-io-error: tar write failed");
        return Status::success();
    }
    Status pad_to_block(std::uint64_t n) {
        const std::size_t rem = static_cast<std::size_t>(n % kBlock);
        if (rem == 0) return Status::success();
        static const char zeros[kBlock] = {};
        return put(zeros, kBlock - rem);
    }

    /// Build a header block for `meta` with `size` bytes of data.
    void build(char* h, const FileMeta& meta, std::uint64_t size, char type,
               const std::string& name, const std::string& link) {
        std::memset(h, 0, kBlock);
        put_field(h, 100, name);
        // Permission bits only: the type is the typeflag, and a setuid bit on
        // an extracted copy is a hazard rather than a record. The listing has
        // the mode the evidence carried.
        put_octal(h + 100, 8, meta.mode & 07777u);
        put_octal(h + 108, 8, meta.uid);
        put_octal(h + 116, 8, meta.gid);
        put_octal(h + 124, 12, size);
        put_octal(h + 136, 12, meta.mtime.value_or(0));
        h[156] = type;
        put_field(h + 157, 100, link);
        std::memcpy(h + 257, "ustar", 5);
        h[263] = '0';
        h[264] = '0';
        // uname/gname are left empty: resolving them would read this host's
        // passwd file, which has nothing to do with the evidence.
        if (type == '3' || type == '4') {
            put_octal(h + 329, 8, meta.rdev_major);
            put_octal(h + 337, 8, meta.rdev_minor);
        }
        set_checksum(h);
    }

    /// A pax extended header carrying whatever will not fit in the fixed
    /// fields, emitted immediately before the entry it describes.
    Status pax_if_needed(const FileMeta& meta, const std::string& name, const std::string& link) {
        std::string recs;
        const auto add = [&recs](const char* key, const std::string& value) {
            // "<len> key=value\n", where len counts itself.
            std::size_t len = std::strlen(key) + value.size() + 3;
            for (std::size_t guess = len;;) {
                const std::size_t digits = std::to_string(guess).size();
                if (len + digits == guess) break;
                guess = len + digits;
                len = std::strlen(key) + value.size() + 3;
                if (len + std::to_string(guess).size() == guess) break;
            }
            std::size_t total = len;
            while (total != len + std::to_string(total).size())
                total = len + std::to_string(total).size();
            recs += std::to_string(total) + " " + key + "=" + value + "\n";
        };
        if (name.size() > 100 || !is_utf8(name)) add("path", name);
        if (!link.empty() && (link.size() > 100 || !is_utf8(link))) add("linkpath", link);
        if (recs.empty()) return Status::success();

        char h[kBlock];
        FileMeta pm;
        pm.mode = 0644;
        pm.mtime = meta.mtime;
        build(h, pm, recs.size(), 'x', "PaxHeader", {});
        if (Status st = put(h, kBlock); !st) return st;
        if (Status st = put(recs.data(), recs.size()); !st) return st;
        return pad_to_block(recs.size());
    }
};

Status TarWriter::open(const std::string& path, std::unique_ptr<TarWriter>& out) {
    std::unique_ptr<TarWriter> w(new TarWriter());
    w->impl_ = std::make_unique<Impl>();
    w->impl_->f = std::fopen(path.c_str(), "w+b");
    if (w->impl_->f == nullptr)
        return Status::fail("sink-io-error: cannot create tar '" + path + "'");
    out = std::move(w);
    return Status::success();
}

TarWriter::~TarWriter() {
    if (impl_ && impl_->f != nullptr) {
        static_cast<void>(finish());
        std::fclose(impl_->f);
        impl_->f = nullptr;
    }
}

Status TarWriter::begin_file(const FileMeta& meta) {
    Impl& m = *impl_;
    if (m.in_file) return Status::fail("sink-protocol: a tar entry is already open");
    const std::string name = meta.path;
    if (Status st = m.pax_if_needed(meta, name, {}); !st) return st;
    m.header_at = std::ftell(m.f);
    if (m.header_at < 0) return Status::fail("sink-io-error: tar is not seekable");
    // Size unknown until end_file; written as 0 and patched then.
    m.build(m.header, meta, 0, '0', name.size() > 100 ? name.substr(0, 100) : name, {});
    if (Status st = m.put(m.header, kBlock); !st) return st;
    m.in_file = true;
    m.written = 0;
    return Status::success();
}

Status TarWriter::write(std::span<const std::uint8_t> data) {
    Impl& m = *impl_;
    if (!m.in_file) return Status::fail("sink-protocol: no tar entry is open");
    if (Status st = m.put(data.data(), data.size()); !st) return st;
    m.written += data.size();
    return Status::success();
}

Status TarWriter::end_file() {
    Impl& m = *impl_;
    if (!m.in_file) return Status::fail("sink-protocol: no tar entry is open");
    m.in_file = false;
    if (Status st = m.pad_to_block(m.written); !st) return st;
    const long end = std::ftell(m.f);
    // Patch the size in, now that it is known, and fix the checksum over it.
    put_octal(m.header + 124, 12, m.written);
    set_checksum(m.header);
    if (std::fseek(m.f, m.header_at, SEEK_SET) != 0)
        return Status::fail("sink-io-error: cannot seek back to the tar header");
    if (Status st = m.put(m.header, kBlock); !st) return st;
    if (std::fseek(m.f, end, SEEK_SET) != 0)
        return Status::fail("sink-io-error: cannot seek forward in the tar");
    return Status::success();
}

Status TarWriter::entry(const FileMeta& meta) {
    Impl& m = *impl_;
    if (m.in_file) return Status::fail("sink-protocol: a tar entry is already open");
    std::string name = meta.path;
    if (meta.kind == EntryKind::Directory && !name.empty() && name.back() != '/') name += '/';
    const std::string link = meta.link_target;
    if (Status st = m.pax_if_needed(meta, name, link); !st) return st;
    char h[kBlock];
    m.build(h, meta, 0, type_of(meta.kind), name.size() > 100 ? name.substr(0, 100) : name,
            link.size() > 100 ? link.substr(0, 100) : link);
    return m.put(h, kBlock);
}

Status TarWriter::finish() {
    Impl& m = *impl_;
    if (m.finished || m.f == nullptr) return Status::success();
    m.finished = true;
    static const char zeros[kBlock] = {};
    if (Status st = m.put(zeros, kBlock); !st) return st;
    if (Status st = m.put(zeros, kBlock); !st) return st;
    if (std::fflush(m.f) != 0) return Status::fail("sink-io-error: tar flush failed");
    return Status::success();
}

}  // namespace omnitrace::detail
