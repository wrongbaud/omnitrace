// Source.cpp — MemorySource, MappedFile and SubSource.
//
// This is one of the three files allowed to touch the host OS (see
// docs/ARCHITECTURE.md rule 8). POSIX and Win32 mappings live side by side
// behind #ifdef _WIN32; everything above the Impl struct is portable.
#include "omnitrace/core/Source.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <limits>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace omnitrace {

namespace {

// Bytes available in [off, size) — 0 when off >= size. Overflow-safe.
std::uint64_t available(std::uint64_t size, std::uint64_t off) {
    return off < size ? size - off : 0;
}

// Lowercase hex with a 0x prefix; deterministic and locale-independent.
std::string hex64(std::uint64_t v) {
    static constexpr char digits[] = "0123456789abcdef";
    char buf[2 + 16];
    std::size_t n = 0;
    buf[n++] = '0';
    buf[n++] = 'x';
    if (v == 0) {
        buf[n++] = '0';
    } else {
        char tmp[16];
        std::size_t t = 0;
        while (v != 0) {
            tmp[t++] = digits[v & 0xFu];
            v >>= 4;
        }
        while (t != 0) buf[n++] = tmp[--t];
    }
    return std::string(buf, n);
}

// Copy from a contiguous buffer of `size` bytes into `out`, starting at off.
std::size_t copy_out(const std::uint8_t* data, std::uint64_t size, std::uint64_t off,
                     std::span<std::uint8_t> out) {
    const std::uint64_t avail = available(size, off);
    if (avail == 0 || out.empty()) return 0;
    const std::uint64_t n64 = std::min<std::uint64_t>(avail, out.size());
    const std::size_t n = static_cast<std::size_t>(n64);
    std::memcpy(out.data(), data + off, n);
    return n;
}

// Zero-copy window over a contiguous buffer; empty if [off, off+len) does not fit.
std::span<const std::uint8_t> map_contiguous(const std::uint8_t* data, std::uint64_t size,
                                             std::uint64_t off, std::size_t len) {
    if (off > size || len > size - off) return {};
    if (len == 0) return {};
    return std::span<const std::uint8_t>(data + off, len);
}

#ifdef _WIN32
std::string last_error_text(DWORD err) {
    char* msg = nullptr;
    const DWORD n = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPSTR>(&msg), 0,
        nullptr);
    std::string text;
    if (n != 0 && msg != nullptr) {
        text.assign(msg, n);
        LocalFree(msg);
        while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' '))
            text.pop_back();
    } else {
        text = "error " + std::to_string(err);
    }
    return text;
}

// UTF-8 path -> UTF-16 for the W-suffixed APIs. Returns false on malformed input.
bool utf8_to_wide(const std::string& in, std::wstring& out) {
    out.clear();
    if (in.empty()) return true;
    if (in.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) return false;
    const int in_len = static_cast<int>(in.size());
    const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in.data(), in_len, nullptr, 0);
    if (n <= 0) return false;
    out.resize(static_cast<std::size_t>(n));
    const int m =
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in.data(), in_len, out.data(), n);
    return m == n;
}
#endif

}  // namespace

// ---------------------------------------------------------------- MemorySource

MemorySource::MemorySource(std::vector<std::uint8_t> bytes, std::string label)
    : bytes_(std::move(bytes)), label_(std::move(label)) {}

std::uint64_t MemorySource::size() const {
    return bytes_.size();
}

std::string MemorySource::id() const {
    return "mem:" + label_;
}

std::size_t MemorySource::read(std::uint64_t off, std::span<std::uint8_t> out) const {
    return copy_out(bytes_.data(), bytes_.size(), off, out);
}

std::span<const std::uint8_t> MemorySource::map(std::uint64_t off, std::size_t len) const {
    return map_contiguous(bytes_.data(), bytes_.size(), off, len);
}

// ------------------------------------------------------------------ MappedFile

struct MappedFile::Impl {
    const std::uint8_t* data = nullptr;  // nullptr when size == 0
    std::uint64_t size = 0;
#ifdef _WIN32
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = nullptr;
#endif

    Impl() = default;
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    ~Impl() {
#ifdef _WIN32
        if (data != nullptr) UnmapViewOfFile(data);
        if (mapping != nullptr) CloseHandle(mapping);
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
#else
        if (data != nullptr) {
            // size fits in size_t here: we refused to map otherwise.
            munmap(const_cast<std::uint8_t*>(data), static_cast<std::size_t>(size));
        }
#endif
    }
};

MappedFile::~MappedFile() = default;

Status MappedFile::open(const std::string& path, std::shared_ptr<MappedFile>& out) {
    out.reset();
    auto impl = std::make_unique<Impl>();

#ifdef _WIN32
    std::wstring wpath;
    if (!utf8_to_wide(path, wpath)) {
        return Status::fail("cannot open '" + path + "': path is not valid UTF-8");
    }
    impl->file =
        CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (impl->file == INVALID_HANDLE_VALUE) {
        return Status::fail("cannot open '" + path + "': " + last_error_text(GetLastError()));
    }
    const DWORD attrs = GetFileAttributesW(wpath.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        return Status::fail("cannot open '" + path + "': is a directory");
    }
    LARGE_INTEGER li{};
    if (!GetFileSizeEx(impl->file, &li)) {
        return Status::fail("cannot stat '" + path + "': " + last_error_text(GetLastError()));
    }
    if (li.QuadPart < 0) {
        return Status::fail("cannot stat '" + path + "': negative file size");
    }
    impl->size = static_cast<std::uint64_t>(li.QuadPart);
    if (impl->size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return Status::fail("cannot map '" + path + "': file larger than the address space");
    }
    if (impl->size != 0) {
        // Size 0/0 maps the whole file; CreateFileMappingW fails on empty files,
        // which is why the zero-length case is handled above without a mapping.
        impl->mapping = CreateFileMappingW(impl->file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (impl->mapping == nullptr) {
            return Status::fail("cannot map '" + path + "': " + last_error_text(GetLastError()));
        }
        LPVOID view = MapViewOfFile(impl->mapping, FILE_MAP_READ, 0, 0, 0);
        if (view == nullptr) {
            return Status::fail("cannot map '" + path + "': " + last_error_text(GetLastError()));
        }
        impl->data = static_cast<const std::uint8_t*>(view);
    }
#else
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        const int err = errno;
        return Status::fail("cannot open '" + path + "': " + std::strerror(err));
    }
    struct stat st{};
    if (fstat(fd, &st) != 0) {
        const int err = errno;
        ::close(fd);
        return Status::fail("cannot stat '" + path + "': " + std::strerror(err));
    }
    if (S_ISDIR(st.st_mode)) {
        ::close(fd);
        return Status::fail("cannot open '" + path + "': " + std::strerror(EISDIR));
    }
    if (st.st_size < 0) {
        ::close(fd);
        return Status::fail("cannot stat '" + path + "': negative file size");
    }
    impl->size = static_cast<std::uint64_t>(st.st_size);
    if (impl->size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        ::close(fd);
        return Status::fail("cannot map '" + path + "': file larger than the address space");
    }
    if (impl->size != 0) {
        void* p =
            mmap(nullptr, static_cast<std::size_t>(impl->size), PROT_READ, MAP_PRIVATE, fd, 0);
        if (p == MAP_FAILED) {
            const int err = errno;
            ::close(fd);
            return Status::fail("cannot map '" + path + "': " + std::strerror(err));
        }
        impl->data = static_cast<const std::uint8_t*>(p);
#ifdef MADV_SEQUENTIAL
        // Advisory only; failure is harmless.
        (void)madvise(p, static_cast<std::size_t>(impl->size), MADV_SEQUENTIAL);
#endif
    }
    // The mapping stays valid after the descriptor is closed.
    ::close(fd);
#endif

    std::shared_ptr<MappedFile> mf(new MappedFile());
    mf->impl_ = std::move(impl);
    mf->path_ = path;
    out = std::move(mf);
    return Status::success();
}

std::uint64_t MappedFile::size() const {
    return impl_ ? impl_->size : 0;
}

std::string MappedFile::id() const {
    return path_;
}

std::size_t MappedFile::read(std::uint64_t off, std::span<std::uint8_t> out) const {
    if (!impl_ || impl_->data == nullptr) return 0;
    return copy_out(impl_->data, impl_->size, off, out);
}

std::span<const std::uint8_t> MappedFile::map(std::uint64_t off, std::size_t len) const {
    if (!impl_ || impl_->data == nullptr) return {};
    return map_contiguous(impl_->data, impl_->size, off, len);
}

// ------------------------------------------------------------------- SubSource

SubSource::SubSource(std::shared_ptr<const Source> parent, std::uint64_t off, std::uint64_t len)
    : parent_(std::move(parent)), off_(off), len_(len) {
    // Clamp to the parent so a hostile (off, len) can never reach past it.
    const std::uint64_t psize = parent_ ? parent_->size() : 0;
    if (off_ > psize) off_ = psize;
    len_ = std::min(len_, psize - off_);
}

std::uint64_t SubSource::size() const {
    return len_;
}

std::string SubSource::id() const {
    return (parent_ ? parent_->id() : std::string{}) + "@" + hex64(off_) + "+" + hex64(len_);
}

std::size_t SubSource::read(std::uint64_t off, std::span<std::uint8_t> out) const {
    const std::uint64_t avail = available(len_, off);
    if (avail == 0 || out.empty() || !parent_) return 0;
    const std::uint64_t n64 = std::min<std::uint64_t>(avail, out.size());
    return parent_->read(off_ + off, out.first(static_cast<std::size_t>(n64)));
}

std::span<const std::uint8_t> SubSource::map(std::uint64_t off, std::size_t len) const {
    if (!parent_ || off > len_ || len > len_ - off) return {};
    if (len == 0) return {};
    auto m = parent_->map(off_ + off, len);
    // Never hand out more than asked, even if a parent misbehaves.
    if (m.size() != len) return {};
    return m;
}

}  // namespace omnitrace
