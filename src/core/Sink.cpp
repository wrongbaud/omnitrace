// Sink.cpp — DiskSink, ListingSink and the path normalizer they share.
//
// Everything a hostile image can do to an extractor is a path trick: "..",
// absolute names, a symlink planted early and written through later, two
// entries with the same name, a device node. The platform-independent half
// of this file decides *what* to do with an entry (normalize, version,
// dedupe, hash, count against Limits); the OS layer at the bottom only knows
// how to open a directory that is really a directory and create a file that
// did not exist a moment ago.
//
// Names are evidence, never a reason to drop an entry. A name the host
// cannot store verbatim (Windows: a reserved device name, a backslash, a
// colon, a trailing dot) is escaped on that host only, recorded in
// extra["host_name"] with a sink-name-escaped note, and FileMeta::path in the
// listing stays what the filesystem said. On POSIX every byte but '/' and NUL
// is a legal file-name byte and is written as is.
#include "omnitrace/core/Sink.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <map>
#include <optional>
#include <string_view>
#include <utility>

#include "HostNames.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace omnitrace {

// ---------------------------------------------------------------------------
// Path normalization
// ---------------------------------------------------------------------------

namespace {

constexpr char kVersionsDir[] = ".omnitrace-versions";

bool reject(std::string* why, const char* reason) {
    if (why) *why = reason;
    return false;
}

std::vector<std::string> split_components(const std::string& path) {
    std::vector<std::string> comps;
    std::string cur;
    for (const char c : path) {
        if (c == '/') {
            if (!cur.empty()) comps.push_back(std::move(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) comps.push_back(std::move(cur));
    return comps;
}

}  // namespace

// Readers always produce POSIX-style paths, so '/' is the only separator: a
// backslash is an ordinary file-name byte (systemd's "Data-mnt\x2dc.mount"),
// and so are ':' and a Windows device name. What the host cannot store is the
// host layer's problem (windows_host_component), never a reason to refuse.
// Refused: NUL (no OS accepts it in a name), empty, a leading '/' (absolute)
// and any ".." component (the tree boundary).
bool normalize_entry_path(const std::string& in, std::string& out, std::string* why) {
    out.clear();
    if (in.find('\0') != std::string::npos) return reject(why, "path contains a NUL byte");
    if (in.empty()) return reject(why, "empty path");
    if (in[0] == '/') return reject(why, "absolute path (leading '/')");

    std::vector<std::string> comps;
    std::string cur;
    auto flush = [&]() -> bool {
        if (cur.empty() || cur == ".") {
            cur.clear();
            return true;
        }
        if (cur == "..") return false;
        comps.push_back(std::move(cur));
        cur.clear();
        return true;
    };
    for (const char c : in) {
        if (c == '/') {
            if (!flush()) return reject(why, "parent-directory reference (\"..\")");
        } else {
            cur.push_back(c);
        }
    }
    if (!flush()) return reject(why, "parent-directory reference (\"..\")");
    if (comps.empty()) return reject(why, "path has no components");

    std::string joined;
    for (std::size_t i = 0; i < comps.size(); ++i) {
        if (i) joined.push_back('/');
        joined += comps[i];
    }
    out = std::move(joined);
    return true;
}

namespace detail {

std::string windows_host_component(std::string_view comp) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(comp.size() + 4);
    for (const char c : comp) {
        const auto b = static_cast<unsigned char>(c);
        const bool illegal = c == '\\' || c == ':' || c == '*' || c == '?' || c == '"' ||
                             c == '<' || c == '>' || c == '|' || b < 0x20;
        if (!illegal) {
            out.push_back(c);
            continue;
        }
        out.push_back('%');
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0Fu]);
    }
    // A device name is matched on the stem, so the marker goes after the stem
    // ("CON.txt~res" would still be the console; "CON~res.txt" is a file).
    if (is_windows_reserved_name(out)) {
        const std::size_t dot = out.find('.');
        out.insert(dot == std::string::npos ? out.size() : dot, "~res");
    }
    // Win32 strips trailing dots and spaces, so "a." and "a" would collide.
    if (!out.empty() && (out.back() == '.' || out.back() == ' ')) out.push_back('~');
    return out;
}

}  // namespace detail

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

namespace {

Status fail_code(const char* code, const std::string& detail) {
    std::string msg = code;
    if (!detail.empty()) {
        msg += ": ";
        msg += detail;
    }
    return Status::fail(std::move(msg));
}

std::string errno_text(int err) {
    const char* s = std::strerror(err);
    return s ? std::string(s) : std::string("errno ") + std::to_string(err);
}

bool is_historical(const FileMeta& m) {
    return m.superseded || m.deleted;
}

// Where an entry lands relative to the root: live entries at their own path,
// superseded/deleted versions under .omnitrace-versions/<path>/v<version> so
// the live tree remains a faithful copy of what the filesystem currently shows.
std::string placement_path(const FileMeta& m, const std::string& normalized) {
    if (!is_historical(m)) return normalized;
    return std::string(kVersionsDir) + "/" + normalized + "/v" + std::to_string(m.version);
}

// The components DiskSink actually creates for placement path `rel`. On POSIX
// they are the components themselves. On Windows each one goes through
// windows_host_component; when any changed, `host_rel` differs from `rel`,
// `extra["host_name"]` records it and an Info diagnostic says so. The logical
// path (FileMeta::path) is never touched.
struct HostPlacement {
    std::vector<std::string> comps;
    std::string host_rel;
};

HostPlacement host_placement(const std::string& rel, std::map<std::string, std::string>& extra,
                             std::vector<Diagnostic>& diags) {
    HostPlacement hp;
    hp.comps = split_components(rel);
    hp.host_rel = rel;
#ifdef _WIN32
    bool changed = false;
    for (std::string& c : hp.comps) {
        std::string h = detail::windows_host_component(c);
        if (h != c) changed = true;
        c = std::move(h);
    }
    if (changed) {
        std::string joined;
        for (std::size_t i = 0; i < hp.comps.size(); ++i) {
            if (i) joined.push_back('/');
            joined += hp.comps[i];
        }
        hp.host_rel = joined;
        extra["host_name"] = hp.host_rel;
        diags.push_back({Severity::Info, "sink-name-escaped",
                         "'" + rel + "' is not a valid Windows file name; written as '" +
                             hp.host_rel + "' (listing path unchanged)"});
    }
#else
    (void)extra;
    (void)diags;
#endif
    return hp;
}

// Limit checks shared by both sinks. `chunk` is trimmed to what the limits
// allow; the returned Status names the limit that tripped (or is ok).
struct LimitClamp {
    std::size_t allowed = 0;
    Status status = Status::success();
    Diagnostic diagnostic;  // valid when !status.ok
};

LimitClamp clamp_write(const Limits& lim, std::uint64_t file_so_far, std::uint64_t total_so_far,
                       std::size_t n) {
    LimitClamp r;
    r.allowed = n;
    const std::uint64_t file_room =
        lim.max_file_bytes > file_so_far ? lim.max_file_bytes - file_so_far : 0;
    const std::uint64_t total_room =
        lim.max_bytes > total_so_far ? lim.max_bytes - total_so_far : 0;
    if (static_cast<std::uint64_t>(n) > file_room) {
        r.allowed = static_cast<std::size_t>(file_room);
        r.diagnostic = {Severity::Warning, "sink-limit-file-bytes",
                        "entry exceeds max_file_bytes (" + std::to_string(lim.max_file_bytes) +
                            "); data truncated"};
        r.status = fail_code("sink-limit-file-bytes",
                             "max_file_bytes " + std::to_string(lim.max_file_bytes) + " reached");
    }
    if (static_cast<std::uint64_t>(r.allowed) > total_room) {
        r.allowed = static_cast<std::size_t>(total_room);
        // No number here: the driver hands each walk what is *left* of the
        // run's budget (discovery/Recurse.cpp), so `lim.max_bytes` is a
        // remainder that reaches 0, not the budget anyone configured. Naming
        // it read as "run exceeds max_bytes (0)". max_file_bytes above is not
        // derived that way and is safe to quote.
        r.diagnostic = {Severity::Warning, "sink-limit-bytes",
                        "the run's extraction budget (max_bytes) is exhausted; data truncated"};
        r.status = fail_code("sink-limit-bytes", "max_bytes reached");
    }
    return r;
}

Status check_file_count(const Limits& lim, std::uint64_t files_so_far) {
    if (files_so_far >= lim.max_files)
        return fail_code("sink-limit-files",
                         "max_files " + std::to_string(lim.max_files) + " reached");
    return Status::success();
}

}  // namespace

// ---------------------------------------------------------------------------
// Sink::file
// ---------------------------------------------------------------------------

Status Sink::file(const FileMeta& meta, std::span<const std::uint8_t> data, EntryResult& out) {
    Status s = begin_file(meta);
    if (!s) return s;
    // A limit tripping mid-write still leaves a (truncated) entry to finish and
    // report; end_file runs regardless so the caller gets the EntryResult.
    Status w = write(data);
    Status e = end_file(out);
    if (!e) return e;
    return w;
}

// ---------------------------------------------------------------------------
// OS layer
// ---------------------------------------------------------------------------

namespace {

#ifdef _WIN32

// A verified directory is identified by its absolute wide path. Every step of
// the walk re-checks the attributes of the component it is about to descend
// into, so a reparse point (symlink/junction) planted by an earlier entry is
// never crossed.
struct DirRef {
    std::wstring path;
};
struct FileRef {
    HANDLE h = INVALID_HANDLE_VALUE;
    bool valid() const { return h != INVALID_HANDLE_VALUE; }
};

std::wstring to_wide(const std::string& utf8) {
    if (utf8.empty()) return {};
    const int n =
        MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), w.data(), n);
    return w;
}

std::string last_error_text(DWORD err) {
    LPWSTR buf = nullptr;
    const DWORD len = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, 0, reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    std::string out = "error " + std::to_string(err);
    if (len && buf) {
        const int n = WideCharToMultiByte(CP_UTF8, 0, buf, static_cast<int>(len), nullptr, 0,
                                          nullptr, nullptr);
        if (n > 0) {
            std::string s(static_cast<std::size_t>(n), '\0');
            WideCharToMultiByte(CP_UTF8, 0, buf, static_cast<int>(len), s.data(), n, nullptr,
                                nullptr);
            while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' '))
                s.pop_back();
            out = s;
        }
        LocalFree(buf);
    }
    return out;
}

std::wstring join_wide(const std::wstring& dir, const std::string& comp) {
    return dir + L"\\" + to_wide(comp);
}

Status open_root_dir(const std::string& root, DirRef& out) {
    std::wstring w = to_wide(root);
    if (w.empty()) return fail_code("sink-root-invalid", "root path is empty or not valid UTF-8");
    // Resolve to an absolute path so later joins are unambiguous.
    const DWORD need = GetFullPathNameW(w.c_str(), 0, nullptr, nullptr);
    if (need == 0) return fail_code("sink-root-invalid", last_error_text(GetLastError()));
    std::wstring full(need, L'\0');
    const DWORD got = GetFullPathNameW(w.c_str(), need, full.data(), nullptr);
    if (got == 0 || got >= need)
        return fail_code("sink-root-invalid", last_error_text(GetLastError()));
    full.resize(got);
    while (full.size() > 3 && (full.back() == L'\\' || full.back() == L'/')) full.pop_back();
    const DWORD attrs = GetFileAttributesW(full.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectoryW(full.c_str(), nullptr))
            return fail_code("sink-root-invalid",
                             "cannot create root: " + last_error_text(GetLastError()));
    } else if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        return fail_code("sink-root-invalid", "root is not a directory");
    }
    out.path = std::move(full);
    return Status::success();
}

void close_dir(DirRef&, const DirRef&) {}

// Open (creating when absent) `comp` inside `parent`. Refuses anything that is
// not a plain directory: a reparse point is a symlink/junction that could point
// anywhere on the host.
Status enter_subdir(const DirRef& parent, const std::string& comp, DirRef& out) {
    std::wstring p = join_wide(parent.path, comp);
    DWORD attrs = GetFileAttributesW(p.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectoryW(p.c_str(), nullptr)) {
            const DWORD err = GetLastError();
            if (err != ERROR_ALREADY_EXISTS)
                return fail_code("sink-io-error", "mkdir '" + comp + "': " + last_error_text(err));
        }
        attrs = GetFileAttributesW(p.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES)
            return fail_code("sink-io-error",
                             "stat '" + comp + "': " + last_error_text(GetLastError()));
    }
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT)
        return fail_code("sink-symlink-component", "'" + comp + "' is a reparse point");
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY))
        return fail_code("sink-not-directory", "'" + comp + "' exists and is not a directory");
    out.path = std::move(p);
    return Status::success();
}

// 0 = created, 1 = already exists, -1 = other error (detail filled).
int create_new_file(const DirRef& dir, const std::string& name, FileRef& out, std::string& detail) {
    std::wstring p = join_wide(dir.path, name);
    HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS) return 1;
        detail = last_error_text(err);
        return -1;
    }
    out.h = h;
    return 0;
}

Status write_all(FileRef& f, std::span<const std::uint8_t> data) {
    std::size_t off = 0;
    while (off < data.size()) {
        const std::size_t want = std::min<std::size_t>(data.size() - off, 1u << 30);
        DWORD wrote = 0;
        if (!WriteFile(f.h, data.data() + off, static_cast<DWORD>(want), &wrote, nullptr))
            return fail_code("sink-io-error", "write: " + last_error_text(GetLastError()));
        if (wrote == 0) return fail_code("sink-io-error", "write: no progress");
        off += wrote;
    }
    return Status::success();
}

FILETIME to_filetime(std::int64_t unix_seconds, std::uint32_t nsec) {
    // FILETIME is 100ns ticks since 1601-01-01.
    const std::int64_t ticks =
        (unix_seconds + 11644473600LL) * 10000000LL + static_cast<std::int64_t>(nsec / 100u);
    ULARGE_INTEGER u;
    u.QuadPart = static_cast<ULONGLONG>(ticks);
    FILETIME ft;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    return ft;
}

// Mode bits do not map onto NTFS ACLs; the one faithful signal is "not
// writable by owner" -> read-only attribute.
void apply_mode(FileRef&, const DirRef& dir, const std::string& name, std::uint32_t mode) {
    std::wstring p = join_wide(dir.path, name);
    DWORD attrs = GetFileAttributesW(p.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return;
    if ((mode & 0200u) == 0)
        attrs |= FILE_ATTRIBUTE_READONLY;
    else
        attrs &= ~static_cast<DWORD>(FILE_ATTRIBUTE_READONLY);
    SetFileAttributesW(p.c_str(), attrs);
}

void apply_mtime(FileRef& f, std::int64_t mtime, std::uint32_t nsec) {
    if (mtime < -11644473600LL) return;  // before FILETIME epoch
    const FILETIME ft = to_filetime(mtime, nsec);
    SetFileTime(f.h, nullptr, nullptr, &ft);
}

void close_file(FileRef& f) {
    if (f.valid()) CloseHandle(f.h);
    f.h = INVALID_HANDLE_VALUE;
}

// Directory attributes: Windows keeps directory mtimes current as children
// arrive, and read-only on a directory has no effect on creation, so nothing
// to do here.
void apply_dir_attrs(const DirRef&, std::uint32_t, std::optional<std::int64_t>, std::uint32_t) {}

// 0 = created, 1 = exists, 2 = unsupported on this host, -1 = error.
int create_symlink(const DirRef& dir, const std::string& name, const std::string& target,
                   std::string& detail) {
    std::wstring p = join_wide(dir.path, name);
    const std::wstring t = to_wide(target);
    // Refuse to overwrite: CreateSymbolicLinkW fails on an existing name.
    const DWORD existing = GetFileAttributesW(p.c_str());
    if (existing != INVALID_FILE_ATTRIBUTES) return 1;
    const DWORD flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
    if (CreateSymbolicLinkW(p.c_str(), t.c_str(), flags)) return 0;
    const DWORD err = GetLastError();
    if (err == ERROR_ALREADY_EXISTS || err == ERROR_FILE_EXISTS) return 1;
    if (err == ERROR_PRIVILEGE_NOT_HELD || err == ERROR_INVALID_PARAMETER ||
        err == ERROR_NOT_SUPPORTED) {
        detail = last_error_text(err);
        return 2;
    }
    detail = last_error_text(err);
    return -1;
}

void apply_symlink_mtime(const DirRef&, const std::string&, std::int64_t, std::uint32_t) {}

std::string host_path_of(const std::string& root, const std::string& rel) {
    std::string out = root;
    if (!out.empty() && out.back() != '\\' && out.back() != '/') out.push_back('\\');
    for (const char c : rel) out.push_back(c == '/' ? '\\' : c);
    return out;
}

#else  // POSIX

struct DirRef {
    int fd = -1;
};
struct FileRef {
    int fd = -1;
    bool valid() const { return fd >= 0; }
};

Status open_root_dir(const std::string& root, DirRef& out) {
    if (root.empty()) return fail_code("sink-root-invalid", "root path is empty");
    if (::mkdir(root.c_str(), 0755) != 0 && errno != EEXIST)
        return fail_code("sink-root-invalid", "cannot create root: " + errno_text(errno));
    const int fd = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return fail_code("sink-root-invalid",
                         "cannot open root as a directory: " + errno_text(errno));
    out.fd = fd;
    return Status::success();
}

void close_dir(DirRef& d, const DirRef& root) {
    if (d.fd >= 0 && d.fd != root.fd) ::close(d.fd);
    d.fd = -1;
}

Status enter_subdir(const DirRef& parent, const std::string& comp, DirRef& out) {
    if (::mkdirat(parent.fd, comp.c_str(), 0755) != 0 && errno != EEXIST)
        return fail_code("sink-io-error", "mkdir '" + comp + "': " + errno_text(errno));
    // O_NOFOLLOW: if `comp` is a symlink (planted earlier), this fails with
    // ELOOP rather than descending through it; O_DIRECTORY rejects plain files.
    const int fd =
        ::openat(parent.fd, comp.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        const int err = errno;
        // Linux reports a symlink here as ENOTDIR (some kernels/FSes: ELOOP);
        // ask the inode itself so the diagnostic names the real cause.
        if (err == ELOOP || err == ENOTDIR) {
            struct stat st{};
            if (::fstatat(parent.fd, comp.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0 &&
                S_ISLNK(st.st_mode))
                return fail_code("sink-symlink-component", "'" + comp + "' is a symlink");
            return fail_code("sink-not-directory", "'" + comp + "' exists and is not a directory");
        }
        return fail_code("sink-io-error", "open '" + comp + "': " + errno_text(err));
    }
    out.fd = fd;
    return Status::success();
}

int create_new_file(const DirRef& dir, const std::string& name, FileRef& out, std::string& detail) {
    const int fd =
        ::openat(dir.fd, name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        const int err = errno;
        if (err == EEXIST) return 1;
        detail = errno_text(err);
        return -1;
    }
    out.fd = fd;
    return 0;
}

Status write_all(FileRef& f, std::span<const std::uint8_t> data) {
    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::write(f.fd, data.data() + off, data.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return fail_code("sink-io-error", "write: " + errno_text(errno));
        }
        if (n == 0) return fail_code("sink-io-error", "write: no progress");
        off += static_cast<std::size_t>(n);
    }
    return Status::success();
}

void apply_mode(FileRef& f, const DirRef&, const std::string&, std::uint32_t mode) {
    // Permission bits only. setuid/setgid/sticky must never be recreated on the
    // examiner's machine.
    ::fchmod(f.fd, static_cast<mode_t>(mode & 0777u));
}

void apply_mtime(FileRef& f, std::int64_t mtime, std::uint32_t nsec) {
    timespec ts[2];
    ts[0].tv_sec = 0;
    ts[0].tv_nsec = UTIME_OMIT;  // atime: leave alone
    ts[1].tv_sec = static_cast<time_t>(mtime);
    ts[1].tv_nsec = static_cast<long>(nsec % 1000000000u);
    ::futimens(f.fd, ts);
}

void close_file(FileRef& f) {
    if (f.fd >= 0) ::close(f.fd);
    f.fd = -1;
}

// Directories: keep owner rwx so later entries can still be created beneath
// them; mtime is not applied because every child creation would clobber it.
void apply_dir_attrs(const DirRef& d, std::uint32_t mode, std::optional<std::int64_t>,
                     std::uint32_t) {
    ::fchmod(d.fd, static_cast<mode_t>((mode & 0777u) | 0700u));
}

int create_symlink(const DirRef& dir, const std::string& name, const std::string& target,
                   std::string& detail) {
    if (::symlinkat(target.c_str(), dir.fd, name.c_str()) == 0) return 0;
    const int err = errno;
    if (err == EEXIST) return 1;
    detail = errno_text(err);
    return -1;
}

void apply_symlink_mtime(const DirRef& dir, const std::string& name, std::int64_t mtime,
                         std::uint32_t nsec) {
    timespec ts[2];
    ts[0].tv_sec = 0;
    ts[0].tv_nsec = UTIME_OMIT;
    ts[1].tv_sec = static_cast<time_t>(mtime);
    ts[1].tv_nsec = static_cast<long>(nsec % 1000000000u);
    ::utimensat(dir.fd, name.c_str(), ts, AT_SYMLINK_NOFOLLOW);
}

std::string host_path_of(const std::string& root, const std::string& rel) {
    std::string out = root;
    if (!out.empty() && out.back() != '/') out.push_back('/');
    out += rel;
    return out;
}

#endif

// Walk every component but the last, creating directories as needed. On
// success `out` is the parent directory (closed by the caller via close_dir)
// and `leaf` the final component. `comps` must not be empty.
Status open_parent(const DirRef& root, const std::vector<std::string>& comps, DirRef& out,
                   std::string& leaf) {
    DirRef cur = root;
    for (std::size_t i = 0; i + 1 < comps.size(); ++i) {
        DirRef next;
        Status s = enter_subdir(cur, comps[i], next);
        close_dir(cur, root);
        if (!s) return s;
        cur = next;
    }
    out = cur;
    leaf = comps.back();
    return Status::success();
}

}  // namespace

// ---------------------------------------------------------------------------
// DiskSink
// ---------------------------------------------------------------------------

// In-flight regular file for DiskSink. Kept at namespace scope rather than
// nested in Impl: a nested class's default member initializers are a
// complete-class context of the *enclosing* class, so clang cannot evaluate
// is_constructible_v<Current> (needed by std::optional::emplace) while Impl
// is still being defined.
struct DiskSinkCurrent {
    FileMeta meta;
    std::string rel;  // placement path actually used (after dedupe)
    FileRef file;
    Hasher hasher;
    std::uint64_t written = 0;
    bool truncated = false;
    std::vector<Diagnostic> diagnostics;
};

struct DiskSink::Impl {
    std::string root_path;
    DirRef root;
    Options opts;
    std::uint64_t files = 0;
    std::uint64_t bytes = 0;
    // Next "~<n>" suffix to try per placement path, so a burst of duplicates
    // does not rescan from ~1 each time.
    std::map<std::string, unsigned> dup_counters;

    using Current = DiskSinkCurrent;
    std::optional<Current> cur;

    ~Impl() {
        if (cur) close_file(cur->file);
        close_root();
    }
    void close_root() {
#ifndef _WIN32
        if (root.fd >= 0) ::close(root.fd);
        root.fd = -1;
#endif
    }

    // Try leaf, leaf~1, leaf~2, ... until one is created. `make` returns
    // 0 created, 1 exists, -1 error (detail set). Fills `used` with the leaf
    // name that succeeded and adds the duplicate diagnostic when needed.
    template <class Make>
    Status create_unique(const std::string& rel, const std::string& leaf, Make make,
                         std::string& used, std::vector<Diagnostic>& diags) {
        std::string detail;
        int rc = make(leaf, detail);
        if (rc == 0) {
            used = leaf;
            return Status::success();
        }
        if (rc < 0) return fail_code("sink-io-error", "create '" + rel + "': " + detail);
        unsigned& n = dup_counters[rel];
        if (n == 0) n = 1;
        // Bounded by max_files: each attempt corresponds to an existing entry.
        for (std::uint64_t tries = 0; tries <= opts.limits.max_files + 1; ++tries, ++n) {
            const std::string cand = leaf + "~" + std::to_string(n);
            rc = make(cand, detail);
            if (rc == 0) {
                used = cand;
                ++n;
                diags.push_back(
                    {Severity::Warning, "sink-duplicate-path",
                     "'" + rel + "' already exists on disk; written as '" + cand + "'"});
                return Status::success();
            }
            if (rc < 0) return fail_code("sink-io-error", "create '" + rel + "': " + detail);
        }
        return fail_code("sink-duplicate-path", "no free '~<n>' suffix for '" + rel + "'");
    }
};

Status DiskSink::open(const std::string& root_dir, Options opts, std::unique_ptr<DiskSink>& out) {
    out.reset();
    auto impl = std::make_unique<Impl>();
    impl->root_path = root_dir;
    impl->opts = opts;
    Status s = open_root_dir(root_dir, impl->root);
    if (!s) return s;
    std::unique_ptr<DiskSink> sink(new DiskSink());
    sink->impl_ = std::move(impl);
    out = std::move(sink);
    return Status::success();
}

DiskSink::~DiskSink() = default;

const Limits& DiskSink::limits() const {
    return impl_->opts.limits;
}
std::uint64_t DiskSink::files_emitted() const {
    return impl_->files;
}
std::uint64_t DiskSink::bytes_emitted() const {
    return impl_->bytes;
}
const std::string& DiskSink::root() const {
    return impl_->root_path;
}

Status DiskSink::begin_file(const FileMeta& meta) {
    Impl& im = *impl_;
    if (im.cur)
        return fail_code("sink-protocol", "begin_file while '" + im.cur->rel + "' is still open");
    std::string norm, why;
    if (!normalize_entry_path(meta.path, norm, &why))
        return fail_code("sink-unsafe-path", why + " ('" + meta.path + "')");
    if (Status s = check_file_count(im.opts.limits, im.files); !s) return s;

    // Hasher is neither copyable nor movable, so the in-flight state is built
    // in place and dropped again if anything below refuses the entry.
    Impl::Current& cur = im.cur.emplace();
    cur.meta = meta;
    cur.meta.path = norm;

    if (is_historical(meta) && !im.opts.write_versions) {
        // Recorded (hashed, counted) but never lands on disk.
        cur.diagnostics.push_back(
            {Severity::Info, "sink-version-skipped",
             "historical version of '" + norm + "' not written (write_versions=false)"});
        return Status::success();
    }

    const std::string rel = placement_path(meta, norm);
    const HostPlacement hp = host_placement(rel, cur.meta.extra, cur.diagnostics);
    DirRef parent;
    std::string leaf;
    if (Status s = open_parent(im.root, hp.comps, parent, leaf); !s) {
        im.cur.reset();
        return s;
    }

    std::string used;
    Status s = im.create_unique(
        hp.host_rel, leaf,
        [&](const std::string& name, std::string& detail) {
            return create_new_file(parent, name, cur.file, detail);
        },
        used, cur.diagnostics);
    if (s) {
        cur.rel = hp.host_rel.substr(0, hp.host_rel.size() - leaf.size()) + used;
        if (im.opts.preserve_mode) apply_mode(cur.file, parent, used, meta.mode);
    } else {
        im.cur.reset();
    }
    close_dir(parent, im.root);
    return s;
}

Status DiskSink::write(std::span<const std::uint8_t> data) {
    Impl& im = *impl_;
    if (!im.cur) return fail_code("sink-protocol", "write without an open file");
    Impl::Current& cur = *im.cur;
    if (data.empty()) return Status::success();
    if (cur.truncated) return fail_code("sink-limit-file-bytes", "entry already truncated");

    const LimitClamp clamp = clamp_write(im.opts.limits, cur.written, im.bytes, data.size());
    const std::span<const std::uint8_t> part = data.first(clamp.allowed);
    if (!part.empty()) {
        if (cur.file.valid()) {
            if (Status s = write_all(cur.file, part); !s) {
                cur.diagnostics.push_back({Severity::Error, "sink-io-error", s.error});
                cur.truncated = true;
                return s;
            }
            im.bytes += part.size();
        }
        if (im.opts.hash) cur.hasher.update(part);
        cur.written += part.size();
    }
    if (!clamp.status) {
        cur.truncated = true;
        cur.diagnostics.push_back(clamp.diagnostic);
        return clamp.status;
    }
    return Status::success();
}

Status DiskSink::end_file(EntryResult& out) {
    Impl& im = *impl_;
    if (!im.cur) return fail_code("sink-protocol", "end_file without an open file");
    Impl::Current& cur = *im.cur;

    out = EntryResult{};
    out.meta = std::move(cur.meta);
    out.truncated = cur.truncated;
    out.diagnostics = std::move(cur.diagnostics);
    if (im.opts.hash) {
        out.digests = cur.hasher.finish();
        out.digests.bytes = cur.written;
    }
    if (cur.file.valid()) {
        if (im.opts.preserve_times && out.meta.mtime)
            apply_mtime(cur.file, *out.meta.mtime, out.meta.mtime_nsec.value_or(0));
        close_file(cur.file);
        out.host_path = host_path_of(im.root_path, cur.rel);
        out.written = true;
    }
    im.cur.reset();
    ++im.files;
    return Status::success();
}

Status DiskSink::entry(const FileMeta& meta, EntryResult& out) {
    Impl& im = *impl_;
    if (im.cur)
        return fail_code("sink-protocol", "entry while '" + im.cur->rel + "' is still open");
    if (meta.kind == EntryKind::Regular) {
        // A regular file through entry() is an empty file.
        if (Status s = begin_file(meta); !s) return s;
        return end_file(out);
    }
    std::string norm, why;
    if (!normalize_entry_path(meta.path, norm, &why))
        return fail_code("sink-unsafe-path", why + " ('" + meta.path + "')");
    if (Status s = check_file_count(im.opts.limits, im.files); !s) return s;

    out = EntryResult{};
    out.meta = meta;
    out.meta.path = norm;

    auto finish = [&](Status s) {
        if (s) ++im.files;
        return s;
    };

    switch (meta.kind) {
        case EntryKind::Directory:
        case EntryKind::Symlink:
            break;
        case EntryKind::CharDevice:
        case EntryKind::BlockDevice:
        case EntryKind::Fifo:
        case EntryKind::Socket:
        case EntryKind::Unknown:
        case EntryKind::Regular:
            out.diagnostics.push_back({Severity::Info, "sink-special-skipped",
                                       std::string(entry_kind_name(meta.kind)) + " '" + norm +
                                           "' recorded but not created"});
            return finish(Status::success());
    }

    if (is_historical(meta) && !im.opts.write_versions) {
        out.diagnostics.push_back(
            {Severity::Info, "sink-version-skipped",
             "historical version of '" + norm + "' not written (write_versions=false)"});
        return finish(Status::success());
    }

    const std::string rel = placement_path(meta, norm);
    const HostPlacement hp = host_placement(rel, out.meta.extra, out.diagnostics);

    if (meta.kind == EntryKind::Directory) {
        DirRef cur = im.root;
        for (const std::string& comp : hp.comps) {
            DirRef next;
            Status s = enter_subdir(cur, comp, next);
            close_dir(cur, im.root);
            if (!s) return s;
            cur = next;
        }
        if (im.opts.preserve_mode)
            apply_dir_attrs(cur, meta.mode, meta.mtime, meta.mtime_nsec.value_or(0));
        close_dir(cur, im.root);
        out.host_path = host_path_of(im.root_path, hp.host_rel);
        out.written = true;
        return finish(Status::success());
    }

    // Symlink: the target is stored verbatim and never resolved by us. An
    // empty target, or one holding a NUL byte (a deleted record whose data
    // block was reused or zeroed), can be created on no host: symlinkat sees
    // "" and fails with ENOENT. Such an entry is recorded, not written.
    if (meta.link_target.empty() || meta.link_target.find('\0') != std::string::npos) {
        out.diagnostics.push_back(
            {Severity::Warning, "sink-symlink-bad-target",
             "symlink '" + norm +
                 "' has an empty target or one with a NUL byte; recorded but not created"});
        return finish(Status::success());
    }
    DirRef parent;
    std::string leaf;
    if (Status s = open_parent(im.root, hp.comps, parent, leaf); !s) return s;
    bool unsupported = false;
    std::string used;
    Status s = im.create_unique(
        hp.host_rel, leaf,
        [&](const std::string& name, std::string& detail) {
            const int rc = create_symlink(parent, name, meta.link_target, detail);
            if (rc == 2) {
                unsupported = true;
                return 0;  // treated as handled; reported below
            }
            return rc;
        },
        used, out.diagnostics);
    if (s) {
        if (unsupported) {
            out.diagnostics.push_back({Severity::Warning, "sink-symlink-unsupported",
                                       "symlink '" + norm + "' -> '" + meta.link_target +
                                           "' recorded but not created on this host"});
        } else {
            if (im.opts.preserve_times && meta.mtime)
                apply_symlink_mtime(parent, used, *meta.mtime, meta.mtime_nsec.value_or(0));
            out.host_path = host_path_of(
                im.root_path, hp.host_rel.substr(0, hp.host_rel.size() - leaf.size()) + used);
            out.written = true;
        }
    }
    close_dir(parent, im.root);
    return finish(s);
}

// ---------------------------------------------------------------------------
// ListingSink
// ---------------------------------------------------------------------------

// See DiskSinkCurrent for why this is not nested in Impl.
struct ListingSinkCurrent {
    EntryResult result;
    Hasher hasher;
    std::uint64_t written = 0;
};

struct ListingSink::Impl {
    bool hash = false;
    Limits limits;
    std::uint64_t files = 0;
    std::uint64_t bytes = 0;
    std::vector<EntryResult> entries;

    using Current = ListingSinkCurrent;
    std::optional<Current> cur;
};

ListingSink::ListingSink(bool hash, Limits limits) : impl_(std::make_unique<Impl>()) {
    impl_->hash = hash;
    impl_->limits = limits;
}

ListingSink::~ListingSink() = default;

const Limits& ListingSink::limits() const {
    return impl_->limits;
}
std::uint64_t ListingSink::files_emitted() const {
    return impl_->files;
}
std::uint64_t ListingSink::bytes_emitted() const {
    return impl_->bytes;
}
const std::vector<EntryResult>& ListingSink::entries() const {
    return impl_->entries;
}

Status ListingSink::begin_file(const FileMeta& meta) {
    Impl& im = *impl_;
    if (im.cur)
        return fail_code("sink-protocol",
                         "begin_file while '" + im.cur->result.meta.path + "' is still open");
    std::string norm, why;
    if (!normalize_entry_path(meta.path, norm, &why))
        return fail_code("sink-unsafe-path", why + " ('" + meta.path + "')");
    if (Status s = check_file_count(im.limits, im.files); !s) return s;
    Impl::Current& cur = im.cur.emplace();
    cur.result.meta = meta;
    cur.result.meta.path = norm;
    return Status::success();
}

Status ListingSink::write(std::span<const std::uint8_t> data) {
    Impl& im = *impl_;
    if (!im.cur) return fail_code("sink-protocol", "write without an open file");
    Impl::Current& cur = *im.cur;
    if (data.empty()) return Status::success();
    if (cur.result.truncated) return fail_code("sink-limit-file-bytes", "entry already truncated");
    const LimitClamp clamp = clamp_write(im.limits, cur.written, im.bytes, data.size());
    const std::span<const std::uint8_t> part = data.first(clamp.allowed);
    if (im.hash) cur.hasher.update(part);
    cur.written += part.size();
    im.bytes += part.size();
    if (!clamp.status) {
        cur.result.truncated = true;
        cur.result.diagnostics.push_back(clamp.diagnostic);
        return clamp.status;
    }
    return Status::success();
}

Status ListingSink::end_file(EntryResult& out) {
    Impl& im = *impl_;
    if (!im.cur) return fail_code("sink-protocol", "end_file without an open file");
    Impl::Current& cur = *im.cur;
    out = std::move(cur.result);
    if (im.hash) {
        out.digests = cur.hasher.finish();
        out.digests.bytes = cur.written;
    }
    out.written = false;
    out.host_path.clear();
    im.entries.push_back(out);
    im.cur.reset();
    ++im.files;
    return Status::success();
}

Status ListingSink::entry(const FileMeta& meta, EntryResult& out) {
    Impl& im = *impl_;
    if (im.cur)
        return fail_code("sink-protocol",
                         "entry while '" + im.cur->result.meta.path + "' is still open");
    if (meta.kind == EntryKind::Regular) {
        if (Status s = begin_file(meta); !s) return s;
        return end_file(out);
    }
    std::string norm, why;
    if (!normalize_entry_path(meta.path, norm, &why))
        return fail_code("sink-unsafe-path", why + " ('" + meta.path + "')");
    if (Status s = check_file_count(im.limits, im.files); !s) return s;
    out = EntryResult{};
    out.meta = meta;
    out.meta.path = norm;
    im.entries.push_back(out);
    ++im.files;
    return Status::success();
}

}  // namespace omnitrace
