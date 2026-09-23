// ArReader.cpp — ar archives: static libraries, .deb, .ipk.
//
// The format is the simplest here: a magic, then 60-byte headers each
// followed by data padded to an even offset. Every field is ASCII and space
// padded, and none of them is NUL terminated, so a name is 16 bytes of text
// and a size is up to 10 characters of decimal.
//
// Two things make it less simple than it looks.
//
// **A name is not a name.** `/108` means "offset 108 of the `//` member",
// which is one string table holding every name too long for 16 bytes. `#1/13`
// means "the first 13 bytes of my data are my name, and my recorded size
// includes them". Emitting either verbatim produces a case directory full of
// files called `/108`, which is what an archive of object files with long
// names looks like when a reader does not resolve them — and a cross
// toolchain's libgcc.a is entirely long names.
//
// **Two members are not files.** The symbol table (`/`, or `__.SYMDEF` on
// BSD) and the string table (`//`) are the archive's own indexes. unsquashfs's
// equivalent, `ar t`, does not list them and neither does unblob; emitting
// them would put two files in every extracted static library that were never
// in the source tree. Their presence is recorded in `attrs` instead.
//
// Reference: `ar.h` / the System V and BSD archive formats.
#include "ArReader.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "../common.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::container {

namespace detail {
void omnitrace_container_anchor_ar() {}
}  // namespace detail

namespace {

constexpr std::uint64_t kMagicLen = 8;
constexpr std::uint64_t kHeaderLen = 60;
constexpr std::size_t kMaxStringTable = 16U << 20;  // a name table larger than this is not one

constexpr const char* kCodeBadHeader = "ar-bad-header";
constexpr const char* kCodeTruncated = "ar-truncated-member";
constexpr const char* kCodeLimitEntries = "ar-limit-entries";
constexpr const char* kCodeBadName = "ar-bad-name";
constexpr const char* kCodeSinkError = "ar-sink-error";

std::string dec(std::uint64_t v) {
    return std::to_string(v);
}

/// An ASCII field, space padded, in `base`. `nullopt` when it is not a number.
std::optional<std::uint64_t> ascii_num(const std::uint8_t* p, std::size_t len, unsigned base) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < len; ++i) {
        const std::uint8_t c = p[i];
        if (c == ' ') {
            for (std::size_t j = i; j < len; ++j) {
                if (p[j] != ' ') return std::nullopt;
            }
            break;
        }
        if (c < '0' || c > '9') return std::nullopt;
        const auto d = static_cast<unsigned>(c - '0');
        if (d >= base) return std::nullopt;
        if (v > (0xFFFFFFFFFFFFFFFFULL - d) / base) return std::nullopt;
        v = (v * base) + d;
    }
    return v;
}

/// A member name is a path component, and only that: a separator or a `..`
/// would move the extracted file somewhere the archive never named.
bool safe_name(const std::string& n) {
    return !n.empty() && n != "." && n != ".." && n.find('/') == std::string::npos &&
           n.find('\\') == std::string::npos && n.find('\0') == std::string::npos;
}

}  // namespace

// ------------------------------------------------------------------ members

std::string ArReader::long_name(std::uint64_t offset) const {
    if (offset >= strings_.size()) return {};
    // GNU terminates each name with "/\n"; some writers use only "\n".
    std::size_t end = static_cast<std::size_t>(offset);
    while (end < strings_.size() && strings_[end] != '\n') ++end;
    std::size_t stop = end;
    if (stop > offset && strings_[stop - 1] == '/') --stop;
    return std::string(reinterpret_cast<const char*>(strings_.data() + offset),
                       stop - static_cast<std::size_t>(offset));
}

ArReader::Member ArReader::read_member(std::uint64_t pos) const {
    Member m;
    m.header_at = pos;
    if (pos + kHeaderLen > span_.size()) return m;
    const auto raw = span_.bytes(pos, kHeaderLen);
    if (!raw) return m;
    const std::uint8_t* h = raw->data();
    if (h[58] != 0x60 || h[59] != 0x0A) return m;

    const auto size = ascii_num(h + 48, 10, 10);
    const auto mtime = ascii_num(h + 16, 12, 10);
    const auto uid = ascii_num(h + 28, 6, 10);
    const auto gid = ascii_num(h + 34, 6, 10);
    const auto mode = ascii_num(h + 40, 8, 8);
    if (!size || !mtime || !uid || !gid || !mode) return m;

    m.size = *size;
    m.mtime = *mtime;
    m.uid = static_cast<std::uint32_t>(*uid);
    m.gid = static_cast<std::uint32_t>(*gid);
    m.mode = static_cast<std::uint32_t>(*mode);
    m.data_at = pos + kHeaderLen;
    const std::uint64_t padded = m.size + (m.size & 1U);
    m.next = m.data_at + padded;

    std::string field(reinterpret_cast<const char*>(h), 16);
    // Trailing spaces are padding; a name may contain a space before them,
    // which is why GNU marks the end with a slash rather than trimming.
    while (!field.empty() && field.back() == ' ') field.pop_back();

    if (field == "/" || field == "__.SYMDEF" || field.rfind("__.SYMDEF", 0) == 0) {
        m.is_table = true;
        m.name = field;
    } else if (field == "//") {
        m.is_table = true;
        m.name = field;
    } else if (field.size() > 1 && field[0] == '/' &&
               field.find_first_not_of("0123456789", 1) == std::string::npos) {
        // GNU long name: an offset into the string table.
        const auto off = ascii_num(reinterpret_cast<const std::uint8_t*>(field.data()) + 1,
                                   field.size() - 1, 10);
        m.name = off ? long_name(*off) : std::string{};
    } else if (field.size() > 3 && field.rfind("#1/", 0) == 0) {
        // BSD long name: it is the first `len` bytes of the data, and the
        // recorded size covers them.
        const auto len = ascii_num(reinterpret_cast<const std::uint8_t*>(field.data()) + 3,
                                   field.size() - 3, 10);
        if (len && *len <= m.size) {
            if (const auto nb = span_.bytes(m.data_at, *len)) {
                m.name.assign(nb->begin(), nb->end());
                // A BSD name is NUL padded to a multiple of four.
                const std::size_t z = m.name.find('\0');
                if (z != std::string::npos) m.name.resize(z);
            }
            m.data_at += *len;
            m.size -= *len;
        }
    } else {
        if (!field.empty() && field.back() == '/') field.pop_back();  // GNU short
        m.name = field;
    }
    m.ok = true;
    return m;
}

void ArReader::load_string_table() {
    strings_.clear();
    std::uint64_t pos = kMagicLen;
    // The string table is one of the first members, so a bounded look is
    // enough; a member's name cannot be resolved before it is loaded.
    for (int i = 0; i < 4 && pos + kHeaderLen <= span_.size(); ++i) {
        const auto raw = span_.bytes(pos, kHeaderLen);
        if (!raw || (*raw)[58] != 0x60 || (*raw)[59] != 0x0A) return;
        const auto size = ascii_num(raw->data() + 48, 10, 10);
        if (!size) return;
        std::string field(reinterpret_cast<const char*>(raw->data()), 16);
        while (!field.empty() && field.back() == ' ') field.pop_back();
        if (field == "//") {
            if (*size <= kMaxStringTable) {
                if (auto t = span_.bytes(pos + kHeaderLen, *size)) strings_ = std::move(*t);
            }
            return;
        }
        pos += kHeaderLen + *size + (*size & 1U);
    }
}

// ------------------------------------------------------------------ public

Status ArReader::open(const Span& span) {
    span_ = span;
    opened_ = false;
    strings_.clear();
    members_ = total_ = data_bytes_ = 0;
    has_symbol_table_ = has_string_table_ = bsd_names_ = false;

    const auto magic = span_.bytes(0, kMagicLen);
    if (!magic) return Status::fail("container-empty: fewer than 8 bytes for the ar magic");
    if (std::memcmp(magic->data(), "!<arch>\n", kMagicLen) != 0)
        return Status::fail("container-bad-magic: no '!<arch>' at offset 0");

    load_string_table();

    // One pass to count and to find the end: the format has no trailer, so
    // the last member's data *is* the end.
    std::uint64_t pos = kMagicLen;
    total_ = kMagicLen;
    while (pos + kHeaderLen <= span_.size()) {
        const Member m = read_member(pos);
        if (!m.ok || m.next <= pos || m.next > span_.size()) break;
        if (m.is_table) {
            if (m.name == "//")
                has_string_table_ = true;
            else
                has_symbol_table_ = true;
        } else {
            ++members_;
            data_bytes_ += m.size;
        }
        pos = m.next;
        total_ = pos;
    }
    if (members_ == 0 && !has_symbol_table_ && !has_string_table_)
        return Status::fail("container-bad-header: no member header follows the ar magic");
    opened_ = true;
    return Status::success();
}

ContainerInfo ArReader::info() const {
    ContainerInfo ci;
    ci.format = "ar";
    if (!opened_) return ci;
    ci.size = total_;
    ci.attrs["members"] = dec(members_);
    ci.attrs["data_bytes"] = dec(data_bytes_);
    if (has_symbol_table_) ci.attrs["symbol_table"] = "true";
    if (has_string_table_) ci.attrs["string_table"] = "true";
    if (bsd_names_) ci.attrs["bsd_long_names"] = "true";
    return ci;
}

Status ArReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    if (!opened_) return Status::fail("container-not-open: walk before a successful open");

    const std::uint64_t cap = opts.limits.max_nodes_per_fs;
    std::uint64_t pos = kMagicLen;
    std::uint64_t unnamed = 0;

    while (pos + kHeaderLen <= span_.size()) {
        if (out.entries >= cap) {
            out.diagnostics.push_back({Severity::Warning, kCodeLimitEntries,
                                       "max_nodes_per_fs (" + dec(cap) +
                                           ") reached; the rest of the archive was not walked"});
            out.truncated = true;
            break;
        }
        const Member m = read_member(pos);
        if (!m.ok) {
            // A header that stops making sense ends the archive. Saying so is
            // only useful when something came before it; a first bad header
            // was already refused by open().
            out.diagnostics.push_back({Severity::Warning, kCodeBadHeader,
                                       "the member header at offset " + dec(pos) +
                                           " is not one; the archive ends there"});
            out.truncated = true;
            break;
        }
        if (m.next <= pos) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeBadHeader,
                 "the member at offset " + dec(pos) + " does not advance; stopping"});
            out.truncated = true;
            break;
        }
        if (m.is_table) {  // archive metadata, not a file
            pos = m.next;
            continue;
        }

        std::string name = sanitize_utf8(m.name);
        if (!safe_name(name)) {
            // A name that would escape the extraction root, or that the string
            // table could not supply, still identifies a member: give it one
            // derived from where it is, so the bytes are not lost.
            ++unnamed;
            out.diagnostics.push_back({Severity::Warning, kCodeBadName,
                                       "the member at offset " + dec(pos) +
                                           " has no usable name ('" + name +
                                           "'); emitted as member-" + dec(unnamed)});
            name = "member-" + dec(unnamed);
        }

        FileMeta meta;
        meta.path = name;
        meta.kind = EntryKind::Regular;
        meta.mode = m.mode & 07777U;
        meta.uid = m.uid;
        meta.gid = m.gid;
        if (m.mtime != 0) meta.mtime = static_cast<std::int64_t>(m.mtime);
        meta.nlink = 1;
        meta.size = std::min<std::uint64_t>(m.size, span_.size() - m.data_at);

        EntryResult r;
        bool short_read = false;
        const Status st =
            emit_span_file(sink, opts, meta, span_, m.data_at, meta.size, r, short_read);
        if (short_read || meta.size < m.size) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeTruncated,
                 "'" + name + "' claims " + dec(m.size) + " bytes but the archive ends first"});
            r.truncated = true;
            out.truncated = true;
        }
        if (!st) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeSinkError, "'" + name + "': " + st.error});
            out.truncated = true;
            out.entries_out.push_back(std::move(r));
            ++out.entries;
            ++out.files;
            break;
        }
        out.bytes += r.digests.bytes;
        out.entries_out.push_back(std::move(r));
        ++out.entries;
        ++out.files;
        pos = m.next;
    }
    return Status::success();
}

OMNITRACE_REGISTER_CONTAINER("ar", ArReader);

}  // namespace omnitrace::container
