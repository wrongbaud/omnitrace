// Common.cpp — private helpers shared by the YAML and Markdown renderers.
#include "Common.h"

#include <cstdio>

#include "omnitrace/core/Clock.h"

namespace omnitrace::output::detail {

std::optional<EntryKind> entry_kind_from_name(const std::string& s) {
    static constexpr EntryKind kAll[] = {
        EntryKind::Regular,     EntryKind::Directory, EntryKind::Symlink, EntryKind::CharDevice,
        EntryKind::BlockDevice, EntryKind::Fifo,      EntryKind::Socket,  EntryKind::Unknown};
    for (const EntryKind k : kAll) {
        if (s == entry_kind_name(k)) return k;
    }
    return std::nullopt;
}

std::optional<Endian> endian_from_name(const std::string& s) {
    if (s == endian_name(Endian::Little)) return Endian::Little;
    if (s == endian_name(Endian::Big)) return Endian::Big;
    return std::nullopt;
}

std::optional<Severity> severity_from_name(const std::string& s) {
    for (const Severity sev : {Severity::Info, Severity::Warning, Severity::Error}) {
        if (s == severity_name(sev)) return sev;
    }
    return std::nullopt;
}

std::string iso8601(std::int64_t unix_seconds) {
    // Clock::iso8601 is a pure formatter; it never reads the wall clock.
    return Clock::iso8601(unix_seconds);
}

std::string dec(std::uint64_t v) {
    char buf[32];
    const int n = std::snprintf(buf, sizeof buf, "%llu", static_cast<unsigned long long>(v));
    if (n <= 0) return "0";
    return std::string(buf, static_cast<std::size_t>(n));
}

std::string dec_signed(std::int64_t v) {
    char buf[32];
    const int n = std::snprintf(buf, sizeof buf, "%lld", static_cast<long long>(v));
    if (n <= 0) return "0";
    return std::string(buf, static_cast<std::size_t>(n));
}

std::string mode_octal(std::uint32_t mode) {
    char buf[16];
    const int n = std::snprintf(buf, sizeof buf, "%04o", static_cast<unsigned>(mode & 07777u));
    if (n <= 0) return "0000";
    return std::string(buf, static_cast<std::size_t>(n));
}

}  // namespace omnitrace::output::detail
