// Clock.cpp — the only wall-clock read in the project (ARCHITECTURE.md rule 5).
#include "omnitrace/core/Clock.h"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <limits>
#include <mutex>
#include <utility>

namespace omnitrace {

namespace {

std::mutex& override_mutex() {
    static std::mutex m;
    return m;
}

std::function<std::int64_t()>& override_fn() {
    static std::function<std::int64_t()> fn;
    return fn;
}

}  // namespace

std::int64_t Clock::now() {
    std::function<std::int64_t()> fn;
    {
        std::lock_guard<std::mutex> lock(override_mutex());
        fn = override_fn();
    }
    if (fn) return fn();
    const auto now = std::chrono::system_clock::now();
    return static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
}

std::string Clock::iso8601(std::int64_t unix_seconds) {
    // time_t may be narrower than int64 on exotic targets; refuse rather than wrap.
    if (unix_seconds < static_cast<std::int64_t>(std::numeric_limits<std::time_t>::min()) ||
        unix_seconds > static_cast<std::int64_t>(std::numeric_limits<std::time_t>::max())) {
        return {};
    }
    const std::time_t t = static_cast<std::time_t>(unix_seconds);
    std::tm tm{};
#ifdef _WIN32
    if (gmtime_s(&tm, &t) != 0) return {};
#else
    if (gmtime_r(&t, &tm) == nullptr) return {};
#endif
    char buf[64];
    const int n =
        std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ", tm.tm_year + 1900,
                      tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    if (n <= 0 || static_cast<std::size_t>(n) >= sizeof(buf)) return {};
    return std::string(buf, static_cast<std::size_t>(n));
}

void Clock::set_override(std::function<std::int64_t()> fn) {
    std::lock_guard<std::mutex> lock(override_mutex());
    override_fn() = std::move(fn);
}

}  // namespace omnitrace
