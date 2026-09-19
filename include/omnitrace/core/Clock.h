// Clock.h — the only place wall-clock time is read. Injectable for deterministic
// tests and byte-identical reports.
#pragma once
#include <cstdint>
#include <functional>
#include <string>

namespace omnitrace {

struct Clock {
    // Unix seconds now.
    static std::int64_t now();
    // ISO-8601 UTC "YYYY-MM-DDTHH:MM:SSZ".
    static std::string iso8601(std::int64_t unix_seconds);
    static std::string now_iso8601() { return iso8601(now()); }
    // Tests: override the time source. Pass nullptr to restore the system clock.
    static void set_override(std::function<std::int64_t()> fn);
};

}  // namespace omnitrace
