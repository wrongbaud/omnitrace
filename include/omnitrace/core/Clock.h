// Clock.h — the only place wall-clock time is read. Injectable for deterministic
// tests and byte-identical reports.
/// @file Clock.h
/// @brief The only wall-clock read in the project (docs/ARCHITECTURE.md rule 5).
///
/// Readers, validators and serializers never call this; only the CLI does,
/// for `RunInfo::started_at` / `finished_at`. Tests replace the source with
/// `Clock::set_override` so a manifest is byte-identical run to run.
#pragma once
#include <cstdint>
#include <functional>
#include <string>

namespace omnitrace {

/// Static-only clock. Thread-safety: `now()` copies the override under a mutex
/// and calls it after releasing the lock; `set_override()` takes the same
/// mutex. An override may therefore call `now()` or `set_override()` itself
/// without deadlocking.
///
/// ```cpp
/// omnitrace::Clock::set_override([] { return std::int64_t{1700000000}; });
/// m.run.started_at = omnitrace::Clock::now_iso8601();  // "2023-11-14T22:13:20Z"
/// omnitrace::Clock::set_override(nullptr);              // back to the system clock
/// ```
struct Clock {
    /// Unix seconds now: from the override when one is set, else the system clock.
    static std::int64_t now();
    /// ISO-8601 UTC "YYYY-MM-DDTHH:MM:SSZ". A pure formatter that never reads the clock.
    /// Returns an empty string when the value does not fit `time_t` or `gmtime` fails.
    static std::string iso8601(std::int64_t unix_seconds);
    /// `iso8601(now())`.
    static std::string now_iso8601() { return iso8601(now()); }
    /// Tests: replace the time source. Pass `nullptr` to restore the system clock.
    /// Mutex-guarded; safe to call while other threads call `now()`.
    static void set_override(std::function<std::int64_t()> fn);
};

}  // namespace omnitrace
