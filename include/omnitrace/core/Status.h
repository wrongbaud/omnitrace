// Status.h — the one error type. Parsers never throw on bad input; they return
// Status::fail(...) (or std::nullopt from readers) and attach a Diagnostic.
/// @file Status.h
/// @brief The one error type: `Status` carries ok/fail plus a message.
///
/// Three error channels exist in OmniTrace and each has a job:
///
/// | Channel | Used for | Example |
/// |---|---|---|
/// | `Status` | an operation that can fail as a whole | `MappedFile::open`, `Sink::begin_file`,
/// `compress::decompress` | | `std::optional` | a read or a probe that simply yields nothing |
/// `Span::at<T>` on overrun, a `Validator` rejecting a hit | | `Diagnostic` | a degraded result
/// that still produced data | `jffs2-crc-mismatch` on a Node, `sink-limit-bytes` on an EntryResult
/// |
///
/// A hostile image is the normal case, so none of these throw. Exceptions are
/// reserved for programmer errors (see `SignatureSet::builtin`).
#pragma once
#include <string>
#include <utility>

/// @namespace omnitrace
/// @brief Everything in the library. Sub-namespaces: `compress`, `discovery`,
/// `fs`, `container`, `output`.
namespace omnitrace {

/// Result of an operation that can fail as a whole.
///
/// `error` is empty when `ok` is true. Where a caller keys on the failure,
/// `error` starts with a stable kebab-case code ("sink-unsafe-path: ...",
/// "decompress-cap"); see the function that produced it for its codes.
///
/// ```cpp
/// std::shared_ptr<omnitrace::MappedFile> file;
/// if (omnitrace::Status st = omnitrace::MappedFile::open(path, file); !st) {
///     spdlog::error("{}", st.error);  // "cannot open 'x': No such file or directory"
///     return 1;
/// }
/// ```
struct Status {
    bool ok = true;     ///< True when the operation succeeded.
    std::string error;  ///< Human-readable reason; empty when `ok`.

    /// A successful Status.
    static Status success() { return {}; }
    /// A failed Status carrying `msg`.
    static Status fail(std::string msg) { return {false, std::move(msg)}; }
    /// True when `ok`, so `if (!st)` reads as "if it failed".
    explicit operator bool() const { return ok; }
};

}  // namespace omnitrace
