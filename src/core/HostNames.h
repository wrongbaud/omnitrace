// HostNames.h — internal helpers for host-OS file-name rules, shared by
// Sink.cpp (DiskSink placement) and Text.cpp (safe_filename_component).
//
// Not a public header: nothing under include/omnitrace/ declares these, and
// their contract is docs/CASE_LAYOUT.md "Host file-name escaping". Tests
// declare the prototypes themselves (tests/unit/core/sink_test.cpp).
#pragma once
#include <string>
#include <string_view>

namespace omnitrace::detail {

/// True when `name` is a Windows reserved device name: the stem (the part
/// before the first '.', trailing spaces ignored) is CON, PRN, AUX, NUL,
/// COM1-9 or LPT1-9 in any case. "CON.txt" and "nul " count; "CON0",
/// "console" and "COM10" do not.
bool is_windows_reserved_name(std::string_view name);

/// Rewrite one already-normalized path component so that Win32 accepts it and
/// it lands as its own file: `\ : * ? " < > |` and control bytes become
/// `%XX` (uppercase hex), a reserved device stem gets `~res` inserted after
/// the stem (`CON` -> `CON~res`, `con.txt` -> `con~res.txt`), and a name
/// ending in a space or a dot gets a trailing `~`. Returns `comp` unchanged
/// when none of that applies. Pure; compiled on every host so it can be
/// tested where DiskSink never calls it.
std::string windows_host_component(std::string_view comp);

}  // namespace omnitrace::detail
