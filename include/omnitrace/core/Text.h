// Text.h — string hygiene for anything that leaves the process.
//
// Evidence strings (filenames, labels, gzip names) are attacker-controlled
// bytes. Every serializer (YAML, JSON, Markdown, stdout tables) passes them
// through sanitize_utf8() so output is always valid UTF-8 and never aborts.
/// @file Text.h
/// @brief UTF-8 sanitizing and host-safe file names for evidence strings.
///
/// All functions are pure and thread-safe. Readers keep evidence strings as
/// raw bytes in `FileMeta`/`Node`; the output layer and the carver call these
/// at the boundary.
#pragma once
#include <cstdint>
#include <span>
#include <string>

namespace omnitrace {

// Returns a valid UTF-8 string. Invalid bytes and overlong/surrogate sequences
// become "\xNN" escapes (literal backslash, x, two lowercase hex digits).
// C0 control characters other than \t \n \r become "\xNN" too. Valid multi-byte
// sequences pass through unchanged. Idempotent on already-clean input.
/// Return valid UTF-8. Invalid bytes, overlong forms, surrogates and C0
/// controls other than `\t` `\n` `\r` become literal `\xNN` escapes (two
/// lowercase hex digits) so the examiner still sees the exact bytes; valid
/// sequences pass through. Idempotent on clean input.
std::string sanitize_utf8(std::string_view in);
/// Byte-span overload of `sanitize_utf8`.
std::string sanitize_utf8(std::span<const std::uint8_t> in);

// True if `in` is well-formed UTF-8 with no C0 controls except \t \n \r.
/// True when `in` is well-formed UTF-8 with no C0 controls except `\t` `\n` `\r`
/// (i.e. `sanitize_utf8` would return it unchanged).
bool is_clean_utf8(std::string_view in);

// Decode a UTF-16LE fixed-width field (GPT partition names) into sanitized UTF-8.
/// Decode a NUL-padded UTF-16LE field (GPT partition names) into sanitized
/// UTF-8. Stops at the first NUL code unit; lone surrogates and an odd
/// trailing byte are escaped, not dropped.
std::string utf16le_to_utf8(std::span<const std::uint8_t> in);

// Make a string safe as a single path component on every host OS: sanitize,
// replace '/', '\\', ':' and other reserved characters with '_', trim to
// max_len bytes at a UTF-8 boundary, and return "unnamed" if empty.
/// Make `in` usable as one path component on every host OS (carved partition
/// names, `filesystems/<id>` labels): sanitize, replace `/ \ : * ? " < > |`
/// and control characters with `_` (runs collapsed), strip leading dots and
/// trailing dots/spaces, trim to `max_len` bytes at a UTF-8 boundary, rename
/// append `_` to Windows device names (CON, COM1, ...), and return "unnamed" for an empty result.
std::string safe_filename_component(std::string_view in, std::size_t max_len = 64);

}  // namespace omnitrace
