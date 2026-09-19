// Text.h — string hygiene for anything that leaves the process.
//
// Evidence strings (filenames, labels, gzip names) are attacker-controlled
// bytes. Every serializer (YAML, JSON, Markdown, stdout tables) passes them
// through sanitize_utf8() so output is always valid UTF-8 and never aborts.
#pragma once
#include <cstdint>
#include <span>
#include <string>

namespace omnitrace {

// Returns a valid UTF-8 string. Invalid bytes and overlong/surrogate sequences
// become "\xNN" escapes (literal backslash, x, two lowercase hex digits).
// C0 control characters other than \t \n \r become "\xNN" too. Valid multi-byte
// sequences pass through unchanged. Idempotent on already-clean input.
std::string sanitize_utf8(std::string_view in);
std::string sanitize_utf8(std::span<const std::uint8_t> in);

// True if `in` is well-formed UTF-8 with no C0 controls except \t \n \r.
bool is_clean_utf8(std::string_view in);

// Decode a UTF-16LE fixed-width field (GPT partition names) into sanitized UTF-8.
std::string utf16le_to_utf8(std::span<const std::uint8_t> in);

// Make a string safe as a single path component on every host OS: sanitize,
// replace '/', '\\', ':' and other reserved characters with '_', trim to
// max_len bytes at a UTF-8 boundary, and return "unnamed" if empty.
std::string safe_filename_component(std::string_view in, std::size_t max_len = 64);

}  // namespace omnitrace
