// Common.h — private helpers shared by the YAML and Markdown renderers.
// Everything here is pure: no clock, no host filesystem, no locale.
#pragma once
#include <cstdint>
#include <optional>
#include <string>

#include "omnitrace/core/Node.h"

namespace omnitrace::output::detail {

// Reverse of entry_kind_name(); nullopt for an unknown label.
std::optional<EntryKind> entry_kind_from_name(const std::string& s);

// Reverse of endian_name(); nullopt for an unknown label.
std::optional<Endian> endian_from_name(const std::string& s);

// Reverse of severity_name(); nullopt for an unknown label.
std::optional<Severity> severity_from_name(const std::string& s);

// ISO-8601 UTC twin of a unix timestamp; empty when out of range.
std::string iso8601(std::int64_t unix_seconds);

// Unsigned decimal, locale independent.
std::string dec(std::uint64_t v);
std::string dec_signed(std::int64_t v);

// Zero-padded octal of the low 12 bits ("0755"); type bits are dropped.
std::string mode_octal(std::uint32_t mode);

}  // namespace omnitrace::output::detail
