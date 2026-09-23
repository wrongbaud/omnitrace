// Common.h — helpers shared by the platform analyzers. Internal to the layer.
//
// Every platform that has a `passwd` file has the same `passwd` file, and the
// question an examiner asks of it -- could this account be logged into, and how
// well does its secret resist cracking -- is the same everywhere. Only the hash
// formats differ, and a second copy of `hash_kind` is how the Linux and QNX
// answers would quietly drift apart.
#pragma once
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "omnitrace/analyzers/Platform.h"

namespace omnitrace::analyzers::common {

/// Diagnostic codes shared by more than one analyzer.
inline constexpr const char* kCodeEmptyPassword = "platform-account-no-password";
inline constexpr const char* kCodeWeakHash = "platform-account-weak-hash";
inline constexpr const char* kCodeFactsDisagree = "platform-release-disagrees";

/// Call `fn` for each non-empty line, `\r` trimmed.
void for_each_line(const std::string& text, const std::function<void(std::string_view)>& fn);

/// One colon-separated line's fields, `passwd`/`shadow`/`group` style.
std::vector<std::string_view> split_colons(std::string_view line);

/// `KEY=VALUE` lines with optionally quoted values: os-release, lsb-release,
/// OpenWrt's release file, and QNX build-info files are all this shape.
std::map<std::string, std::string> parse_env(const std::string& text);

/// Record a fact. Two files that agree are recorded once; two that disagree
/// are both kept, with `platform-release-disagrees` naming which said what --
/// a vendor rebuild that edits one release file and not the other looks
/// exactly like that.
void add(Report& r, std::string key, std::string value, std::string source);

/// Name the password field's state without ever copying the secret.
///
/// What matters forensically is whether the account could be logged into and
/// how well its hash resists cracking, not the hash itself; a report that
/// quoted hashes would be a credential store.
///
/// The same bytes mean different things in the two files, which is why the
/// caller says which it is reading. In `passwd`, `x` means "the secret is in
/// shadow" and is the normal case. In `shadow` it is not a hash at all, so
/// nothing a user types can match it and the account cannot be logged in. An
/// **empty** field in either means the account authenticates with no password.
///
/// Formats: the crypt(3) `$id$` family, historic 13-character DES, and QNX's
/// own `@S@<base64>@<base64>`, which is not crypt(3) and which a crypt-only
/// reader calls "unrecognised" -- the automotive Android unit's QNX root account is exactly
/// that.
std::string hash_kind(std::string_view field, bool in_shadow);

/// Is this a hash someone could attack, rather than a state that means the
/// account has no usable password?
bool is_real_hash(const std::string& kind);

/// What one `passwd`- or `shadow`-shaped file said.
struct PasswordTally {
    unsigned accounts = 0;
    unsigned with_hash = 0;                   ///< Accounts with a hash someone could attack.
    unsigned empty = 0;                       ///< Accounts that authenticate with no password.
    std::map<std::string, unsigned> by_kind;  ///< Every state, counted.
};

/// Read one `passwd`- or `shadow`-shaped file, reporting the accounts that
/// matter individually and the rest as counts.
///
/// An account gets its own row only when it has a real hash or an empty
/// password -- the two states an examiner acts on. Everything else is counted,
/// because an automotive QNX unit's boot image has 286 accounts and 286 rows reading
/// "in-shadow" is not a report. The counts still come back so the caller can
/// state them.
///
/// Emits `platform-account-no-password` for an empty field and
/// `platform-account-weak-hash` for a hash that cracks quickly or one sitting
/// in a world-readable file.
PasswordTally describe_password_file(const Tree& t, Report& r, const std::string& path,
                                     bool is_shadow);

/// A JSON build manifest, read flat.
///
/// Only the top level is kept: scalar members as strings, and the element
/// count of any array member. That is deliberate -- an automotive QNX unit's
/// `artifact.json` carries 181 components with twelve fields each, and 2172
/// facts is not a report. The count says a bill of materials is there and the
/// file is named so it can be opened.
struct JsonManifest {
    bool ok = false;  ///< False when the text is not JSON, or is past a limit.
    std::map<std::string, std::string> scalars;
    std::map<std::string, std::size_t> arrays;  ///< Member name -> element count.
};

/// Read the top level of a JSON object.
///
/// Parsed through a SAX handler with a depth limit rather than into a
/// document, because evidence is attacker-controlled: a recursive-descent
/// parse of deeply nested JSON is a stack overflow, and materialising the
/// document costs many times the file. `max_depth` past 32 is refused, not
/// truncated -- a manifest is a flat record and anything deeper is not one.
JsonManifest read_json_manifest(const std::string& text, unsigned max_depth = 32);

/// State the tally as facts: how many accounts have a real hash, how many
/// authenticate with none, and how many are in each other state. This is what
/// replaces a row per account on a system that has hundreds.
///
/// Call it for the **authoritative** file only -- shadow when there is one,
/// passwd otherwise. The same count key means different things in the two
/// files, so emitting from both makes them collide and report a disagreement
/// that is really just the two files doing their jobs.
void add_password_counts(Report& r, const PasswordTally& tally, const std::string& source);

}  // namespace omnitrace::analyzers::common
