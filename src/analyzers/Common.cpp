// Common.cpp — helpers shared by the platform analyzers. See Common.h.
#include "Common.h"

#include <nlohmann/json.hpp>

namespace omnitrace::analyzers::common {

namespace {

// A SAX handler that keeps only the top level: scalar members as strings and
// the element count of array members. It never builds a document, so a 100 KB
// manifest costs the few dozen strings it actually reports, and it refuses a
// document deeper than the limit rather than recursing into it.
class TopLevelSax {
   public:
    TopLevelSax(JsonManifest& out, unsigned max_depth) : out_(out), max_depth_(max_depth) {}

    bool null() { return scalar("null"); }
    bool boolean(bool v) { return scalar(v ? "true" : "false"); }
    bool number_integer(std::int64_t v) { return scalar(std::to_string(v)); }
    bool number_unsigned(std::uint64_t v) { return scalar(std::to_string(v)); }
    bool number_float(double /*unused*/, const std::string& s) { return scalar(s); }
    bool string(std::string& v) { return scalar(v); }
    bool binary(std::vector<std::uint8_t>& /*unused*/) { return scalar("<binary>"); }

    bool start_object(std::size_t /*unused*/) { return descend(); }
    bool start_array(std::size_t /*unused*/) {
        // A top-level array member is counted, not read: the automotive QNX unit manifest's
        // `component` array has 181 entries of twelve fields each.
        if (depth_ == 1 && !key_.empty() && counting_.empty()) {
            counting_ = key_;
            counted_ = 0;
        }
        return descend();
    }
    bool end_object() { return ascend(); }
    bool end_array() {
        if (depth_ == 2 && !counting_.empty()) {
            out_.arrays[counting_] = counted_;
            counting_.clear();
        }
        return ascend();
    }
    bool key(std::string& k) {
        if (depth_ == 1) key_ = k;
        return true;
    }
    bool parse_error(std::size_t /*unused*/, const std::string& /*unused*/,
                     const nlohmann::json::exception& /*unused*/) {
        return false;
    }

   private:
    // Returning false stops the parse, which is how the depth limit is
    // enforced: refuse the document rather than recurse into it.
    bool descend() {
        count_element();
        ++depth_;
        return depth_ <= max_depth_;
    }
    bool ascend() {
        if (depth_ != 0) --depth_;
        return true;
    }
    bool scalar(std::string v) {
        count_element();
        if (depth_ == 1 && !key_.empty() && counting_.empty()) out_.scalars[key_] = std::move(v);
        return true;
    }
    // One more element of the top-level array currently being counted.
    void count_element() {
        if (!counting_.empty() && depth_ == 2) ++counted_;
    }

    JsonManifest& out_;
    unsigned max_depth_;
    unsigned depth_ = 0;
    std::string key_;
    std::string counting_;  // non-empty while inside a top-level array
    std::size_t counted_ = 0;
};

}  // namespace

JsonManifest read_json_manifest(const std::string& text, unsigned max_depth) {
    JsonManifest out;
    if (text.empty() || max_depth == 0) return out;
    TopLevelSax sax(out, max_depth);
    out.ok = nlohmann::json::sax_parse(text, &sax, nlohmann::json::input_format_t::json,
                                       /*strict=*/false);
    if (!out.ok) {
        out.scalars.clear();
        out.arrays.clear();
    }
    return out;
}

void for_each_line(const std::string& text, const std::function<void(std::string_view)>& fn) {
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        std::string_view line(text.data() + pos, eol - pos);
        pos = eol + 1;
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (!line.empty()) fn(line);
    }
}

std::vector<std::string_view> split_colons(std::string_view line) {
    std::vector<std::string_view> out;
    std::size_t pos = 0;
    for (;;) {
        const std::size_t c = line.find(':', pos);
        if (c == std::string_view::npos) {
            out.push_back(line.substr(pos));
            break;
        }
        out.push_back(line.substr(pos, c - pos));
        pos = c + 1;
    }
    return out;
}

std::map<std::string, std::string> parse_env(const std::string& text) {
    std::map<std::string, std::string> out;
    for_each_line(text, [&out](std::string_view line) {
        if (line.front() == '#') return;
        const std::size_t eq = line.find('=');
        if (eq == std::string_view::npos) return;
        std::string_view key = line.substr(0, eq);
        std::string_view val = line.substr(eq + 1);
        if (val.size() >= 2 && (val.front() == '"' || val.front() == '\'') &&
            val.back() == val.front()) {
            val.remove_prefix(1);
            val.remove_suffix(1);
        }
        if (key.empty() || val.empty()) return;
        out.emplace(std::string(key), std::string(val));
    });
    return out;
}

void add(Report& r, std::string key, std::string value, std::string source) {
    if (value.empty()) return;
    const Fact* clash = nullptr;
    for (const Fact& f : r.facts) {
        if (f.key != key) continue;
        if (f.value == value) return;  // agreed; saying it twice is noise
        clash = &f;
    }
    if (clash != nullptr)
        r.diagnostics.push_back({Severity::Info, kCodeFactsDisagree,
                                 key + " differs between " + clash->source + " (" + clash->value +
                                     ") and " + source + " (" + value + "); both are reported"});
    r.facts.push_back(Fact{std::move(key), std::move(value), std::move(source)});
}

std::string hash_kind(std::string_view h, bool in_shadow) {
    if (h.empty()) return "empty";  // any password, or none, is accepted
    if (h == "*" || h == "!" || h == "!!" || h == "!*") return "locked";
    if (h == "x") return in_shadow ? "invalid" : "in-shadow";
    // QNX Neutrino writes @S@<base64 hash>@<base64 salt>, which is not
    // crypt(3) at all. Read by a crypt-only parser it is "unrecognised", which
    // would report a hashed account as having no usable password.
    if (h.rfind("@S@", 0) == 0) return "qnx-strong";
    if (h.rfind("$1$", 0) == 0) return "md5";
    if (h.rfind("$2", 0) == 0) return "bcrypt";
    if (h.rfind("$5$", 0) == 0) return "sha256";
    if (h.rfind("$6$", 0) == 0) return "sha512";
    if (h.rfind("$y$", 0) == 0 || h.rfind("$7$", 0) == 0) return "yescrypt";
    if (h.front() == '$') return "crypt-other";
    if (h.size() == 13) return "descrypt";  // the ancient one, trivially cracked
    return "unrecognised";
}

bool is_real_hash(const std::string& kind) {
    return kind != "empty" && kind != "locked" && kind != "invalid" && kind != "in-shadow" &&
           kind != "unrecognised";
}

PasswordTally describe_password_file(const Tree& t, Report& r, const std::string& path,
                                     bool is_shadow) {
    PasswordTally tally;
    const auto text = t.read(path, 4U << 20);
    if (!text) return tally;
    for_each_line(*text, [&](std::string_view line) {
        if (line.front() == '#') return;
        const auto f = split_colons(line);
        if (f.size() < 2) return;
        const std::string name(f[0]);
        if (name.empty()) return;
        ++tally.accounts;
        const std::string kind = hash_kind(f[1], is_shadow);
        const bool real = is_real_hash(kind);
        ++tally.by_kind[kind];
        if (real) ++tally.with_hash;

        // Only the two states an examiner acts on get a row of their own. The
        // rest are counted: a QNX boot image with 286 accounts would otherwise
        // produce 286 rows that all say "in-shadow".
        if (real || kind == "empty") add(r, "user." + name + ".password", kind, path);

        // An account that accepts any password, or none, is the single most
        // actionable thing on a system, and a table row is the wrong place for
        // it. Both corpus families have one: OpenWrt's `root::` in shadow, and
        // the automotive Android unit's QNX service accounts.
        if (kind == "empty") {
            ++tally.empty;
            r.diagnostics.push_back({Severity::Warning, kCodeEmptyPassword,
                                     "'" + name + "' has an empty password field in " + path +
                                         ": the account authenticates with no password"});
        }
        // These two are independent, and chaining them lost the more serious
        // one in the commonest case: an IP camera keeps root's md5 in
        // etc/passwd, which is both crackable *and* world-readable, and an
        // else-if reported only that md5 is weak.
        if (real && !is_shadow)
            r.diagnostics.push_back({Severity::Warning, kCodeWeakHash,
                                     "'" + name + "' has its password hash (" + kind + ") in " +
                                         path + ", which is world-readable"});
        if (kind == "md5" || kind == "descrypt")
            r.diagnostics.push_back(
                {Severity::Info, kCodeWeakHash,
                 "'" + name + "' uses " + kind + ", which modern hardware cracks quickly"});
    });
    return tally;
}

void add_password_counts(Report& r, const PasswordTally& tally, const std::string& source) {
    if (tally.accounts == 0) return;
    add(r, "users.with_password", std::to_string(tally.with_hash), source);
    if (tally.empty != 0) add(r, "users.no_password", std::to_string(tally.empty), source);
    for (const auto& [kind, n] : tally.by_kind) {
        if (kind == "empty") continue;  // already stated, and each one is a diagnostic
        add(r, "users.password_" + kind, std::to_string(n), source);
    }
}

}  // namespace omnitrace::analyzers::common
