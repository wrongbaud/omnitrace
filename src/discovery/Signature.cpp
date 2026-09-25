// Signature.cpp — ValidatorRegistry, TOML signature loading, and the embedded
// builtin set. See docs/formats/signatures.md for the schema.
#include "omnitrace/discovery/Signature.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <set>
#include <sstream>
#include <stdexcept>

// toml++ is used header-only on purpose. TOML_EXCEPTIONS is a library-wide
// setting, not a per-file one: with it off, parse() lives in toml::v3::noex,
// and a package-provided libtomlplusplus.a (vcpkg's, for one) is compiled
// with exceptions on and exports toml::v3::parse instead -- so linking it
// leaves this file's call undefined. Header-only costs one translation unit
// and resolves the same way wherever toml++ came from. The undef is for the
// package configs that put -DTOML_HEADER_ONLY=0 on the command line.
#undef TOML_HEADER_ONLY
#define TOML_HEADER_ONLY 1
#define TOML_EXCEPTIONS 0
#include <toml++/toml.hpp>

#include "validators/anchors.h"

namespace omnitrace::discovery {

namespace detail {
struct EmbeddedToml {
    const char* name;
    const unsigned char* data;
    std::size_t size;
};
extern const EmbeddedToml kEmbedded[];
extern const std::size_t kEmbeddedCount;
}  // namespace detail

// ---------------------------------------------------------------- registry

ValidatorRegistry& ValidatorRegistry::instance() {
    static ValidatorRegistry registry;
    return registry;
}

void ValidatorRegistry::add(const std::string& name, Validator v) {
    validators_[name] = std::move(v);
}

const Validator* ValidatorRegistry::find(const std::string& name) const {
    // Validators live in their own translation units inside a static library;
    // touching the anchors guarantees the linker keeps them (and so their
    // static registrars) even when nothing else references those objects.
    detail::link_builtin_validators();
    const auto it = validators_.find(name);
    return it == validators_.end() ? nullptr : &it->second;
}

std::vector<std::string> ValidatorRegistry::names() const {
    detail::link_builtin_validators();
    std::vector<std::string> out;
    out.reserve(validators_.size());
    for (const auto& [k, v] : validators_) out.push_back(k);
    return out;  // std::map iteration is already sorted
}

// ---------------------------------------------------------------- TOML

namespace {

const std::set<std::string>& known_categories() {
    static const std::set<std::string> cats{"filesystem", "container",  "partition-table", "kernel",
                                            "bootloader", "compressed", "crypto",          "other"};
    return cats;
}

const std::set<std::string>& known_keys() {
    static const std::set<std::string> keys{"name",      "format",       "category",  "magic",
                                            "hex",       "magic_offset", "endian",    "validator",
                                            "alignment", "description",  "references"};
    return keys;
}

std::optional<std::vector<std::uint8_t>> parse_hex(std::string_view text) {
    std::string digits;
    for (const char c : text) {
        if (c == ' ' || c == '\t' || c == '_' || c == ':') continue;
        digits.push_back(c);
    }
    if (digits.size() >= 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X'))
        digits.erase(0, 2);
    if (digits.empty() || (digits.size() % 2) != 0) return std::nullopt;
    std::vector<std::uint8_t> out;
    out.reserve(digits.size() / 2);
    for (std::size_t i = 0; i < digits.size(); i += 2) {
        unsigned v = 0;
        for (std::size_t k = 0; k < 2; ++k) {
            const char c = digits[i + k];
            unsigned nib = 0;
            if (c >= '0' && c <= '9')
                nib = static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f')
                nib = static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                nib = static_cast<unsigned>(c - 'A' + 10);
            else
                return std::nullopt;
            v = (v << 4) | nib;
        }
        out.push_back(static_cast<std::uint8_t>(v));
    }
    return out;
}

// One [[signature]] table -> Signature, or an error message.
std::optional<std::string> parse_signature(const toml::table& t, Signature& sig) {
    auto require_string = [&](const char* key, std::string& out) -> std::optional<std::string> {
        const toml::node* n = t.get(key);
        if (n == nullptr) return std::string("missing required key '") + key + "'";
        const auto* s = n->as_string();
        if (s == nullptr) return std::string("key '") + key + "' must be a string";
        out = s->get();
        if (out.empty()) return std::string("key '") + key + "' must not be empty";
        return std::nullopt;
    };
    auto optional_string = [&](const char* key, std::string& out) -> std::optional<std::string> {
        const toml::node* n = t.get(key);
        if (n == nullptr) return std::nullopt;
        const auto* s = n->as_string();
        if (s == nullptr) return std::string("key '") + key + "' must be a string";
        out = s->get();
        return std::nullopt;
    };
    auto optional_u64 = [&](const char* key, std::uint64_t& out) -> std::optional<std::string> {
        const toml::node* n = t.get(key);
        if (n == nullptr) return std::nullopt;
        const auto* i = n->as_integer();
        if (i == nullptr) return std::string("key '") + key + "' must be an integer";
        if (i->get() < 0) return std::string("key '") + key + "' must not be negative";
        out = static_cast<std::uint64_t>(i->get());
        return std::nullopt;
    };

    if (auto e = require_string("name", sig.name)) return e;
    if (auto e = require_string("format", sig.format)) return e;
    if (auto e = require_string("category", sig.category)) return e;
    if (known_categories().count(sig.category) == 0)
        return "unknown category '" + sig.category + "'";

    const toml::node* magic = t.get("magic");
    const toml::node* hex = t.get("hex");
    if (magic != nullptr && hex != nullptr)
        return std::string("give either 'magic' or 'hex', not both");
    if (magic == nullptr && hex == nullptr) return std::string("missing 'magic' or 'hex'");
    if (magic != nullptr) {
        const auto* s = magic->as_string();
        if (s == nullptr) return std::string("key 'magic' must be a string");
        const std::string& m = s->get();
        sig.magic.assign(m.begin(), m.end());
    } else {
        const auto* s = hex->as_string();
        if (s == nullptr) return std::string("key 'hex' must be a string");
        auto bytes = parse_hex(s->get());
        if (!bytes) return "key 'hex' is not a valid even-length hex string: '" + s->get() + "'";
        sig.magic = std::move(*bytes);
    }
    if (sig.magic.size() < 2) return std::string("magic must be at least 2 bytes long");

    if (auto e = optional_u64("magic_offset", sig.magic_offset)) return e;
    if (auto e = optional_u64("alignment", sig.alignment)) return e;
    if (sig.alignment == 0) sig.alignment = 1;
    if (auto e = optional_string("validator", sig.validator)) return e;
    if (auto e = optional_string("description", sig.description)) return e;

    std::string endian;
    if (auto e = optional_string("endian", endian)) return e;
    if (endian == "little")
        sig.endian = Endian::Little;
    else if (endian == "big")
        sig.endian = Endian::Big;
    else if (!endian.empty())
        return "key 'endian' must be \"little\" or \"big\", got '" + endian + "'";

    if (const toml::node* refs = t.get("references")) {
        const auto* arr = refs->as_array();
        if (arr == nullptr) return std::string("key 'references' must be an array of strings");
        for (const auto& el : *arr) {
            const auto* s = el.as_string();
            if (s == nullptr) return std::string("key 'references' must be an array of strings");
            sig.references.push_back(s->get());
        }
    }

    // Anything else is passed to the validator verbatim (stringified).
    for (const auto& [key, node] : t) {
        const std::string k(key.str());
        if (known_keys().count(k) != 0) continue;
        if (const auto* s = node.as_string())
            sig.extra[k] = s->get();
        else if (const auto* i = node.as_integer())
            sig.extra[k] = std::to_string(i->get());
        else if (const auto* b = node.as_boolean())
            sig.extra[k] = b->get() ? "true" : "false";
        else if (const auto* f = node.as_floating_point()) {
            std::ostringstream os;
            os << f->get();
            sig.extra[k] = os.str();
        } else
            return "extra key '" + k + "' must be a string, integer, float or boolean";
    }
    return std::nullopt;
}

}  // namespace

Status SignatureSet::load_toml(const std::string& toml_text, const std::string& origin) {
    toml::parse_result result = toml::parse(toml_text, origin);
    if (!result) {
        const auto& err = result.error();
        std::ostringstream os;
        os << origin << ": TOML parse error at line " << err.source().begin.line << ", column "
           << err.source().begin.column << ": " << err.description();
        return Status::fail(os.str());
    }
    const toml::table& root = result.table();
    const toml::node* sigs = root.get("signature");
    if (sigs == nullptr) return Status::fail(origin + ": no [[signature]] entries");
    const auto* arr = sigs->as_array();
    if (arr == nullptr || !arr->is_array_of_tables())
        return Status::fail(origin + ": 'signature' must be an array of tables ([[signature]])");

    std::set<std::string> names;
    for (const Signature& s : signatures) names.insert(s.name);

    std::vector<Signature> loaded;
    std::size_t index = 0;
    for (const auto& el : *arr) {
        const auto* t = el.as_table();
        Signature sig;
        std::optional<std::string> err;
        if (t == nullptr)
            err = std::string("entry is not a table");
        else
            err = parse_signature(*t, sig);
        if (err) {
            std::ostringstream os;
            os << origin << ": signature[" << index << "]";
            if (!sig.name.empty()) os << " (" << sig.name << ")";
            os << ": " << *err;
            return Status::fail(os.str());
        }
        if (!names.insert(sig.name).second) {
            std::ostringstream os;
            os << origin << ": signature[" << index << "]: duplicate name '" << sig.name << "'";
            return Status::fail(os.str());
        }
        loaded.push_back(std::move(sig));
        ++index;
    }
    // All-or-nothing: a bad file leaves the set untouched.
    std::move(loaded.begin(), loaded.end(), std::back_inserter(signatures));
    return Status::success();
}

Status SignatureSet::load_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return Status::fail("cannot open signature file '" + path + "'");
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (in.bad()) return Status::fail("error reading signature file '" + path + "'");
    return load_toml(text, path);
}

const SignatureSet& SignatureSet::builtin() {
    static const SignatureSet set = [] {
        SignatureSet s;
        for (std::size_t i = 0; i < detail::kEmbeddedCount; ++i) {
            const detail::EmbeddedToml& f = detail::kEmbedded[i];
            const std::string text(reinterpret_cast<const char*>(f.data), f.size);
            const Status st = s.load_toml(text, std::string("builtin:") + f.name);
            // The embedded files are part of the build and covered by tests; a
            // failure here is a programmer error, not bad input.
            if (!st) throw std::logic_error("builtin signature set failed to load: " + st.error);
        }
        return s;
    }();
    return set;
}

}  // namespace omnitrace::discovery
