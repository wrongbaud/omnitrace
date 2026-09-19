// Signature.h — declarative format signatures + structural validators.
//
// A Signature is loaded from TOML (signatures/*.toml, embedded at build time):
//   [[signature]]
//   name = "squashfs-le"      format = "squashfs"   category = "filesystem"
//   magic = "hsqs"            # or hex = "68737173"
//   magic_offset = 0          # where in the structure the magic sits
//   validator = "squashfs"    # optional C++ validator name
//   endian = "little"
//   description = "..."       references = ["https://..."]
// The scanner finds every magic hit; the validator (if any) parses the header at
// (hit - magic_offset), decides the confidence tier, the structure size, and any
// diagnostics. Hits without a validator stay at Confidence::Magic.
#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "omnitrace/core/Diagnostics.h"
#include "omnitrace/core/Endian.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/core/Status.h"

namespace omnitrace::discovery {

struct Signature {
    std::string name;
    std::string format;    // canonical format id used for Node::format and reader lookup
    std::string category;  // "filesystem" | "container" | "partition-table" | "kernel" |
                           // "bootloader" | "compressed" | "crypto" | "other"
    std::vector<std::uint8_t> magic;
    std::uint64_t magic_offset = 0;  // magic position relative to structure start
    std::optional<Endian> endian;    // fixed byte order implied by this magic
    std::string validator;           // registered validator name; empty = none
    std::uint64_t alignment = 1;     // only accept hits at this alignment (0/1 = any)
    std::string description;
    std::vector<std::string> references;
    std::map<std::string, std::string> extra;  // free-form TOML keys passed to the validator
};

struct Finding {
    std::uint64_t offset = 0;  // structure start, Span-relative
    std::uint64_t size = 0;    // 0 = unknown
    std::string format;
    std::string category;
    std::string signature;  // Signature::name that produced it
    Confidence confidence = Confidence::Magic;
    std::string evidence;
    Endian endian = Endian::Little;
    std::map<std::string, std::string> attrs;  // version, compression, arch, label, ...
    std::vector<Diagnostic> diagnostics;
    std::vector<Finding> also_matched;  // suppressed lower-confidence overlaps
};

// Validator contract: given the whole scanned Span and a candidate structure
// start, return a Finding with confidence/size/attrs filled, or std::nullopt to
// reject. Must never throw on bad input; must never read outside `span`.
using Validator = std::function<std::optional<Finding>(const Span& span, std::uint64_t start,
                                                       const Signature& sig)>;

class ValidatorRegistry {
   public:
    static ValidatorRegistry& instance();
    void add(const std::string& name, Validator v);
    const Validator* find(const std::string& name) const;
    std::vector<std::string> names() const;

   private:
    std::map<std::string, Validator> validators_;
};

// Static registration helper: `OMNITRACE_REGISTER_VALIDATOR("squashfs", fn);` at namespace scope.
struct ValidatorRegistrar {
    ValidatorRegistrar(const char* name, Validator v) {
        ValidatorRegistry::instance().add(name, std::move(v));
    }
};
#define OMNITRACE_REGISTER_VALIDATOR(name, fn)                                    \
    static ::omnitrace::discovery::ValidatorRegistrar _omnitrace_validator_##fn { \
        name, fn                                                                  \
    }

// Signature sets.
struct SignatureSet {
    std::vector<Signature> signatures;
    Status load_toml(const std::string& toml_text, const std::string& origin);
    Status load_file(const std::string& path);
    // Signatures compiled into the binary from signatures/*.toml.
    static const SignatureSet& builtin();
};

struct ScanOptions {
    bool validate = true;
    bool resolve_conflicts =
        true;  // deterministic overlap resolution (highest confidence, then earliest, then largest)
    std::uint64_t max_hits = 1'000'000;
};

// Scan the whole Span for every signature; validated, sorted by offset, deduped.
std::vector<Finding> scan(const Span& span, const SignatureSet& sigs, const ScanOptions& opts = {});

}  // namespace omnitrace::discovery
