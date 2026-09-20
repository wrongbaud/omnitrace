// fit.cpp — flattened device tree (DTB) and U-Boot FIT image validators.
//
// Both read the FDT container, whose parser is omnitrace::fdt in
// include/omnitrace/core/Fdt.h: it is in core because container::FitReader
// walks the same trees to extract what these validators only describe.
//
// A FIT is an FDT whose root holds an /images node; each image carries its
// payload either inline (property "data") or outside the tree
// ("data-position" absolute from the FIT start, or "data-offset" relative
// to the 4-aligned end of the tree, plus "data-size"). Hash subnodes
// (algo + value) let the payload be verified: crc32, md5, sha1 and sha256
// are checked here.
//
// Both validators live in one translation unit so they share the parser;
// "dtb" registers here too (there is no dtb.cpp).
// References: Devicetree Specification ch. 5 (flattened format);
// U-Boot doc/usage/fit/source_file_format.rst.
#include <array>
#include <vector>

#include "../crc32.h"
#include "anchors.h"
#include "common.h"
#include "omnitrace/core/Fdt.h"
#include "omnitrace/core/Hash.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

// The parser is core's (Fdt.h). These aliases keep the format-level code
// below reading the way it did when the parser was private to this file.
using FdtHeader = fdt::Header;
using WalkLimits = fdt::Limits;
using fdt::header_problem;
using fdt::Prop;
using fdt::read_header;
using fdt::Tree;
using fdt::walk;

// Bytes one FIT may hash while verifying its images (Signature::extra
// "max_hash_bytes"); a hostile FIT could otherwise name thousands of 4 GiB
// payloads inside a large image and stall the scan for hours.
constexpr std::uint64_t kDefaultMaxHashBytes = 1ull << 30;

WalkLimits limits_from(const Signature& sig) {
    WalkLimits l;
    l.max_nodes = extra_u64(sig, "max_nodes").value_or(fdt::kDefaultMaxNodes);
    l.max_props = extra_u64(sig, "max_props").value_or(fdt::kDefaultMaxProps);
    l.max_depth = extra_u64(sig, "max_depth").value_or(fdt::kDefaultMaxDepth);
    return l;
}

// The attr-facing views of a property. The tree holds raw evidence bytes;
// these make them printable, so they are named apart from the fdt:: readers
// they wrap (which argument-dependent lookup would otherwise find too).

// First string of a string(-list) property, control bytes dropped.
std::optional<std::string> attr_string(const Span& span, const Prop* p) {
    const auto s = fdt::prop_string(span, p);
    if (!s) return std::nullopt;
    std::string out;
    for (const char ch : *s) {
        const auto u = static_cast<unsigned char>(ch);
        out.push_back(u < 0x20 || u == 0x7F ? '_' : ch);
    }
    return out;
}

// Every string in a string-list property, joined with ','.
std::string attr_string_list(const Span& span, const Prop* p) {
    std::string out;
    for (const std::string& one : fdt::prop_strings(span, p)) {
        if (!out.empty()) out.push_back(',');
        out += list_safe(one);
    }
    return out;
}

void fill_header_attrs(Finding& f, const FdtHeader& h) {
    f.attrs["version"] = dec(h.version);
    f.attrs["totalsize"] = dec(h.totalsize);
    f.attrs["struct_size"] = dec(h.size_dt_struct);
    f.attrs["strings_size"] = dec(h.size_dt_strings);
}

void fill_tree_diag(Finding& f, const Tree& t, const char* fmt) {
    if (t.complete) return;
    diag(f, Severity::Warning, t.problem,
         std::string(fmt) + " structure block did not parse to END (" + t.problem + ") after " +
             dec(t.nodes.size()) + " node(s)");
}

// ----------------------------------------------------------------------- dtb

std::optional<Finding> validate_dtb(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    const auto h = read_header(span, start);
    if (!h) return std::nullopt;
    const std::string problem = header_problem(*h);
    if (!problem.empty()) return std::nullopt;  // 4-byte magic with an insane header: noise
    Finding f = make_finding(sig, start, Confidence::Structural);
    f.endian = Endian::Big;
    fill_header_attrs(f, *h);
    bool truncated = false;
    f.size = clamp_size(span, start, h->totalsize, truncated);
    if (truncated) {
        diag(f, Severity::Warning, "dtb-truncated",
             "totalsize " + dec(h->totalsize) + " extends past the available data");
        return f;
    }
    const Tree t = walk(span, start, *h, limits_from(sig));
    f.attrs["nodes"] = dec(t.nodes.size());
    f.attrs["properties"] = dec(t.props.size());
    if (!t.complete) {
        fill_tree_diag(f, t, "DTB");
        return f;
    }
    f.confidence = Confidence::Consistent;
    if (const auto model = attr_string(span, t.prop(0, "model"))) f.attrs["model"] = *model;
    const std::string compat = attr_string_list(span, t.prop(0, "compatible"));
    if (!compat.empty()) f.attrs["compatible"] = compat;
    if (t.child(0, "images")) {
        // A FIT is a valid DTB; the fit signature reports it with the payload
        // inventory, so this finding steps back to let it win at the same offset.
        f.confidence = Confidence::Structural;
        diag(f, Severity::Info, "dtb-is-fit",
             "root has an /images node: this is a FIT image (see the fit finding)");
    }
    f.evidence = "FDT v" + dec(h->version) + ", " + dec(t.nodes.size()) + " nodes" +
                 (f.attrs.count("model") ? ", model \"" + f.attrs["model"] + "\"" : std::string{});
    return f;
}

// ----------------------------------------------------------------------- fit

struct Image {
    std::string name;
    std::uint64_t off = 0;  // Span-relative payload offset
    std::uint64_t size = 0;
    bool external = false;
    bool present = false;  // payload located inside the Span
    std::string type, compression;
};

std::uint32_t digest_len(const std::string& algo) {
    if (algo == "crc32") return 4;
    if (algo == "md5") return 16;
    if (algo == "sha1") return 20;
    if (algo == "sha256") return 32;
    return 0;
}

// Digest of [off, off+len) in the named algorithm as lowercase hex; nullopt
// when the algorithm is unsupported or the range is outside the Span.
std::optional<std::string> digest_of(const Span& span, std::uint64_t off, std::uint64_t len,
                                     const std::string& algo) {
    if (off > span.size() || len > span.size() - off) return std::nullopt;
    if (algo == "crc32") {
        const auto c = crc32_span(span, off, len, 0xFFFFFFFFu, 0xFFFFFFFFu);
        if (!c) return std::nullopt;
        return hex_fixed(*c, 8).substr(2);
    }
    if (digest_len(algo) == 0) return std::nullopt;
    Hasher hasher;
    std::array<std::uint8_t, 64 * 1024> buf{};
    std::uint64_t done = 0;
    while (done < len) {
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), len - done));
        if (auto v = span.view(off + done, want)) {
            hasher.update(*v);
        } else {
            if (span.read(off + done, std::span<std::uint8_t>(buf.data(), want)) != want)
                return std::nullopt;
            hasher.update(std::span<const std::uint8_t>(buf.data(), want));
        }
        done += want;
    }
    const Digests d = hasher.finish();
    if (algo == "md5") return d.md5;
    if (algo == "sha1") return d.sha1;
    return d.sha256;
}

std::optional<Finding> validate_fit(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    const auto h = read_header(span, start);
    if (!h) return std::nullopt;
    if (!header_problem(*h).empty()) return std::nullopt;
    const std::uint64_t avail = remaining(span, start);
    // The tree itself must be present to tell a FIT from a plain DTB.
    if (h->off_dt_struct + static_cast<std::uint64_t>(h->size_dt_struct) > avail ||
        h->off_dt_strings + static_cast<std::uint64_t>(h->size_dt_strings) > avail)
        return std::nullopt;
    const Tree t = walk(span, start, *h, limits_from(sig));
    if (t.nodes.empty()) return std::nullopt;
    const auto images = t.child(0, "images");
    if (!images) return std::nullopt;  // a plain DTB: the dtb signature reports it

    Finding f = make_finding(sig, start, Confidence::Structural);
    f.endian = Endian::Big;
    fill_header_attrs(f, *h);
    if (const auto d = attr_string(span, t.prop(0, "description"))) f.attrs["description"] = *d;
    if (const auto ts = fdt::prop_u32(span, t.prop(0, "timestamp"))) f.attrs["timestamp"] = dec(*ts);
    if (!t.complete) fill_tree_diag(f, t, "FIT");

    // External data sits after the tree, 4-aligned.
    const std::uint64_t ext_base =
        (static_cast<std::uint64_t>(h->totalsize) + 3) & ~std::uint64_t{3};
    std::vector<Image> imgs;
    std::uint64_t end = h->totalsize;
    bool all_present = true;
    std::uint64_t hash_ok = 0, hash_bad = 0, hash_unsupported = 0, hash_missing = 0;
    const std::uint64_t hash_budget =
        extra_u64(sig, "max_hash_bytes").value_or(kDefaultMaxHashBytes);
    std::uint64_t hashed = 0;
    bool hash_budget_hit = false;
    for (const std::uint32_t i : t.children[*images]) {
        Image im;
        im.name = t.nodes[i].name;
        if (const auto ty = attr_string(span, t.prop(i, "type"))) im.type = *ty;
        if (const auto c = attr_string(span, t.prop(i, "compression"))) im.compression = *c;
        if (const Prop* data = t.prop(i, "data")) {
            im.off = data->off;
            im.size = data->len;
            im.present = true;
        } else {
            const auto dsize = fdt::prop_u32(span, t.prop(i, "data-size"));
            const auto dpos = fdt::prop_u32(span, t.prop(i, "data-position"));
            const auto doff = fdt::prop_u32(span, t.prop(i, "data-offset"));
            if (dsize && (dpos || doff)) {
                im.external = true;
                im.size = *dsize;
                im.off = start + (dpos ? *dpos : ext_base + *doff);
                const std::uint64_t rel = im.off - start;
                im.present = rel <= avail && im.size <= avail - rel;
                const std::uint64_t rel_end = rel + im.size;
                if (im.present && rel_end > end) end = rel_end;
            }
        }
        if (!im.present) all_present = false;
        // Hash subnodes: hash, hash@1, hash-1 ...
        bool any_hash = false;
        for (const std::uint32_t k : t.children[i]) {
            if (t.nodes[k].name.rfind("hash", 0) != 0) continue;
            any_hash = true;
            const auto algo = attr_string(span, t.prop(k, "algo"));
            const Prop* value = t.prop(k, "value");
            if (!algo || value == nullptr || digest_len(*algo) == 0 ||
                value->len != digest_len(*algo)) {
                ++hash_unsupported;
                continue;
            }
            const auto stored = span.bytes(value->off, value->len);
            if (!stored || !im.present) {
                ++hash_unsupported;
                continue;
            }
            if (im.size > hash_budget - std::min(hashed, hash_budget)) {
                hash_budget_hit = true;
                ++hash_unsupported;
                continue;
            }
            hashed += im.size;
            const auto computed = digest_of(span, im.off, im.size, *algo);
            if (!computed) {
                ++hash_unsupported;
                continue;
            }
            if (*computed ==
                hex_bytes(std::span<const std::uint8_t>(stored->data(), stored->size())))
                ++hash_ok;
            else
                ++hash_bad;
        }
        if (!any_hash) ++hash_missing;
        imgs.push_back(std::move(im));
    }

    std::string list;
    for (const Image& im : imgs) {
        if (!list.empty()) list.push_back(';');
        list += list_safe(im.name) + ":" + (im.present ? hex(im.off - start) : "missing") + ":" +
                dec(im.size) + ":" + list_safe(im.type) + ":" + list_safe(im.compression);
    }
    f.attrs["images"] = list;
    f.attrs["image_count"] = dec(imgs.size());

    // Configurations: "<name>:kernel=..,fdt=..,ramdisk=..;..."
    if (const auto confs = t.child(0, "configurations")) {
        std::string cl;
        for (const std::uint32_t i : t.children[*confs]) {
            if (!cl.empty()) cl.push_back(';');
            cl += list_safe(t.nodes[i].name) + ":";
            bool first = true;
            for (const char* key : {"kernel", "fdt", "ramdisk", "firmware", "loadables"}) {
                const std::string v = attr_string_list(span, t.prop(i, key));
                if (v.empty()) continue;
                if (!first) cl.push_back(',');
                first = false;
                cl += std::string(key) + "=" + v;
            }
        }
        f.attrs["configurations"] = cl;
        if (const auto d = attr_string(span, t.prop(*confs, "default")))
            f.attrs["default_configuration"] = *d;
    }
    f.attrs["hash_ok"] = dec(hash_ok);
    f.attrs["hash_failed"] = dec(hash_bad);
    f.attrs["hash_unsupported"] = dec(hash_unsupported);
    f.attrs["images_without_hash"] = dec(hash_missing);

    bool truncated = false;
    f.size = clamp_size(span, start, end, truncated);
    if (truncated)
        diag(f, Severity::Warning, "fit-truncated",
             "image data extends past the available data (claimed end " + hex(end) + ")");
    if (!all_present)
        diag(f, Severity::Warning, "fit-data-missing",
             "one or more images have no payload inside the available data");
    if (imgs.empty()) diag(f, Severity::Warning, "fit-no-images", "/images has no subnodes");
    if (hash_bad != 0)
        diag(f, Severity::Warning, "fit-hash-mismatch",
             dec(hash_bad) + " image hash(es) do not match the payload");
    if (hash_unsupported != 0)
        diag(f, Severity::Info, "fit-hash-unsupported",
             dec(hash_unsupported) + " hash node(s) use an algorithm not checked here");
    if (hash_budget_hit)
        diag(f, Severity::Warning, "fit-limit-hash-bytes",
             "image payloads exceed max_hash_bytes (" + dec(hash_budget) +
                 "); remaining hashes not verified");

    if (t.complete && !truncated && all_present && !imgs.empty()) {
        f.confidence = Confidence::Consistent;
        if (hash_ok != 0 && hash_bad == 0) f.confidence = Confidence::Verified;
    }
    f.evidence =
        "FIT with " + dec(imgs.size()) + " image(s)" +
        (hash_ok != 0 ? ", " + dec(hash_ok) + " hash(es) verified" : std::string{}) +
        (f.attrs.count("description") ? ", \"" + f.attrs["description"] + "\"" : std::string{});
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("dtb", validate_dtb);
OMNITRACE_REGISTER_VALIDATOR("fit", validate_fit);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(fit)
