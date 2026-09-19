// fit.cpp — flattened device tree (DTB) and U-Boot FIT image validators.
//
// Both share the FDT container (magic 0xd00dfeed, big-endian header of ten
// u32: magic, totalsize, off_dt_struct, off_dt_strings, off_mem_rsvmap,
// version, last_comp_version, boot_cpuid_phys, size_dt_strings,
// size_dt_struct). The structure block is a token stream: BEGIN_NODE(1) +
// NUL-terminated name padded to 4, END_NODE(2), PROP(3) + u32 len + u32
// nameoff + data padded to 4, NOP(4), END(9). Property names live in the
// strings block.
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
#include "omnitrace/core/Hash.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint32_t kBeginNode = 1, kEndNode = 2, kProp = 3, kNop = 4, kEnd = 9;
constexpr std::uint64_t kDefaultMaxNodes = 65536;
constexpr std::uint64_t kDefaultMaxProps = 262144;
constexpr std::uint64_t kDefaultMaxDepth = 64;
// Bytes one FIT may hash while verifying its images (Signature::extra
// "max_hash_bytes"); a hostile FIT could otherwise name thousands of 4 GiB
// payloads inside a large image and stall the scan for hours.
constexpr std::uint64_t kDefaultMaxHashBytes = 1ull << 30;

struct FdtHeader {
    std::uint32_t totalsize = 0, off_dt_struct = 0, off_dt_strings = 0, off_mem_rsvmap = 0,
                  version = 0, last_comp_version = 0, boot_cpuid_phys = 0, size_dt_strings = 0,
                  size_dt_struct = 0;
};

std::optional<FdtHeader> read_header(const Span& span, std::uint64_t start) {
    std::array<std::uint8_t, 40> raw{};
    if (span.read(start, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size())
        return std::nullopt;
    auto u32 = [&](std::size_t o) { return load_int<std::uint32_t>(raw.data() + o, Endian::Big); };
    if (u32(0) != 0xd00dfeedu) return std::nullopt;
    FdtHeader h;
    h.totalsize = u32(4);
    h.off_dt_struct = u32(8);
    h.off_dt_strings = u32(12);
    h.off_mem_rsvmap = u32(16);
    h.version = u32(20);
    h.last_comp_version = u32(24);
    h.boot_cpuid_phys = u32(28);
    h.size_dt_strings = u32(32);
    h.size_dt_struct = u32(36);
    return h;
}

// Hard header constraints. Returns a diagnostic code, or empty when sane.
std::string header_problem(const FdtHeader& h) {
    if (h.totalsize < 40) return "fdt-bad-totalsize";
    if (h.version < 16 || h.version > 17 || h.last_comp_version > h.version ||
        h.last_comp_version < 16)
        return "fdt-unsupported-version";
    if ((h.off_dt_struct & 3u) != 0 || h.off_dt_struct < 40 || h.off_dt_struct >= h.totalsize)
        return "fdt-bad-struct-offset";
    if (h.size_dt_struct > h.totalsize - h.off_dt_struct) return "fdt-bad-struct-size";
    if (h.off_dt_strings < 40 || h.off_dt_strings > h.totalsize) return "fdt-bad-strings-offset";
    if (h.size_dt_strings > h.totalsize - h.off_dt_strings) return "fdt-bad-strings-size";
    if ((h.off_mem_rsvmap & 7u) != 0 || h.off_mem_rsvmap < 40 || h.off_mem_rsvmap >= h.totalsize)
        return "fdt-bad-rsvmap-offset";
    return {};
}

struct Node {
    std::string name;
    std::uint32_t parent = 0;  // index; root is its own parent
    std::uint32_t depth = 0;
};

struct Prop {
    std::uint32_t node = 0;
    std::string name;
    std::uint64_t off = 0;  // Span-relative offset of the data
    std::uint32_t len = 0;
};

struct Tree {
    std::vector<Node> nodes;
    std::vector<Prop> props;
    // Per node, in token order: its subnodes and its properties. Looked up
    // per image, so a hostile FIT with max_nodes images costs O(nodes), not
    // O(nodes * (nodes + props)).
    std::vector<std::vector<std::uint32_t>> children;
    std::vector<std::vector<std::uint32_t>> node_props;
    bool complete = false;  // END token reached with balanced nesting
    std::string problem;    // diagnostic code when !complete
    bool limit_hit = false;

    std::optional<std::uint32_t> child(std::uint32_t parent, std::string_view name) const {
        if (parent >= children.size()) return std::nullopt;
        for (const std::uint32_t i : children[parent])
            if (nodes[i].name == name) return i;
        return std::nullopt;
    }
    const Prop* prop(std::uint32_t node, std::string_view name) const {
        if (node >= node_props.size()) return nullptr;
        for (const std::uint32_t p : node_props[node])
            if (props[p].name == name) return &props[p];
        return nullptr;
    }
};

struct WalkLimits {
    std::uint64_t max_nodes = kDefaultMaxNodes;
    std::uint64_t max_props = kDefaultMaxProps;
    std::uint64_t max_depth = kDefaultMaxDepth;
};

Tree walk(const Span& span, std::uint64_t start, const FdtHeader& h, const WalkLimits& lim) {
    Tree t;
    const std::uint64_t struct_base = start + h.off_dt_struct;
    const std::uint64_t struct_end = struct_base + h.size_dt_struct;
    const std::uint64_t strings_base = start + h.off_dt_strings;
    std::uint64_t pos = struct_base;
    std::vector<std::uint32_t> stack;
    auto token = [&](std::uint64_t at) -> std::optional<std::uint32_t> {
        if (at + 4 > struct_end) return std::nullopt;
        return span.at<std::uint32_t>(at, Endian::Big);
    };
    while (true) {
        const auto tok = token(pos);
        if (!tok) {
            t.problem = "fdt-struct-overrun";
            return t;
        }
        pos += 4;
        if (*tok == kBeginNode) {
            if (t.nodes.size() >= lim.max_nodes) {
                t.problem = "fdt-limit-nodes";
                t.limit_hit = true;
                return t;
            }
            if (stack.size() >= lim.max_depth) {
                t.problem = "fdt-limit-depth";
                t.limit_hit = true;
                return t;
            }
            const auto name = span.cstring(pos, static_cast<std::size_t>(struct_end - pos));
            if (!name || pos + name->size() >= struct_end) {
                t.problem = "fdt-bad-node-name";
                return t;
            }
            if (!stack.empty() && name->empty()) {
                t.problem = "fdt-bad-node-name";  // only the root may be unnamed
                return t;
            }
            pos = (pos + name->size() + 1 + 3) & ~std::uint64_t{3};
            Node n;
            n.name = *name;
            n.parent = stack.empty() ? 0 : stack.back();
            n.depth = static_cast<std::uint32_t>(stack.size());
            if (stack.empty() && !t.nodes.empty()) {
                t.problem = "fdt-multiple-roots";
                return t;
            }
            const auto idx = static_cast<std::uint32_t>(t.nodes.size());
            if (!stack.empty()) t.children[stack.back()].push_back(idx);
            stack.push_back(idx);
            t.nodes.push_back(std::move(n));
            t.children.emplace_back();
            t.node_props.emplace_back();
        } else if (*tok == kEndNode) {
            if (stack.empty()) {
                t.problem = "fdt-unbalanced";
                return t;
            }
            stack.pop_back();
        } else if (*tok == kProp) {
            if (stack.empty()) {
                t.problem = "fdt-prop-outside-node";
                return t;
            }
            if (t.props.size() >= lim.max_props) {
                t.problem = "fdt-limit-props";
                t.limit_hit = true;
                return t;
            }
            const auto len = token(pos);
            const auto nameoff = token(pos + 4);
            if (!len || !nameoff) {
                t.problem = "fdt-struct-overrun";
                return t;
            }
            pos += 8;
            if (*len > struct_end - pos) {
                t.problem = "fdt-prop-overrun";
                return t;
            }
            if (*nameoff >= h.size_dt_strings) {
                t.problem = "fdt-bad-prop-name";
                return t;
            }
            const auto pname = span.cstring(strings_base + *nameoff, h.size_dt_strings - *nameoff);
            if (!pname) {
                t.problem = "fdt-bad-prop-name";
                return t;
            }
            Prop p;
            p.node = stack.back();
            p.name = *pname;
            p.off = pos;
            p.len = *len;
            t.node_props[stack.back()].push_back(static_cast<std::uint32_t>(t.props.size()));
            t.props.push_back(std::move(p));
            pos = (pos + *len + 3) & ~std::uint64_t{3};
        } else if (*tok == kNop) {
            continue;
        } else if (*tok == kEnd) {
            if (!stack.empty()) {
                t.problem = "fdt-unbalanced";
                return t;
            }
            if (t.nodes.empty()) {
                t.problem = "fdt-no-root";
                return t;
            }
            t.complete = true;
            return t;
        } else {
            t.problem = "fdt-bad-token";
            return t;
        }
    }
}

WalkLimits limits_from(const Signature& sig) {
    WalkLimits l;
    l.max_nodes = extra_u64(sig, "max_nodes").value_or(kDefaultMaxNodes);
    l.max_props = extra_u64(sig, "max_props").value_or(kDefaultMaxProps);
    l.max_depth = extra_u64(sig, "max_depth").value_or(kDefaultMaxDepth);
    return l;
}

// First string of a string(-list) property, control bytes dropped.
std::optional<std::string> prop_string(const Span& span, const Prop* p) {
    if (p == nullptr || p->len == 0) return std::nullopt;
    const auto s = span.cstring(p->off, p->len);
    if (!s) return std::nullopt;
    std::string out;
    for (const char ch : *s) {
        const auto u = static_cast<unsigned char>(ch);
        out.push_back(u < 0x20 || u == 0x7F ? '_' : ch);
    }
    return out;
}

std::optional<std::uint32_t> prop_u32(const Span& span, const Prop* p) {
    if (p == nullptr || p->len != 4) return std::nullopt;
    return span.at<std::uint32_t>(p->off, Endian::Big);
}

// Every string in a string-list property, joined with ','.
std::string prop_string_list(const Span& span, const Prop* p) {
    if (p == nullptr || p->len == 0) return {};
    const auto raw = span.bytes(p->off, p->len);
    if (!raw) return {};
    std::string out, cur;
    for (const std::uint8_t b : *raw) {
        if (b == 0) {
            if (!cur.empty()) {
                if (!out.empty()) out.push_back(',');
                out += list_safe(cur);
                cur.clear();
            }
        } else {
            cur.push_back(static_cast<char>(b));
        }
    }
    if (!cur.empty()) {
        if (!out.empty()) out.push_back(',');
        out += list_safe(cur);
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
    if (const auto model = prop_string(span, t.prop(0, "model"))) f.attrs["model"] = *model;
    const std::string compat = prop_string_list(span, t.prop(0, "compatible"));
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
    if (const auto d = prop_string(span, t.prop(0, "description"))) f.attrs["description"] = *d;
    if (const auto ts = prop_u32(span, t.prop(0, "timestamp"))) f.attrs["timestamp"] = dec(*ts);
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
        if (const auto ty = prop_string(span, t.prop(i, "type"))) im.type = *ty;
        if (const auto c = prop_string(span, t.prop(i, "compression"))) im.compression = *c;
        if (const Prop* data = t.prop(i, "data")) {
            im.off = data->off;
            im.size = data->len;
            im.present = true;
        } else {
            const auto dsize = prop_u32(span, t.prop(i, "data-size"));
            const auto dpos = prop_u32(span, t.prop(i, "data-position"));
            const auto doff = prop_u32(span, t.prop(i, "data-offset"));
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
            const auto algo = prop_string(span, t.prop(k, "algo"));
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
                const std::string v = prop_string_list(span, t.prop(i, key));
                if (v.empty()) continue;
                if (!first) cl.push_back(',');
                first = false;
                cl += std::string(key) + "=" + v;
            }
        }
        f.attrs["configurations"] = cl;
        if (const auto d = prop_string(span, t.prop(*confs, "default")))
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
