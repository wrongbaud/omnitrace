// Fdt.cpp — flattened device tree parsing. See the header for the format.
//
// This was the private parser inside src/discovery/validators/fit.cpp until
// the FIT container reader needed the same walk. Nothing here decides what a
// structure *is*: the validators score it, the reader extracts from it, and
// both get the same tree.
#include "omnitrace/core/Fdt.h"

#include <array>
#include <span>
#include <utility>

#include "omnitrace/core/Endian.h"

namespace omnitrace::fdt {

std::optional<std::uint32_t> Tree::child(std::uint32_t parent, std::string_view name) const {
    if (parent >= children.size()) return std::nullopt;
    for (const std::uint32_t i : children[parent])
        if (nodes[i].name == name) return i;
    return std::nullopt;
}

const Prop* Tree::prop(std::uint32_t node, std::string_view name) const {
    if (node >= node_props.size()) return nullptr;
    for (const std::uint32_t p : node_props[node])
        if (props[p].name == name) return &props[p];
    return nullptr;
}

std::optional<Header> read_header(const Span& span, std::uint64_t start) {
    std::array<std::uint8_t, kHeaderSize> raw{};
    if (span.read(start, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size())
        return std::nullopt;
    auto u32 = [&](std::size_t o) { return load_int<std::uint32_t>(raw.data() + o, Endian::Big); };
    if (u32(0) != kMagic) return std::nullopt;
    Header h;
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

std::string header_problem(const Header& h) {
    if (h.totalsize < kHeaderSize) return "fdt-bad-totalsize";
    if (h.version < 16 || h.version > 17 || h.last_comp_version > h.version ||
        h.last_comp_version < 16)
        return "fdt-unsupported-version";
    if ((h.off_dt_struct & 3u) != 0 || h.off_dt_struct < kHeaderSize ||
        h.off_dt_struct >= h.totalsize)
        return "fdt-bad-struct-offset";
    if (h.size_dt_struct > h.totalsize - h.off_dt_struct) return "fdt-bad-struct-size";
    if (h.off_dt_strings < kHeaderSize || h.off_dt_strings > h.totalsize)
        return "fdt-bad-strings-offset";
    if (h.size_dt_strings > h.totalsize - h.off_dt_strings) return "fdt-bad-strings-size";
    if ((h.off_mem_rsvmap & 7u) != 0 || h.off_mem_rsvmap < kHeaderSize ||
        h.off_mem_rsvmap >= h.totalsize)
        return "fdt-bad-rsvmap-offset";
    return {};
}

Tree walk(const Span& span, std::uint64_t start, const Header& h, const Limits& lim) {
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

std::optional<std::string> prop_string(const Span& span, const Prop* p) {
    if (p == nullptr || p->len == 0) return std::nullopt;
    return span.cstring(p->off, p->len);
}

std::optional<std::uint32_t> prop_u32(const Span& span, const Prop* p) {
    if (p == nullptr || p->len != 4) return std::nullopt;
    return span.at<std::uint32_t>(p->off, Endian::Big);
}

std::vector<std::string> prop_strings(const Span& span, const Prop* p) {
    std::vector<std::string> out;
    if (p == nullptr || p->len == 0) return out;
    const auto raw = span.bytes(p->off, p->len);
    if (!raw) return out;
    std::string cur;
    for (const std::uint8_t b : *raw) {
        if (b == 0) {
            if (!cur.empty()) out.push_back(std::exchange(cur, {}));
        } else {
            cur.push_back(static_cast<char>(b));
        }
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    return out;
}

}  // namespace omnitrace::fdt
