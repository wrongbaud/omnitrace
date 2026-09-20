// Fdt.h — the flattened device tree container, shared by the DTB/FIT
// validators and the FIT container reader.
/// @file Fdt.h
/// @brief Parser for the flattened device tree (DTB) binary format: header,
/// structure-block walk, and property accessors.
///
/// The format is one big-endian header of ten u32 (magic 0xd00dfeed,
/// totalsize, off_dt_struct, off_dt_strings, off_mem_rsvmap, version,
/// last_comp_version, boot_cpuid_phys, size_dt_strings, size_dt_struct)
/// followed by a token stream: BEGIN_NODE(1) + NUL-terminated name padded to
/// 4, END_NODE(2), PROP(3) + u32 len + u32 nameoff + data padded to 4,
/// NOP(4), END(9). Property names live in the strings block.
///
/// It lives in core because two layers read the same bytes: the `dtb` and
/// `fit` validators (src/discovery/validators/fit.cpp) decide what a
/// structure is, and `container::FitReader` extracts the payloads a FIT's
/// `/images` node points at. Neither owns the parse.
///
/// Everything here is pure: it reads through the Span and holds no state
/// beyond the returned Tree, so it is safe from any thread.
///
/// Reference: Devicetree Specification ch. 5 (flattened format).
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "omnitrace/core/Span.h"

/// @namespace omnitrace::fdt
/// @brief Flattened device tree parsing.
namespace omnitrace::fdt {

/// The header magic, big-endian at the structure's first byte.
inline constexpr std::uint32_t kMagic = 0xD00DFEEDu;
/// Bytes of header the v16/v17 format defines.
inline constexpr std::uint64_t kHeaderSize = 40;

/// Structure-block token ids.
inline constexpr std::uint32_t kBeginNode = 1, kEndNode = 2, kProp = 3, kNop = 4, kEnd = 9;

/// Defaults for `Limits`. A tree past any of these is treated as hostile
/// rather than walked: the token stream is attacker-controlled and a scan
/// meets thousands of accidental magics.
inline constexpr std::uint64_t kDefaultMaxNodes = 65536;
/// @copydoc kDefaultMaxNodes
inline constexpr std::uint64_t kDefaultMaxProps = 262144;
/// @copydoc kDefaultMaxNodes
inline constexpr std::uint64_t kDefaultMaxDepth = 64;

/// The ten header fields, `magic` excluded (`read_header` checks it).
struct Header {
    std::uint32_t totalsize = 0,      ///< Bytes from the magic to the end of the tree.
        off_dt_struct = 0,            ///< Structure block, from the magic.
        off_dt_strings = 0,           ///< Strings block, from the magic.
        off_mem_rsvmap = 0,           ///< Memory reservation block, from the magic.
        version = 0,                  ///< Format version (16 or 17 here).
        last_comp_version = 0,        ///< Oldest version this is compatible with.
        boot_cpuid_phys = 0,          ///< Physical id of the boot CPU.
        size_dt_strings = 0,          ///< Bytes of strings block.
        size_dt_struct = 0;           ///< Bytes of structure block.
};

/// One node of the tree. `parent` indexes `Tree::nodes`; the root is its own
/// parent, so walking up from any node terminates at index 0.
struct Node {
    std::string name;          ///< Node name, raw bytes from the tree.
    std::uint32_t parent = 0;  ///< Index into `Tree::nodes`; the root is its own parent.
    std::uint32_t depth = 0;   ///< 0 for the root.
};

/// One property. `off` is a Span-relative offset, so the value is read back
/// through the same Span the tree was walked from and never copied here: a
/// FIT's inline `data` property can be tens of megabytes.
struct Prop {
    std::uint32_t node = 0;  ///< Index into `Tree::nodes`.
    std::string name;        ///< Property name from the strings block.
    std::uint64_t off = 0;   ///< Span-relative offset of the value.
    std::uint32_t len = 0;   ///< Bytes of value.
};

/// Bounds on one `walk`. See `kDefaultMaxNodes`.
struct Limits {
    std::uint64_t max_nodes = kDefaultMaxNodes;  ///< Nodes before the walk gives up.
    std::uint64_t max_props = kDefaultMaxProps;  ///< Properties before the walk gives up.
    std::uint64_t max_depth = kDefaultMaxDepth;  ///< Nesting before the walk gives up.
};

/// The result of a `walk`: every node and property in token order, plus the
/// parent-to-child and node-to-property indexes.
///
/// A partial tree is still returned when the walk stopped early: `complete`
/// is false, `problem` names why, and everything parsed up to that point is
/// usable evidence.
struct Tree {
    std::vector<Node> nodes;  ///< Every node, in token order; index 0 is the root.
    std::vector<Prop> props;  ///< Every property, in token order.
    /// Per node, in token order: its subnodes. Built during the walk so a
    /// lookup costs O(children), not O(nodes).
    std::vector<std::vector<std::uint32_t>> children;
    /// Per node, in token order: its properties. Same reason.
    std::vector<std::vector<std::uint32_t>> node_props;
    bool complete = false;   ///< END token reached with balanced nesting.
    std::string problem;     ///< Diagnostic code when `!complete`.
    bool limit_hit = false;  ///< `problem` is a `Limits` cap, not malformed data.

    /// Index of `parent`'s subnode called `name`, or nullopt.
    std::optional<std::uint32_t> child(std::uint32_t parent, std::string_view name) const;
    /// `node`'s property called `name`, or nullptr. The pointer is into
    /// `props` and is invalidated by anything that mutates this Tree.
    const Prop* prop(std::uint32_t node, std::string_view name) const;
};

/// Read the header at `start`. Nullopt when fewer than 40 bytes are readable
/// or the magic is not `kMagic`; the fields are not checked (`header_problem`).
std::optional<Header> read_header(const Span& span, std::uint64_t start);

/// Hard constraints on `h`: returns a diagnostic code (`fdt-bad-totalsize`,
/// `fdt-unsupported-version`, ...), or an empty string when the header is
/// self-consistent. A header that fails this is not worth walking.
std::string header_problem(const Header& h);

/// Walk the structure block of the tree whose header is at `start`.
///
/// Never throws and never reads outside `span`: every token, name and value
/// is bounds-checked against the structure block the header declared. On any
/// malformed token the walk returns what it had, with `Tree::problem` set.
Tree walk(const Span& span, std::uint64_t start, const Header& h, const Limits& lim);

/// First string of a string(-list) property, raw. Nullopt when `p` is null,
/// empty, or not NUL-terminated inside its own length. Callers that put the
/// result in output run it through `sanitize_utf8` (Text.h) first.
std::optional<std::string> prop_string(const Span& span, const Prop* p);

/// A big-endian u32 property (`#address-cells`, `timestamp`, `data-size`).
/// Nullopt unless the property is exactly 4 bytes.
std::optional<std::uint32_t> prop_u32(const Span& span, const Prop* p);

/// Every string of a string-list property (`compatible`, a FIT
/// configuration's `loadables`), in order, empties dropped.
std::vector<std::string> prop_strings(const Span& span, const Prop* p);

}  // namespace omnitrace::fdt
