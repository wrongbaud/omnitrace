// FitReader.cpp — U-Boot FIT image (flattened image tree).
//
// A FIT is a flattened device tree (omnitrace::fdt, include/omnitrace/core/Fdt.h)
// whose root holds an /images node. Every subnode of /images is one payload,
// and carries it in one of two ways:
//
//   inline    a "data" property holds the bytes, so the payload is inside the
//             tree and the FIT is one self-contained blob.
//   external  "data-size" plus either "data-position" (absolute, from the
//             FIT's first byte) or "data-offset" (relative to the 4-aligned
//             end of the tree). mkimage -E writes these; the bytes follow the
//             tree, so totalsize is *not* the size of the file.
//
// Both are resolved in open(), which is also where the container's own size
// comes from: totalsize, extended by the furthest external payload.
//
// src/discovery/validators/fit.cpp does the same resolution to score the
// structure and verify the hash subnodes. This reader repeats it because a
// reader is handed a Span and never a Finding, and then emits the payloads.
//
// Payloads are emitted as stored. "compression" says how each one is packed,
// but decoding here would duplicate the stream readers: the analysis pass
// re-scans every extracted file, so a gzip ramdisk is found and unpacked one
// level down.
// Reference: U-Boot doc/usage/fit/source_file_format.rst; `dumpimage -l`,
// whose listing this matches.
#include "FitReader.h"

#include <algorithm>
#include <set>
#include <string>
#include <utility>

#include "../common.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::container {

namespace {

// Stable codes; literal so scripts/gen_docs.py can catalogue them. The fit-*
// pair is shared with the validator, which reports the same two conditions
// from the other side.
constexpr const char* kCodeDataMissing = "fit-data-missing";
constexpr const char* kCodeNoImages = "fit-no-images";
constexpr const char* kCodeShortSection = "container-section-truncated";
constexpr const char* kCodeSinkError = "container-sink-error";

std::uint64_t align4(std::uint64_t v) {
    return v > UINT64_MAX - 3 ? v : (v + 3) & ~std::uint64_t{3};
}

// A "load" or "entry" address, which is 4 or 8 bytes depending on the tree's
// #address-cells. Rendered as hex because that is how U-Boot writes it.
std::optional<std::string> address_prop(const Span& span, const fdt::Prop* p) {
    if (p == nullptr) return std::nullopt;
    std::uint64_t v = 0;
    if (p->len == 4) {
        const auto n = span.at<std::uint32_t>(p->off, Endian::Big);
        if (!n) return std::nullopt;
        v = *n;
    } else if (p->len == 8) {
        const auto n = span.at<std::uint64_t>(p->off, Endian::Big);
        if (!n) return std::nullopt;
        v = *n;
    } else {
        return std::nullopt;
    }
    std::string out = "0x";
    for (int shift = 60; shift >= 0; shift -= 4) {
        const auto nib = static_cast<unsigned>((v >> shift) & 0xF);
        if (out.size() > 2 || nib != 0 || shift == 0) out.push_back("0123456789abcdef"[nib]);
    }
    return out;
}

// A string property, made safe for output. The tree holds raw evidence bytes.
std::string text_prop(const Span& span, const fdt::Prop* p) {
    const auto s = fdt::prop_string(span, p);
    return s ? sanitize_utf8(*s) : std::string{};
}

}  // namespace

Status FitReader::open(const Span& span) {
    opened_ = false;
    consumed_ = 0;
    tree_ = fdt::Tree{};
    const auto h = fdt::read_header(span, 0);
    if (!h) return Status::fail("container-bad-magic: no FDT magic at offset 0");
    if (const std::string problem = fdt::header_problem(*h); !problem.empty())
        return Status::fail("container-bad-header: the FDT header is not self-consistent (" +
                            problem + ")");
    // The tree itself has to be present. External payloads may be missing (a
    // carved partition can cut them off) and that is reported per image, but a
    // tree that is not there cannot be walked at all.
    if (h->off_dt_struct + static_cast<std::uint64_t>(h->size_dt_struct) > span.size() ||
        h->off_dt_strings + static_cast<std::uint64_t>(h->size_dt_strings) > span.size())
        return Status::fail("container-truncated: the FDT structure or strings block is not "
                            "inside the container's bytes");

    header_ = *h;
    span_ = span;
    tree_ = fdt::walk(span, 0, header_, fdt::Limits{});
    if (tree_.nodes.empty())
        return Status::fail("container-bad-header: the FDT structure block has no root node");
    const auto images_node = tree_.child(0, "images");
    // Without /images this is a plain device tree blob, which is a structure
    // to report rather than a container to walk.
    if (!images_node)
        return Status::fail("container-bad-header: the FDT root has no /images node");
    images_node_ = *images_node;

    std::uint64_t end = header_.totalsize;
    for (const Image& im : images()) {
        if (!im.present) continue;
        end = std::max(end, im.off + im.size);
    }
    consumed_ = std::min(end, span.size());
    opened_ = true;
    return Status::success();
}

// Resolve every /images subnode to a payload location. Cheap enough to run
// from both open() and walk(): it reads a handful of properties per image and
// copies nothing.
std::vector<FitReader::Image> FitReader::images() const {
    std::vector<Image> out;
    if (images_node_ >= tree_.children.size()) return out;
    const std::uint64_t ext_base = align4(header_.totalsize);
    std::set<std::string> taken;
    for (const std::uint32_t i : tree_.children[images_node_]) {
        Image im;
        im.node = i;
        // The node name is evidence and steers where the Sink writes, so it
        // becomes one host-safe component. Two names that collapse to the same
        // component would otherwise overwrite each other.
        im.name = safe_filename_component(tree_.nodes[i].name);
        for (unsigned n = 2; !taken.insert(im.name).second; ++n)
            im.name = safe_filename_component(tree_.nodes[i].name) + "_" + std::to_string(n);

        if (const fdt::Prop* data = tree_.prop(i, "data")) {
            im.off = data->off;
            im.size = data->len;
            im.present = true;
        } else if (const auto size = fdt::prop_u32(span_, tree_.prop(i, "data-size"))) {
            const auto pos = fdt::prop_u32(span_, tree_.prop(i, "data-position"));
            const auto rel = fdt::prop_u32(span_, tree_.prop(i, "data-offset"));
            if (!pos && !rel) {
                out.push_back(std::move(im));  // data-size with nowhere to read from
                continue;
            }
            im.external = true;
            im.size = *size;
            im.off = pos ? *pos : ext_base + *rel;
            im.present = im.off <= span_.size() && im.size <= span_.size() - im.off;
        }
        out.push_back(std::move(im));
    }
    return out;
}

ContainerInfo FitReader::info() const {
    ContainerInfo i;
    i.format = "fit";
    i.size = consumed_;
    i.attrs["version"] = std::to_string(header_.version);
    i.attrs["totalsize"] = std::to_string(header_.totalsize);
    if (!tree_.nodes.empty()) {
        const std::string desc = text_prop(span_, tree_.prop(0, "description"));
        if (!desc.empty()) i.attrs["description"] = desc;
        if (const auto confs = tree_.child(0, "configurations")) {
            const std::string def = text_prop(span_, tree_.prop(*confs, "default"));
            if (!def.empty()) i.attrs["default_configuration"] = def;
        }
    }
    if (images_node_ < tree_.children.size())
        i.attrs["image_count"] = std::to_string(tree_.children[images_node_].size());
    return i;
}

Status FitReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    if (!opened_) return Status::fail("container-not-open: walk before a successful open");

    if (!tree_.complete) {
        // The tree stopped short, so /images may be missing subnodes. What was
        // parsed is still emitted; the code says which way it broke.
        out.diagnostics.push_back({Severity::Warning, tree_.problem,
                                   "the FIT's structure block did not parse to END (" +
                                       tree_.problem + ") after " +
                                       std::to_string(tree_.nodes.size()) + " node(s)"});
        out.truncated = true;
    }

    const std::vector<Image> imgs = images();
    if (imgs.empty()) {
        out.diagnostics.push_back(
            {Severity::Warning, kCodeNoImages, "/images has no subnodes; nothing to extract"});
        return Status::success();
    }

    for (const Image& im : imgs) {
        if (!im.present) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeDataMissing,
                 "'" + im.name + "' has no payload inside the container: " +
                     (im.external ? std::to_string(im.size) + " bytes at " +
                                        std::to_string(im.off) + " are past its end"
                                  : std::string("neither an inline 'data' property nor a "
                                                "'data-size' with a position"))});
            out.truncated = true;
            continue;
        }

        FileMeta meta;
        meta.path = im.name;
        meta.kind = EntryKind::Regular;
        meta.mode = 0644;
        meta.size = im.size;
        for (const char* key : {"description", "type", "os", "arch", "compression"}) {
            const std::string v = text_prop(span_, tree_.prop(im.node, key));
            if (!v.empty()) meta.extra[key] = v;
        }
        for (const char* key : {"load", "entry"}) {
            if (const auto v = address_prop(span_, tree_.prop(im.node, key))) meta.extra[key] = *v;
        }
        meta.extra["storage"] = im.external ? "external" : "inline";

        EntryResult r;
        bool short_read = false;
        const Status st = emit_span_file(sink, opts, meta, span_, im.off, im.size, r, short_read);
        if (!st) {
            out.diagnostics.push_back(
                {Severity::Warning, kCodeSinkError, "'" + im.name + "': " + st.error});
            continue;
        }
        if (short_read) {
            out.diagnostics.push_back({Severity::Warning, kCodeShortSection,
                                       "'" + im.name + "' ends before the " +
                                           std::to_string(im.size) + " bytes the tree claims"});
            r.truncated = true;
            out.truncated = true;
        }
        count_entry(out, r);
        out.entries_out.push_back(std::move(r));
    }
    return Status::success();
}

OMNITRACE_REGISTER_CONTAINER("fit", FitReader);

namespace detail {
void omnitrace_container_anchor_fit() {}
}  // namespace detail

}  // namespace omnitrace::container
