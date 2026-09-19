// Manifest.cpp — the evidence graph container. Ids are assigned here, in
// insertion order, so the same sequence of add_node calls always yields the
// same ids and the same manifest.yaml.
#include "omnitrace/core/Manifest.h"

#include <cstdio>
#include <utility>

namespace omnitrace {

namespace {

// "n" followed by the 1-based counter zero-padded to six digits. Counters past
// 999999 simply grow wider; they still sort correctly as strings up to that
// point and remain unique beyond it.
std::string make_node_id(std::size_t counter) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "n%06zu", counter);
    return buf;
}

}  // namespace

Node& Manifest::add_node(Node n) {
    n.id = make_node_id(nodes_.size() + 1);
    n.child_ids.clear();  // children are linked as they are added, never pre-set
    if (!n.parent_id.empty()) {
        if (Node* parent = find(n.parent_id)) {
            parent->child_ids.push_back(n.id);
        } else {
            // Dangling parent: keep the reference (it is what the reader said)
            // but tell the examiner the link could not be resolved.
            n.diagnostics.push_back({Severity::Warning, "manifest-parent-missing",
                                     "parent node '" + n.parent_id + "' is not in the graph"});
        }
    }
    index_.emplace(n.id, nodes_.size());
    nodes_.push_back(std::move(n));
    return nodes_.back();
}

const Node* Manifest::find(const std::string& id) const {
    const auto it = index_.find(id);
    if (it == index_.end()) return nullptr;
    return &nodes_[it->second];
}

Node* Manifest::find(const std::string& id) {
    const auto it = index_.find(id);
    if (it == index_.end()) return nullptr;
    return &nodes_[it->second];
}

std::vector<const Node*> Manifest::children_of(const std::string& id) const {
    std::vector<const Node*> out;
    const Node* parent = find(id);
    if (!parent) return out;
    out.reserve(parent->child_ids.size());
    for (const std::string& child : parent->child_ids) {
        if (const Node* c = find(child)) out.push_back(c);
    }
    return out;
}

std::size_t Manifest::count(NodeKind k) const {
    std::size_t n = 0;
    for (const Node& node : nodes_) {
        if (node.kind == k) ++n;
    }
    return n;
}

}  // namespace omnitrace
