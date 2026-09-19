// Manifest.h — the whole case as data. Serialized to manifest.yaml (output/).
#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "omnitrace/core/Node.h"

namespace omnitrace {

struct Evidence {
    std::string id;    // "e1", "e2", ...
    std::string path;  // as given by the examiner
    std::uint64_t size = 0;
    Digests digests;
    std::string acquired_at;  // ISO-8601, examiner supplied or file mtime
    std::string note;
};

struct RunInfo {
    std::string tool = "omnitrace";
    std::string version;   // OMNITRACE_VERSION
    std::string git_sha;   // if known
    std::string started_at, finished_at;  // ISO-8601 from Clock
    std::string host_os;
    std::vector<std::string> argv;
};

class Manifest {
public:
    static constexpr const char* kSchema = "omnitrace/1";

    RunInfo run;
    std::vector<Evidence> evidence;
    std::vector<Coverage> coverage;
    std::vector<ToolRecord> tools;
    std::vector<Diagnostic> diagnostics;  // run-level

    // Graph. Nodes are stored in insertion order; ids are assigned here.
    Node& add_node(Node n);  // sets n.id, links into parent's child_ids
    const Node* find(const std::string& id) const;
    Node* find(const std::string& id);
    const std::vector<Node>& nodes() const { return nodes_; }
    std::vector<const Node*> children_of(const std::string& id) const;
    std::size_t count(NodeKind k) const;

private:
    std::vector<Node> nodes_;
    std::map<std::string, std::size_t> index_;
};

}  // namespace omnitrace
