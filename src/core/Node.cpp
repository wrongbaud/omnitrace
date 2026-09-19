// Node.cpp — name tables for the evidence-graph enums. Names are the stable
// strings that land in manifest.yaml, so they never change once published.
#include "omnitrace/core/Node.h"

#include <cstddef>

namespace omnitrace {

namespace {

struct KindName {
    NodeKind kind;
    const char* name;
};

constexpr KindName kNodeKinds[] = {
    {NodeKind::Image, "image"},         {NodeKind::Partition, "partition"},
    {NodeKind::Container, "container"}, {NodeKind::Filesystem, "filesystem"},
    {NodeKind::File, "file"},           {NodeKind::Region, "region"},
    {NodeKind::Artifact, "artifact"},
};

}  // namespace

const char* node_kind_name(NodeKind k) {
    for (const KindName& e : kNodeKinds) {
        if (e.kind == k) return e.name;
    }
    return "unknown";
}

std::optional<NodeKind> node_kind_from_name(const std::string& s) {
    for (const KindName& e : kNodeKinds) {
        if (s == e.name) return e.kind;
    }
    return std::nullopt;
}

const char* entry_kind_name(EntryKind k) {
    switch (k) {
        case EntryKind::Regular:
            return "regular";
        case EntryKind::Directory:
            return "directory";
        case EntryKind::Symlink:
            return "symlink";
        case EntryKind::CharDevice:
            return "char-device";
        case EntryKind::BlockDevice:
            return "block-device";
        case EntryKind::Fifo:
            return "fifo";
        case EntryKind::Socket:
            return "socket";
        case EntryKind::Unknown:
            break;
    }
    return "unknown";
}

}  // namespace omnitrace
