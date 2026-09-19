// node_test.cpp — enum name tables round-trip and never return null.
#include "omnitrace/core/Node.h"

#include <gtest/gtest.h>

#include <string>

namespace omnitrace {
namespace {

TEST(Node, KindNamesRoundTrip) {
    const NodeKind kinds[] = {NodeKind::Image,      NodeKind::Partition, NodeKind::Container,
                              NodeKind::Filesystem, NodeKind::File,      NodeKind::Region,
                              NodeKind::Artifact};
    for (NodeKind k : kinds) {
        const char* name = node_kind_name(k);
        ASSERT_NE(name, nullptr);
        EXPECT_FALSE(std::string(name).empty());
        const auto back = node_kind_from_name(name);
        ASSERT_TRUE(back.has_value()) << name;
        EXPECT_EQ(*back, k) << name;
    }
}

TEST(Node, KindNamesAreStable) {
    EXPECT_STREQ(node_kind_name(NodeKind::Image), "image");
    EXPECT_STREQ(node_kind_name(NodeKind::Partition), "partition");
    EXPECT_STREQ(node_kind_name(NodeKind::Container), "container");
    EXPECT_STREQ(node_kind_name(NodeKind::Filesystem), "filesystem");
    EXPECT_STREQ(node_kind_name(NodeKind::File), "file");
    EXPECT_STREQ(node_kind_name(NodeKind::Region), "region");
    EXPECT_STREQ(node_kind_name(NodeKind::Artifact), "artifact");
}

TEST(Node, UnknownKindNameRejected) {
    EXPECT_FALSE(node_kind_from_name("").has_value());
    EXPECT_FALSE(
        node_kind_from_name("Image").has_value());  // case-sensitive: this is a serialized token
    EXPECT_FALSE(node_kind_from_name("files").has_value());
    EXPECT_FALSE(node_kind_from_name(std::string("file\0x", 6)).has_value());
}

TEST(Node, OutOfRangeKindDoesNotCrash) {
    const auto bogus = static_cast<NodeKind>(200);
    EXPECT_STREQ(node_kind_name(bogus), "unknown");
    EXPECT_STREQ(entry_kind_name(static_cast<EntryKind>(200)), "unknown");
}

TEST(Node, EntryKindNames) {
    EXPECT_STREQ(entry_kind_name(EntryKind::Regular), "regular");
    EXPECT_STREQ(entry_kind_name(EntryKind::Directory), "directory");
    EXPECT_STREQ(entry_kind_name(EntryKind::Symlink), "symlink");
    EXPECT_STREQ(entry_kind_name(EntryKind::CharDevice), "char-device");
    EXPECT_STREQ(entry_kind_name(EntryKind::BlockDevice), "block-device");
    EXPECT_STREQ(entry_kind_name(EntryKind::Fifo), "fifo");
    EXPECT_STREQ(entry_kind_name(EntryKind::Socket), "socket");
    EXPECT_STREQ(entry_kind_name(EntryKind::Unknown), "unknown");
}

}  // namespace
}  // namespace omnitrace
