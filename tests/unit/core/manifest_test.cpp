// manifest_test.cpp — id assignment, parent/child linking, lookups.
#include "omnitrace/core/Manifest.h"

#include <gtest/gtest.h>

#include <string>

namespace omnitrace {
namespace {

Node make(NodeKind k, const std::string& parent = {}, const std::string& name = {}) {
    Node n;
    n.kind = k;
    n.parent_id = parent;
    n.name = name;
    return n;
}

TEST(Manifest, IdsAreZeroPaddedAndSequential) {
    Manifest m;
    const Node& a = m.add_node(make(NodeKind::Image));
    EXPECT_EQ(a.id, "n000001");
    const Node& b = m.add_node(make(NodeKind::Partition, "n000001"));
    EXPECT_EQ(b.id, "n000002");
    for (int i = 0; i < 10; ++i) m.add_node(make(NodeKind::Region, "n000001"));
    EXPECT_EQ(m.nodes().back().id, "n000012");
    EXPECT_EQ(m.nodes().size(), 12u);
}

TEST(Manifest, IdIsAssignedEvenIfCallerSetOne) {
    Manifest m;
    Node n = make(NodeKind::Image);
    n.id = "bogus";
    n.child_ids = {"x", "y"};  // stale links from the caller are discarded
    const Node& stored = m.add_node(n);
    EXPECT_EQ(stored.id, "n000001");
    EXPECT_TRUE(stored.child_ids.empty());
    EXPECT_EQ(m.find("bogus"), nullptr);
}

TEST(Manifest, ParentChildLinking) {
    Manifest m;
    m.add_node(make(NodeKind::Image, "", "img"));
    m.add_node(make(NodeKind::Partition, "n000001", "p0"));
    m.add_node(make(NodeKind::Partition, "n000001", "p1"));
    m.add_node(make(NodeKind::Filesystem, "n000003", "squashfs"));

    const Node* root = m.find("n000001");
    ASSERT_NE(root, nullptr);
    ASSERT_EQ(root->child_ids.size(), 2u);
    EXPECT_EQ(root->child_ids[0], "n000002");
    EXPECT_EQ(root->child_ids[1], "n000003");

    const auto kids = m.children_of("n000001");
    ASSERT_EQ(kids.size(), 2u);
    EXPECT_EQ(kids[0]->name, "p0");
    EXPECT_EQ(kids[1]->name, "p1");

    const auto grand = m.children_of("n000003");
    ASSERT_EQ(grand.size(), 1u);
    EXPECT_EQ(grand[0]->id, "n000004");
    EXPECT_EQ(grand[0]->parent_id, "n000003");

    EXPECT_TRUE(m.children_of("n000004").empty());
    EXPECT_TRUE(m.children_of("n999999").empty());
}

TEST(Manifest, FindMutableAndConst) {
    Manifest m;
    m.add_node(make(NodeKind::Image));
    Node* n = m.find("n000001");
    ASSERT_NE(n, nullptr);
    n->name = "renamed";
    const Manifest& cm = m;
    ASSERT_NE(cm.find("n000001"), nullptr);
    EXPECT_EQ(cm.find("n000001")->name, "renamed");
    EXPECT_EQ(cm.find(""), nullptr);
    EXPECT_EQ(cm.find("n1"), nullptr);
}

TEST(Manifest, DanglingParentIsDiagnosed) {
    Manifest m;
    const Node& n = m.add_node(make(NodeKind::File, "n000042"));
    EXPECT_EQ(n.parent_id, "n000042");  // kept as reported
    ASSERT_EQ(n.diagnostics.size(), 1u);
    EXPECT_EQ(n.diagnostics[0].code, "manifest-parent-missing");
    EXPECT_EQ(n.diagnostics[0].severity, Severity::Warning);
}

TEST(Manifest, CountByKind) {
    Manifest m;
    m.add_node(make(NodeKind::Image));
    m.add_node(make(NodeKind::Partition, "n000001"));
    m.add_node(make(NodeKind::Partition, "n000001"));
    m.add_node(make(NodeKind::File, "n000002"));
    EXPECT_EQ(m.count(NodeKind::Image), 1u);
    EXPECT_EQ(m.count(NodeKind::Partition), 2u);
    EXPECT_EQ(m.count(NodeKind::File), 1u);
    EXPECT_EQ(m.count(NodeKind::Artifact), 0u);
}

TEST(Manifest, InsertionOrderIsPreserved) {
    Manifest m;
    for (int i = 0; i < 100; ++i) m.add_node(make(NodeKind::Region, "", std::to_string(i)));
    for (std::size_t i = 0; i < 100; ++i) EXPECT_EQ(m.nodes()[i].name, std::to_string(i));
    // Lookups stay valid after the vector reallocated many times.
    EXPECT_EQ(m.find("n000050")->name, "49");
}

}  // namespace
}  // namespace omnitrace
