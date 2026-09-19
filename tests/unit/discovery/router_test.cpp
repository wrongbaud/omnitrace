// router_test.cpp — end-to-end scan of a real router image when present.
#include <gtest/gtest.h>

#include <filesystem>

#include "helpers.h"

using namespace omnitrace;
using namespace omnitrace::discovery;

TEST(Router, KnownLayout) {
    const std::string path = "/home/wrongbaud/projects/omnitrace/firmware/router.bin";
    if (!std::filesystem::exists(path)) GTEST_SKIP() << "router.bin not available";
    std::shared_ptr<MappedFile> file;
    const Status st = MappedFile::open(path, file);
    ASSERT_TRUE(st) << st.error;
    const auto found = scan(Span::whole(file), SignatureSet::builtin());
    const Finding* uimage = test::find_at(found, 0x50000, "uimage");
    ASSERT_NE(uimage, nullptr);
    EXPECT_EQ(uimage->confidence, Confidence::Verified);
    EXPECT_EQ(uimage->attrs.at("compression"), "lzma");
    EXPECT_EQ(uimage->attrs.at("arch"), "mips");
    EXPECT_EQ(uimage->attrs.at("os"), "linux");
    EXPECT_EQ(uimage->attrs.at("type"), "kernel");
    EXPECT_EQ(uimage->category, "kernel");
    EXPECT_EQ(uimage->attrs.at("data_crc"), "ok");
    EXPECT_EQ(uimage->offset + uimage->size, 0x1c9245u);
    const Finding* sq = test::find_at(found, 0x1c9245, "squashfs");
    ASSERT_NE(sq, nullptr);
    EXPECT_EQ(sq->confidence, Confidence::Consistent);
    EXPECT_EQ(sq->attrs.at("compression"), "xz");
    EXPECT_EQ(sq->attrs.at("version"), "4.0");
    EXPECT_LE(sq->offset + sq->size, 0xc60000u);
    const Finding* j = test::find_at(found, 0xc60000, "jffs2");
    ASSERT_NE(j, nullptr);
    EXPECT_EQ(j->confidence, Confidence::Verified);
    EXPECT_EQ(j->endian, Endian::Little);
    EXPECT_EQ(j->attrs.at("nodes"), "2519");
    EXPECT_EQ(j->offset + j->size, 0xff000cu);
    // One finding per structure, not one per node or per erase block.
    std::size_t jffs2_count = 0;
    for (const Finding& f : found) jffs2_count += f.format == "jffs2";
    EXPECT_EQ(jffs2_count, 1u);
}
