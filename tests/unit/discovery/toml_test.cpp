// toml_test.cpp — SignatureSet::load_toml / load_file / builtin.
#include <gtest/gtest.h>

#include <filesystem>

#include "helpers.h"

using namespace omnitrace;
using namespace omnitrace::discovery;

TEST(SignatureToml, LoadsEveryFieldAndExtras) {
    SignatureSet set;
    const Status st = set.load_toml(R"(
[[signature]]
name = "demo"
format = "demofs"
category = "filesystem"
hex = "0x68 73 71 73"
magic_offset = 16
endian = "big"
validator = "squashfs"
alignment = 4
description = "a demo"
references = ["https://a", "https://b"]
custom_int = 42
custom_str = "x"
custom_bool = true

[[signature]]
name = "plain"
format = "p"
category = "other"
magic = "PLAIN"
)",
                                    "unit");
    ASSERT_TRUE(st) << st.error;
    ASSERT_EQ(set.signatures.size(), 2u);
    const Signature& s = set.signatures[0];
    EXPECT_EQ(s.name, "demo");
    EXPECT_EQ(s.format, "demofs");
    EXPECT_EQ(s.category, "filesystem");
    EXPECT_EQ(s.magic, (test::Bytes{'h', 's', 'q', 's'}));
    EXPECT_EQ(s.magic_offset, 16u);
    ASSERT_TRUE(s.endian.has_value());
    EXPECT_EQ(*s.endian, Endian::Big);
    EXPECT_EQ(s.validator, "squashfs");
    EXPECT_EQ(s.alignment, 4u);
    EXPECT_EQ(s.description, "a demo");
    EXPECT_EQ(s.references, (std::vector<std::string>{"https://a", "https://b"}));
    EXPECT_EQ(s.extra.at("custom_int"), "42");
    EXPECT_EQ(s.extra.at("custom_str"), "x");
    EXPECT_EQ(s.extra.at("custom_bool"), "true");
    EXPECT_EQ(s.extra.count("name"), 0u);
    const Signature& p = set.signatures[1];
    EXPECT_EQ(p.magic, (test::Bytes{'P', 'L', 'A', 'I', 'N'}));
    EXPECT_EQ(p.magic_offset, 0u);
    EXPECT_EQ(p.alignment, 1u);
    EXPECT_FALSE(p.endian.has_value());
    EXPECT_TRUE(p.validator.empty());
}

TEST(SignatureToml, MalformedTomlFailsAndLeavesSetUntouched) {
    SignatureSet set;
    ASSERT_TRUE(set.load_toml("[[signature]]\nname='a'\nformat='f'\ncategory='other'\nmagic='AB'\n",
                              "first"));
    ASSERT_EQ(set.signatures.size(), 1u);
    const Status st = set.load_toml("[[signature]\nname = \"broken", "bad");
    EXPECT_FALSE(st);
    EXPECT_NE(st.error.find("bad"), std::string::npos);
    EXPECT_EQ(set.signatures.size(), 1u);
}

TEST(SignatureToml, MissingRequiredFields) {
    const char* cases[] = {
        "[[signature]]\nformat='f'\ncategory='other'\nmagic='AB'\n",  // no name
        "[[signature]]\nname='a'\ncategory='other'\nmagic='AB'\n",    // no format
        "[[signature]]\nname='a'\nformat='f'\nmagic='AB'\n",          // no category
        "[[signature]]\nname='a'\nformat='f'\ncategory='other'\n",    // no magic
        "[[signature]]\nname='a'\nformat='f'\ncategory='other'\nmagic='AB'\nhex='4142'\n",  // both
        "[[signature]]\nname='a'\nformat='f'\ncategory='other'\nhex='ABC'\n",  // odd hex
        "[[signature]]\nname='a'\nformat='f'\ncategory='other'\nhex='zz'\n",   // bad hex
        "[[signature]]\nname='a'\nformat='f'\ncategory='other'\nmagic='A'\n",  // 1 byte
        "[[signature]]\nname='a'\nformat='f'\ncategory='nope'\nmagic='AB'\n",  // bad category
        "[[signature]]\nname='a'\nformat='f'\ncategory='other'\nmagic='AB'\nendian='middle'\n",
        "[[signature]]\nname='a'\nformat='f'\ncategory='other'\nmagic='AB'\nmagic_offset=-1\n",
        "[[signature]]\nname='a'\nformat='f'\ncategory='other'\nmagic='AB'\nreferences='x'\n",
        "[[signature]]\nname='a'\nformat='f'\ncategory='other'\nmagic='AB'\nweird=[1,2]\n",
        "[[signature]]\nname=''\nformat='f'\ncategory='other'\nmagic='AB'\n",
        "[[signature]]\nname=1\nformat='f'\ncategory='other'\nmagic='AB'\n",
        "signature = 3\n",
        "other = 1\n",
    };
    for (const char* text : cases) {
        SignatureSet set;
        const Status st = set.load_toml(text, "case");
        EXPECT_FALSE(st) << text;
        EXPECT_TRUE(set.signatures.empty()) << text;
        EXPECT_NE(st.error.find("case"), std::string::npos) << st.error;
    }
}

TEST(SignatureToml, DuplicateNamesRejectedAcrossLoads) {
    SignatureSet set;
    ASSERT_TRUE(
        set.load_toml("[[signature]]\nname='a'\nformat='f'\ncategory='other'\nmagic='AB'\n", "1"));
    const Status st = set.load_toml(
        "[[signature]]\nname='b'\nformat='f'\ncategory='other'\nmagic='CD'\n"
        "[[signature]]\nname='a'\nformat='f'\ncategory='other'\nmagic='EF'\n",
        "2");
    EXPECT_FALSE(st);
    EXPECT_NE(st.error.find("duplicate"), std::string::npos);
    EXPECT_EQ(set.signatures.size(), 1u);  // all-or-nothing
}

TEST(SignatureToml, LoadFile) {
    SignatureSet set;
    EXPECT_FALSE(set.load_file("/nonexistent/omnitrace/sigs.toml"));
    const std::string core = std::string(OMNITRACE_SOURCE_DIR) + "/signatures/core.toml";
    ASSERT_TRUE(std::filesystem::exists(core));
    const Status st = set.load_file(core);
    ASSERT_TRUE(st) << st.error;
    EXPECT_FALSE(set.signatures.empty());
}

TEST(SignatureToml, BuiltinMatchesSourceFilesAndNamesRegisteredValidators) {
    const SignatureSet& b = SignatureSet::builtin();
    SignatureSet from_files;
    for (const auto& entry :
         std::filesystem::directory_iterator(std::string(OMNITRACE_SOURCE_DIR) + "/signatures")) {
        if (entry.path().extension() == ".toml") {
            ASSERT_TRUE(from_files.load_file(entry.path().string()));
        }
    }
    EXPECT_EQ(b.signatures.size(), from_files.signatures.size());
    std::vector<std::string> expect{"squashfs-le",
                                    "squashfs-be",
                                    "jffs2-le",
                                    "jffs2-be",
                                    "ubi",
                                    "ext",
                                    "mbr",
                                    "gpt",
                                    "uimage",
                                    "gzip",
                                    "xz",
                                    "lz4-frame",
                                    "zstd",
                                    "android-sparse",
                                    "cpio-newc",
                                    "tar-ustar",
                                    "zip",
                                    "7z",
                                    "cramfs-le",
                                    "romfs",
                                    "qnx6-le",
                                    "qnx-ifs",
                                    "fit-dtb",
                                    "elf",
                                    "pem-certificate",
                                    "openssh-private-key"};
    for (const std::string& name : expect) {
        bool found = false;
        for (const Signature& s : b.signatures) found = found || s.name == name;
        EXPECT_TRUE(found) << name;
    }
    const auto names = ValidatorRegistry::instance().names();
    for (const Signature& s : b.signatures) {
        if (s.validator.empty()) continue;
        EXPECT_NE(ValidatorRegistry::instance().find(s.validator), nullptr)
            << s.name << " -> " << s.validator;
    }
    EXPECT_TRUE(std::is_sorted(names.begin(), names.end()));
    EXPECT_GE(names.size(), 12u);
    const Signature* tar = nullptr;
    for (const Signature& s : b.signatures)
        if (s.name == "tar-ustar") tar = &s;
    ASSERT_NE(tar, nullptr);
    EXPECT_EQ(tar->magic_offset, 257u);
    const Signature* qnx = nullptr;
    for (const Signature& s : b.signatures)
        if (s.name == "qnx6-le") qnx = &s;
    ASSERT_NE(qnx, nullptr);
    EXPECT_EQ(qnx->magic_offset, 0x2000u);
    EXPECT_EQ(qnx->magic, (test::Bytes{0x22, 0x11, 0x19, 0x68}));
}
