// docs_check_test.cpp — runs scripts/check_docs.py so `ctest` fails when the
// documentation drifts from the code (generated reference stale, a validator
// without its docs/formats page, a CLI flag missing from docs/CLI.md, a dead
// Markdown link). The script is Python 3 stdlib only; when no python3 is on
// the PATH the test is skipped, not failed, so a build without Python still
// passes.
#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <string>

#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#endif

#ifndef OMNITRACE_SOURCE_DIR
#define OMNITRACE_SOURCE_DIR "."
#endif

namespace {

// Quote a path for the shell that std::system uses (cmd.exe or /bin/sh).
std::string quoted(const std::string& s) {
    return "\"" + s + "\"";
}

}  // namespace

TEST(Docs, CheckDocsScriptPasses) {
#ifdef _WIN32
    const char* devnull = " >NUL 2>&1";
#else
    const char* devnull = " >/dev/null 2>&1";
#endif
    if (std::system((std::string("python3 --version") + devnull).c_str()) != 0)
        GTEST_SKIP() << "python3 not on PATH; scripts/check_docs.py not run";
    const std::string script = std::string(OMNITRACE_SOURCE_DIR) + "/scripts/check_docs.py";
    // Capture stdout+stderr so a failing ctest names the missing YAML entry or
    // dead link instead of only reporting a non-zero exit code.
    const std::string cmd = "python3 " + quoted(script) + " 2>&1";
    std::string output;
    FILE* pipe = ::popen(cmd.c_str(), "r");
    ASSERT_NE(pipe, nullptr) << "could not start " << cmd;
    char buf[512];
    while (std::fgets(buf, sizeof buf, pipe) != nullptr) output += buf;
    const int rc = ::pclose(pipe);
    EXPECT_EQ(rc, 0) << "scripts/check_docs.py failed; run python3 scripts/gen_docs.py and fix the "
                        "items below:\n"
                     << output;
}
