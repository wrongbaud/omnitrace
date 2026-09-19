// omnitrace CLI. Subcommands are added by the modules they belong to; this file
// only wires CLI11 and logging. Keep it small.
#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>

#include <cstdio>
#include <string>

#include "omnitrace/core/Hash.h"

#ifndef OMNITRACE_VERSION
#define OMNITRACE_VERSION "0.0.0"
#endif

namespace {

int cmd_hash(const std::string& path) {
    omnitrace::Digests d;
    auto st = omnitrace::hash_file(path, d);
    if (!st) {
        spdlog::error("{}", st.error);
        return 1;
    }
    std::printf("path: %s\nsize: %llu\nmd5: %s\nsha1: %s\nsha256: %s\n", path.c_str(),
                static_cast<unsigned long long>(d.bytes), d.md5.c_str(), d.sha1.c_str(), d.sha256.c_str());
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    CLI::App app{"OmniTrace: embedded systems forensic analysis"};
    app.set_version_flag("--version", OMNITRACE_VERSION);
    bool verbose = false;
    app.add_flag("-v,--verbose", verbose, "Debug logging");

    std::string hash_path;
    auto* hash = app.add_subcommand("hash", "Hash an evidence file (MD5/SHA-1/SHA-256)");
    hash->add_option("file", hash_path, "Path to image")->required();

    // Registered by later modules: scan, analyze, report. See docs/ARCHITECTURE.md.

    CLI11_PARSE(app, argc, argv);
    spdlog::set_level(verbose ? spdlog::level::debug : spdlog::level::info);
    spdlog::set_pattern("[%^%l%$] %v");

    if (*hash) return cmd_hash(hash_path);
    std::puts(app.help().c_str());
    return 0;
}
