// omnitrace CLI. Subcommands are added by the modules they belong to; this file
// only wires CLI11 and logging. Keep it small.
#include <spdlog/spdlog.h>
#include <CLI/CLI.hpp>

#include <cstdio>
#include <string>
#include <vector>

#include "commands.h"
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
                static_cast<unsigned long long>(d.bytes), d.md5.c_str(), d.sha1.c_str(),
                d.sha256.c_str());
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%^%l%$] %v");
    set_process_argv(std::vector<std::string>(argv, argv + argc));

    CLI::App app{"OmniTrace: embedded systems forensic analysis"};
    app.set_version_flag("--version", OMNITRACE_VERSION);
    app.add_flag_callback(
        "-v,--verbose", [] { spdlog::set_level(spdlog::level::debug); }, "Debug logging");

    std::string hash_path;
    auto* hash = app.add_subcommand("hash", "Hash an evidence file (MD5/SHA-1/SHA-256)");
    hash->add_option("file", hash_path, "Path to image")->required();

    register_analyze_commands(app);  // scan, analyze
    // Later modules register here too (report, ...). See docs/ARCHITECTURE.md.

    CLI11_PARSE(app, argc, argv);

    if (*hash) return cmd_hash(hash_path);
    if (app.get_subcommands().empty()) std::puts(app.help().c_str());
    return 0;
}
