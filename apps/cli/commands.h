// commands.h — subcommand registration. Each layer exposes one
// register_<layer>_commands(CLI::App&) (docs/ARCHITECTURE.md); main.cpp only
// wires them together.
#pragma once
#include <string>
#include <vector>

#include <CLI/CLI.hpp>

// The process argv, recorded in RunInfo by commands that write a manifest.
void set_process_argv(std::vector<std::string> argv);

// `scan` and `analyze`. Both throw CLI::RuntimeError(1) on failure so
// CLI11_PARSE turns it into the exit code.
void register_analyze_commands(CLI::App& app);
