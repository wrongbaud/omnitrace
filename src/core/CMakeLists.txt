# core layer. Sources: src/core/**/*.cpp, tests: tests/unit/core/**/*.cpp (globbed).
omnitrace_module(core DEPS ZLIB::ZLIB LibLZMA::LibLZMA BZip2::BZip2 lz4::lz4 zstd::zstd OpenSSL::Crypto Threads::Threads spdlog::spdlog)
