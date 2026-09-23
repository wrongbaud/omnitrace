# artifacts layer. Sources: src/artifacts/**/*.cpp, tests: tests/unit/artifacts/**/*.cpp (globbed).
#
# core, output and OpenSSL only. An extractor parses a file into records; like
# the analyzers it knows nothing about discovery, Spans or how extraction
# works, so a finished case can be re-examined without re-extracting it.
omnitrace_module(artifacts DEPS omnitrace::core omnitrace::output OpenSSL::Crypto)
