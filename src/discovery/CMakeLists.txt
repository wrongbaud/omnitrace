# discovery layer. Sources: src/discovery/**/*.cpp, tests: tests/unit/discovery/**/*.cpp (globbed).
omnitrace_module(discovery DEPS omnitrace::core tomlplusplus::tomlplusplus)
