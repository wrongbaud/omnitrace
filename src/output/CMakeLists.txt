# output layer. Sources: src/output/**/*.cpp, tests: tests/unit/output/**/*.cpp (globbed).
omnitrace_module(output DEPS omnitrace::core yaml-cpp::yaml-cpp nlohmann_json::nlohmann_json)
