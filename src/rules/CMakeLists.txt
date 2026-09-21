# rules layer. Sources: src/rules/**/*.cpp, tests: tests/unit/rules/**/*.cpp (globbed).
omnitrace_module(rules DEPS omnitrace::core omnitrace::discovery omnitrace::output yaml-cpp::yaml-cpp re2::re2)

# Embed rules/*.yaml into the library so RulePack::builtin() needs no runtime
# files, the same way the discovery layer embeds signatures/*.toml.
file(GLOB _omnitrace_rule_files CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/rules/*.yaml")
list(SORT _omnitrace_rule_files)
set(_omnitrace_rule_gen "${CMAKE_CURRENT_BINARY_DIR}/generated/builtin_rules.cpp")
add_custom_command(
  OUTPUT "${_omnitrace_rule_gen}"
  COMMAND "${CMAKE_COMMAND}"
          "-DOUTPUT=${_omnitrace_rule_gen}"
          "-DINPUTS=${_omnitrace_rule_files}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_rules.cmake"
  DEPENDS ${_omnitrace_rule_files} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_rules.cmake"
  COMMENT "Embedding rules/*.yaml into builtin_rules.cpp"
  VERBATIM)
target_sources(omnitrace_rules PRIVATE "${_omnitrace_rule_gen}")
