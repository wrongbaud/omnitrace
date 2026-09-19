# discovery layer. Sources: src/discovery/**/*.cpp, tests: tests/unit/discovery/**/*.cpp (globbed).
omnitrace_module(discovery DEPS omnitrace::core tomlplusplus::tomlplusplus)

# Embed signatures/*.toml into the library so SignatureSet::builtin() needs no
# runtime files. cmake/embed_signatures.cmake turns each file into a byte array
# in one generated translation unit; it re-runs when a .toml is added or edited.
file(GLOB _omnitrace_sig_files CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/signatures/*.toml")
list(SORT _omnitrace_sig_files)
set(_omnitrace_sig_gen "${CMAKE_CURRENT_BINARY_DIR}/generated/builtin_signatures.cpp")
add_custom_command(
  OUTPUT "${_omnitrace_sig_gen}"
  COMMAND "${CMAKE_COMMAND}"
          "-DOUTPUT=${_omnitrace_sig_gen}"
          "-DINPUTS=${_omnitrace_sig_files}"
          -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_signatures.cmake"
  DEPENDS ${_omnitrace_sig_files} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed_signatures.cmake"
  COMMENT "Embedding signatures/*.toml into builtin_signatures.cpp"
  VERBATIM)
target_sources(omnitrace_discovery PRIVATE "${_omnitrace_sig_gen}")
