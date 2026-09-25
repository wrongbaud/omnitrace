file(GLOB_RECURSE _cli_srcs CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
add_executable(omnitrace ${_cli_srcs})
target_link_libraries(omnitrace PRIVATE
  omnitrace::core omnitrace::output omnitrace::discovery omnitrace::containers
  omnitrace::images omnitrace::filesystems omnitrace::analyzers omnitrace::artifacts omnitrace::report omnitrace::rules omnitrace::diff CLI11::CLI11 spdlog::spdlog
  omnitrace_warnings)
target_compile_definitions(omnitrace PRIVATE OMNITRACE_VERSION="${PROJECT_VERSION}")
omnitrace_git_sha(omnitrace)
if(OMNITRACE_STATIC AND NOT MSVC AND NOT APPLE)
  target_link_options(omnitrace PRIVATE -static-libstdc++ -static-libgcc)
endif()
install(TARGETS omnitrace RUNTIME DESTINATION bin)
