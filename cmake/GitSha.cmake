# GitSha.cmake — makes the commit that produced a binary available to it.
#
# A case directory records `run.git_sha`, and a report shows it as "Build".
# Until this existed both were empty, so a case could say which *version* made
# it but not which build -- and 0.1.0 has been a great many different builds.
# For a tool whose output is evidence that is the wrong gap to leave open.
#
# Captured at **build** time, not configure time. CMake re-runs configure when
# CMakeLists.txt changes, not when HEAD moves, so a configure-time sha goes
# stale the moment you commit and rebuild -- and a stale commit hash in a
# forensic record is worse than no commit hash. The script rewrites the header
# only when the value actually changes, so this costs one `git rev-parse` per
# build and no recompilation.
function(omnitrace_git_sha target)
  set(_dir "${CMAKE_BINARY_DIR}/generated")
  set(_hdr "${_dir}/omnitrace_gitsha.h")
  file(MAKE_DIRECTORY "${_dir}")
  # Write it once now so the first configure leaves a valid header behind.
  execute_process(COMMAND "${CMAKE_COMMAND}"
    "-DOUT=${_hdr}" "-DSRC=${PROJECT_SOURCE_DIR}" "-DOVERRIDE=${OMNITRACE_GIT_SHA}"
    -P "${PROJECT_SOURCE_DIR}/cmake/WriteGitSha.cmake")
  add_custom_target(omnitrace_gitsha_header
    BYPRODUCTS "${_hdr}"
    COMMAND "${CMAKE_COMMAND}"
      "-DOUT=${_hdr}" "-DSRC=${PROJECT_SOURCE_DIR}" "-DOVERRIDE=${OMNITRACE_GIT_SHA}"
      -P "${PROJECT_SOURCE_DIR}/cmake/WriteGitSha.cmake"
    COMMENT "Recording the commit this build came from"
    VERBATIM)
  add_dependencies(${target} omnitrace_gitsha_header)
  target_include_directories(${target} PRIVATE "${_dir}")
endfunction()
