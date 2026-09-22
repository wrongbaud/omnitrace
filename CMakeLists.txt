cmake_minimum_required(VERSION 3.28)
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" OMNITRACE_VERSION_STRING)
project(omnitrace VERSION ${OMNITRACE_VERSION_STRING} LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)  # no C++20 modules; keeps clangd happy with GCC flags
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

option(OMNITRACE_BUILD_TESTS "Build unit tests" ON)
option(OMNITRACE_SANITIZE "Build with ASan+UBSan" OFF)
option(OMNITRACE_WERROR "Treat warnings as errors" OFF)
option(OMNITRACE_STATIC "Prefer static linking of the CLI" OFF)

include(Warnings)
include(Deps)

if(OMNITRACE_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=address,undefined)
endif()

# enable_testing() must precede add_subdirectory(): CTestTestfile.cmake is only
# generated for directories configured while testing is enabled.
if(OMNITRACE_BUILD_TESTS)
  enable_testing()
  include(GoogleTest)
endif()

# One static library per layer. Each subdirectory globs its own sources and
# its own tests so that parallel contributors never edit a shared CMake file.
add_subdirectory(src/core)
add_subdirectory(src/output)
add_subdirectory(src/discovery)
add_subdirectory(src/containers)
add_subdirectory(src/images)
add_subdirectory(src/filesystems)
add_subdirectory(src/analyzers)
add_subdirectory(src/rules)
add_subdirectory(apps/cli)
