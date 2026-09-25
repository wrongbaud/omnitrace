# Third-party dependencies. vcpkg (manifest mode) supplies these on CI and on
# Windows/macOS; on a Linux dev box system packages are used when present, and
# header-only libs fall back to FetchContent so a fresh clone still builds.
include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_package(LibLZMA REQUIRED)
# CMake ships FindBZip2; vcpkg exports the same BZip2::BZip2 target.
find_package(BZip2 REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# lz4 / zstd: vcpkg exports CMake configs; distros usually only ship pkg-config.
find_package(lz4 CONFIG QUIET)
if(NOT TARGET lz4::lz4)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(LZ4 REQUIRED IMPORTED_TARGET liblz4)
  add_library(lz4::lz4 ALIAS PkgConfig::LZ4)
endif()
find_package(zstd CONFIG QUIET)
if(TARGET zstd::libzstd_static)
  add_library(zstd::zstd ALIAS zstd::libzstd_static)
elseif(TARGET zstd::libzstd_shared)
  add_library(zstd::zstd ALIAS zstd::libzstd_shared)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(ZSTD REQUIRED IMPORTED_TARGET libzstd)
  add_library(zstd::zstd ALIAS PkgConfig::ZSTD)
endif()

find_package(yaml-cpp CONFIG REQUIRED)
if(NOT TARGET yaml-cpp::yaml-cpp)
  add_library(yaml-cpp::yaml-cpp ALIAS yaml-cpp)
endif()
find_package(nlohmann_json CONFIG REQUIRED)
find_package(CLI11 CONFIG REQUIRED)
# Resolve fmt before spdlog's own find_dependency(fmt), and prefer a modern
# one: a distro may ship a legacy fmt9 compat package whose config dir also
# matches the fmt* glob, and linking a fmt-9 ABI against a spdlog built on
# fmt 12 fails at link time.
#
# The preference cannot be a hard floor, though. Nothing here uses fmt
# directly -- it is spdlog's dependency, and what actually has to hold is that
# this fmt is the one spdlog was built against, not that it is any particular
# version. Ubuntu 24.04 pairs spdlog 1.12 with fmt 9.1.0 and ships no fmt 10,
# so a `find_package(fmt 10 REQUIRED)` rejects a perfectly coherent pairing
# and fails the configure outright. So: take >= 10 where it exists, and
# otherwise take what the distro paired with its spdlog.
find_package(fmt 10 CONFIG QUIET)
if(NOT TARGET fmt::fmt)
  find_package(fmt CONFIG REQUIRED)
endif()
message(STATUS "fmt: ${fmt_VERSION}")
find_package(spdlog CONFIG REQUIRED)

find_package(tomlplusplus CONFIG QUIET)
if(NOT TARGET tomlplusplus::tomlplusplus)
  FetchContent_Declare(tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG v3.4.0 GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(tomlplusplus)
endif()

# RE2 for the rules engine. A user-supplied pattern must not be able to hang
# the tool, which rules out std::regex's backtracking; RE2 is linear in the
# input and matches a whole set in one pass. Modern RE2 needs Abseil, so the
# FetchContent fallback pulls both -- a slow first configure on a box with
# neither vcpkg nor a system re2, but every other path is cheap.
find_package(re2 CONFIG QUIET)
if(NOT TARGET re2::re2)
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(RE2 QUIET IMPORTED_TARGET re2)
  endif()
  if(TARGET PkgConfig::RE2)
    add_library(re2::re2 ALIAS PkgConfig::RE2)
  else()
    set(ABSL_PROPAGATE_CXX_STD ON CACHE BOOL "" FORCE)
    # RE2 exports a target that references Abseil, so Abseil has to be in an
    # export set too or the generate step fails.
    set(ABSL_ENABLE_INSTALL ON CACHE BOOL "" FORCE)
    set(RE2_BUILD_TESTING OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(abseil
      GIT_REPOSITORY https://github.com/abseil/abseil-cpp.git
      GIT_TAG 20240722.0 GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(abseil)
    FetchContent_Declare(re2
      GIT_REPOSITORY https://github.com/google/re2.git
      GIT_TAG 2024-07-02 GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(re2)
  endif()
endif()

if(OMNITRACE_BUILD_TESTS)
  find_package(GTest CONFIG QUIET)
  if(NOT TARGET GTest::gtest)
    FetchContent_Declare(googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG v1.15.2 GIT_SHALLOW TRUE)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
  endif()
endif()
