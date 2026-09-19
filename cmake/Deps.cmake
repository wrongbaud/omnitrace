# Third-party dependencies. vcpkg (manifest mode) supplies these on CI and on
# Windows/macOS; on a Linux dev box system packages are used when present, and
# header-only libs fall back to FetchContent so a fresh clone still builds.
include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_package(LibLZMA REQUIRED)
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
find_package(spdlog CONFIG REQUIRED)

find_package(tomlplusplus CONFIG QUIET)
if(NOT TARGET tomlplusplus::tomlplusplus)
  FetchContent_Declare(tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG v3.4.0 GIT_SHALLOW TRUE)
  FetchContent_MakeAvailable(tomlplusplus)
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
