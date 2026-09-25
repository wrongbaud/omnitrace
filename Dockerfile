# OmniTrace — offline embedded-systems forensic analysis.
#
# Two stages: a builder that compiles against vcpkg's pinned dependencies, and
# a distroless runtime that holds the binary and nothing else. vcpkg's
# x64-linux triplet is static, so the only thing the CLI needs at runtime is
# glibc -- no OpenSSL, no yaml-cpp, no version skew with whatever the host
# happens to ship.
#
# Build:
#   docker build --build-arg GIT_SHA=$(git rev-parse --short=12 HEAD) -t omnitrace .
#
# Run (evidence read-only, case directory writable, files owned by you):
#   docker run --rm -u $(id -u):$(id -g) \
#     -v /path/to/evidence:/data:ro -v /path/to/cases:/out \
#     omnitrace analyze /data/image.bin --out /out/case-name
#
# `/out` must be a bind mount: a case is tens of gigabytes -- 34 GB for a
# 15.7 GB QNX eMMC with the 32 GiB carve ceiling, and roughly double that with
# --tar-filesystems -- and the container's own writable layer is the wrong
# place for it.

# vcpkg release 2026.07.29, the baseline vcpkg.json pins.
ARG VCPKG_REF=9e593bb18ea69cc5095e012465dcd675a822ed0d

# ---------------------------------------------------------------- builder
# Trixie for GCC 14: std::chrono::clock_cast (analyze_commands.cpp) is
# absent from bookworm's GCC 12. The runtime below is the matching
# Debian release, so the binary runs on the glibc it was built against.
FROM debian:trixie-slim AS build

# The filesystem tools are the same set the Linux CI job installs: the unit
# tests build real squashfs/ext/jffs2/ubifs/vfat images with them, so without
# them the ctest below would pass while testing much less. python3 is needed
# twice over -- vcpkg builds meson with it, and the docs gate runs under it.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ninja-build git pkg-config python3 \
      curl zip unzip tar ca-certificates linux-libc-dev \
      squashfs-tools e2fsprogs dosfstools mtd-utils \
    && rm -rf /var/lib/apt/lists/*

# CMake comes from Kitware, not apt. vcpkg's SPDX generation calls
# string(JSON ... STRING_ENCODE ...), which trixie's 3.31.6 does not have --
# it fails on the first port, bzip2. Pinned by version and verified by
# digest, so the toolchain is part of what the build can be held to.
ARG CMAKE_VERSION=4.4.3
ARG CMAKE_SHA256=d6c83076c575bc00b823522ac974bda66d0af05d6ddc30e739c12385cf32c6cc
RUN curl -fsSLo /tmp/cmake.tar.gz \
      "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz" \
    && echo "${CMAKE_SHA256}  /tmp/cmake.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/cmake.tar.gz --strip-components=1 -C /usr/local \
    && rm /tmp/cmake.tar.gz \
    && cmake --version

# vcpkg at the baseline vcpkg.json pins, so a container build resolves exactly
# what the Windows and macOS CI jobs resolve.
ARG VCPKG_REF
ENV VCPKG_ROOT=/opt/vcpkg
RUN mkdir -p "$VCPKG_ROOT" \
    && git -C "$VCPKG_ROOT" init --quiet \
    && git -C "$VCPKG_ROOT" remote add origin https://github.com/microsoft/vcpkg \
    && git -C "$VCPKG_ROOT" fetch --quiet --depth 1 origin "$VCPKG_REF" \
    && git -C "$VCPKG_ROOT" checkout --quiet FETCH_HEAD \
    && "$VCPKG_ROOT"/bootstrap-vcpkg.sh -disableMetrics

WORKDIR /src
# The manifest first, so a source-only change does not rebuild every port.
COPY vcpkg.json ./
RUN "$VCPKG_ROOT"/vcpkg install --triplet x64-linux --x-manifest-root=/src \
      --x-install-root=/src/vcpkg_installed

# /out is where the case lands. Created here and carried over with an owner,
# because the runtime has no shell to mkdir with and a root-owned /out would
# be unwritable to the default non-root user.
RUN mkdir -p /out

COPY . .

# There is no .git in the build context (.dockerignore), so the commit is
# passed in. Without it a case made by this image records an empty git_sha,
# which is exactly the provenance a released container should carry.
ARG GIT_SHA=""
RUN cmake --preset linux-vcpkg -DOMNITRACE_STATIC=ON -DOMNITRACE_GIT_SHA="$GIT_SHA" \
    && cmake --build --preset linux-vcpkg --parallel

# An image that builds but produces a broken case is worse than no image.
RUN ctest --preset linux-vcpkg --output-on-failure

# ---------------------------------------------------------------- runtime
FROM gcr.io/distroless/cc-debian13 AS runtime

ARG GIT_SHA=""
LABEL org.opencontainers.image.title="omnitrace" \
      org.opencontainers.image.description="Offline forensic analysis of embedded systems flash images" \
      org.opencontainers.image.source="https://github.com/wrongbaud/omnitrace" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /src/build/linux-vcpkg/apps/cli/omnitrace /usr/local/bin/omnitrace
COPY --from=build --chown=nonroot:nonroot /out /out

# Non-root by default; `--user $(id -u):$(id -g)` overrides it so the case
# directory comes out owned by the examiner rather than by root. Nothing in
# the tool resolves the running user -- no getpwuid, no $HOME -- so a uid with
# no passwd entry inside the container is fine.
USER nonroot:nonroot
WORKDIR /out
ENTRYPOINT ["/usr/local/bin/omnitrace"]
CMD ["--help"]
