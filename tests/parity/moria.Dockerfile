# moria (MIT, https://github.com/nmatt0/moria) built from source at a pinned
# commit for the parity harness (tests/parity/run.py). moria is a comparison
# baseline only: OmniTrace never links, vendors or depends on it.
#
#   docker build -f tests/parity/moria.Dockerfile -t omnitrace-parity-moria tests/parity
#   docker run --rm -v /path/to/images:/data:ro -v /path/to/out:/out omnitrace-parity-moria -j -e -C /out /data/img.bin
ARG MORIA_COMMIT=30e4038
FROM debian:bookworm AS build
ARG MORIA_COMMIT
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git cmake ninja-build g++ \
      zlib1g-dev liblzma-dev liblz4-dev libzstd-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone https://github.com/nmatt0/moria.git . \
    && git checkout "${MORIA_COMMIT}" \
    && git rev-parse HEAD > /moria-commit.txt
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build -j"$(nproc)" \
    && ./build/moria --version

FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      zlib1g liblzma5 liblz4-1 libzstd1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/moria /usr/local/bin/moria
COPY --from=build /moria-commit.txt /moria-commit.txt
WORKDIR /out
ENTRYPOINT ["/usr/local/bin/moria"]
