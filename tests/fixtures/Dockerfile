# Fixture toolchain for tests/fixtures/generate.py.
#
# Every mkfs-style tool the synthetic image builder needs, pinned to Debian
# bookworm packages, plus yaffs2utils (mkyaffs2 / unyaffs2, GPL-2.0, built from
# source at a pinned commit; it is only *executed* here, never linked into
# OmniTrace). Build and run through tests/fixtures/build.sh.
#
#   docker build -t omnitrace-fixtures tests/fixtures
#   docker run --rm -v "$PWD/tests/fixtures/out:/out" omnitrace-fixtures --out /out
FROM debian:bookworm AS yaffs2utils
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git build-essential \
    && rm -rf /var/lib/apt/lists/*
# yaffs2utils: the code.google.com/p/yaffs2utils project (Luen-Yung Lin) as
# exported to GitHub. The mirrors are byte-identical exports; this one is pinned
# by commit so the build is reproducible.
ARG YAFFS2UTILS_REPO=https://github.com/dorigom/yaffs2utils.git
ARG YAFFS2UTILS_COMMIT=1edc1688b7f8db140d2b85448dd68f9e6318dc95
WORKDIR /src/yaffs2utils
RUN git clone "${YAFFS2UTILS_REPO}" . \
    && git checkout "${YAFFS2UTILS_COMMIT}" \
    && make CFLAGS="-I. -I./yaffs2 -O2 -D_HAVE_MMAP -Wno-error" \
    && install -m 0755 mkyaffs2 /usr/local/bin/mkyaffs2 \
    && install -m 0755 unyaffs2 /usr/local/bin/unyaffs2 \
    && ln -s /usr/local/bin/mkyaffs2 /usr/local/bin/mkyaffs2image \
    && /usr/local/bin/mkyaffs2 -h 2>&1 | head -3

FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      squashfs-tools \
      mtd-utils \
      e2fsprogs \
      dosfstools \
      mtools \
      python3 \
      python3-yaml \
      xz-utils \
    && rm -rf /var/lib/apt/lists/*
COPY --from=yaffs2utils /usr/local/bin/mkyaffs2 /usr/local/bin/unyaffs2 /usr/local/bin/
RUN ln -s /usr/local/bin/mkyaffs2 /usr/local/bin/mkyaffs2image
COPY generate.py /fixtures/generate.py
# Fixed, timezone-free environment so every tool that stamps time agrees.
ENV TZ=UTC \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    SOURCE_DATE_EPOCH=1700000000 \
    E2FSPROGS_FAKE_TIME=1700000000 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /work
ENTRYPOINT ["python3", "/fixtures/generate.py"]
CMD ["--out", "/out"]
