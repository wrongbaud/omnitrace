# Running OmniTrace in a container

OmniTrace is an offline tool with a lot of decompressors behind it. The
container exists so an examiner can run a *named, hashed* build against
evidence without installing any of them, and so a case can record exactly
which build produced it.

The image is published on a version tag:

```sh
docker pull ghcr.io/wrongbaud/omnitrace:0.2.0
```

## Quick start

```sh
docker run --rm -u "$(id -u):$(id -g)" \
  -v /evidence:/data:ro \
  -v /cases:/out \
  ghcr.io/wrongbaud/omnitrace:0.2.0 \
  analyze /data/router.bin --out /out/case-router --tar-filesystems
```

`ENTRYPOINT` is `omnitrace`, so everything after the image name is the command
line documented in [CLI.md](CLI.md) — `analyze`, `scan`, `hash`, `report`,
`diff`. With no arguments it prints `--help`.

## The two mounts

| Mount | Mode | Holds |
|---|---|---|
| `/data` | `:ro` | the evidence |
| `/out` | read-write | the case directory |

**Mount the evidence read-only.** OmniTrace never writes to an image, but
`:ro` is what makes that a property of the run rather than a promise about the
code: an examiner can state that the container could not have altered the
evidence. The [smoke test](../scripts/smoke_container.sh) asserts the image's
hash is unchanged after a run, for the same reason.

**`/out` must be a bind mount, not the container's own layer.** A case is
routinely larger than the evidence: partitions are carved by default up to
32 GiB each, and `--tar-filesystems` writes a second faithful copy of every
extracted tree. A 15.7 GB QNX eMMC produces roughly 34 GB of case. Writing
that into a container's writable layer fills the Docker storage pool rather
than the disk you chose.

Sizing matters in one more way: `analyze` holds back 5% of the free space on
**the filesystem holding `--out`** and refuses to fill it
(`analyze-limit-disk`, `carve-limit-disk`). Inside a container that
measurement is of whatever `/out` is bound to, which is what you want — but
only if it *is* bound. An unmounted `/out` measures the Docker pool.

## Ownership

`-u "$(id -u):$(id -g)"` makes the case come out owned by the examiner. The
uid needs no entry in the container's `/etc/passwd`: nothing in OmniTrace
resolves the running user — no `getpwuid`, no `$HOME` — so an arbitrary uid
works. Without `-u`, the default is the image's unprivileged `nonroot` user
and the files land owned by uid 65532, which is usually not what you want on
the host.

## Provenance

The image is built with `--build-arg GIT_SHA=<commit>`, and that commit is
what `omnitrace --version` prints and what every case records as `git_sha` in
`INFO.yaml` ([CASE_LAYOUT.md](CASE_LAYOUT.md)). It is also an OCI label:

```sh
docker inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
  ghcr.io/wrongbaud/omnitrace:0.2.0
```

For work that has to be repeatable, pin the digest rather than the tag —
`ghcr.io/wrongbaud/omnitrace@sha256:...` — because a tag can be moved and a
digest cannot.

## What is in the image

A single 17 MB statically-linked-where-it-matters binary on
`gcr.io/distroless/cc`, about 68 MB in total. libstdc++ and libgcc are linked
in (`OMNITRACE_STATIC=ON`) and every dependency — zlib, liblzma, bzip2, lz4,
zstd, OpenSSL, yaml-cpp, spdlog, RE2 — comes from vcpkg as a static library,
so the binary needs only `libc` and `libm`.

There is **no shell, no package manager and no Python** in the runtime image.
That is deliberate, and it means `docker exec ... sh` will not work. To look
around, mount the case directory and inspect it from the host, or run the
builder stage instead:

```sh
docker build --target build -t omnitrace:build .
docker run --rm -it omnitrace:build bash
```

## Building it yourself

```sh
docker build --build-arg GIT_SHA="$(git rev-parse --short=12 HEAD)" -t omnitrace .
scripts/smoke_container.sh omnitrace "$(git rev-parse --short=12 HEAD)"
```

The build takes about four minutes cold, most of it vcpkg compiling OpenSSL
and Abseil. The builder stage runs the full `ctest` suite, so a build that
completes has passed the same tests CI runs — and `scripts/smoke_container.sh`
then runs the finished image against `tests/fixtures/out/gpt.img` and checks
that partitions were carved, filesystems read, files extracted, the report
rendered and the evidence left untouched. Building is not what is worth
testing; a container that compiles and writes an empty case directory is worse
than no container, because the case looks like evidence.

`.dockerignore` keeps `corpus/` out of the build context. It must stay there:
the corpus is real device images, it is git-ignored so it never leaves the
machine, and a build context sweeps up everything it is not told to skip.

The container build is verified against the host build, not just against
itself: on `corpus/router-example`, both produce the same 2,755 extracted
files with the same 2,399 distinct contents, and their `INFO.yaml` files are
identical across all 116,354 lines once paths, timestamps and the build sha
are normalised.

## Publishing a release

Pushing a `v*` tag runs `.github/workflows/release.yml`, which builds the
image, smoke-tests it, and only then pushes to GHCR:

```sh
git tag -a v0.2.0 -m "..." && git push origin v0.2.0
```

`v0.2.0` publishes `0.2.0`, `0.2` and `latest`; a prerelease tag gets no
`latest`. The workflow can also be run manually from the Actions tab, which
builds and smoke-tests without publishing anything.

## Notes

- **amd64 only.** An arm64 image would have to cross-compile or run vcpkg
  under emulation, and building OpenSSL and Abseil under QEMU is slow enough
  that it needs a native runner to be worth doing.
- The builder pins its toolchain: a vcpkg release commit, and CMake fetched
  from Kitware by version *and* SHA-256. Neither pin is decoration. Debian
  bookworm's GCC 12 has no `std::chrono::clock_cast`, so the builder is trixie
  (GCC 14) and the runtime is the matching `cc-debian13` — build and runtime
  must share a Debian release or the binary is linked against a newer glibc
  than it runs on. And trixie's own CMake 3.31.6 cannot build a single vcpkg
  port: the SPDX code calls `string(JSON ... STRING_ENCODE ...)`, which that
  version does not have.
