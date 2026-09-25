# Resuming work on OmniTrace

For whoever — person or agent — picks this up cold. `ARCHITECTURE.md` says what
the code must do; this says how to work on it without losing a day to something
that has already cost one.

## Read these first, in this order

| # | Document | Why this one, now |
|---|---|---|
| 1 | `CLAUDE.md`, the "Project state" section | The densest thing in the repo. Every bullet is a lesson that cost something; it is maintained, so it is current. |
| 2 | `docs/ARCHITECTURE.md` | Fifteen rules. They are the contract, not advice. |
| 3 | `docs/CODE_TOUR.md` | How a byte gets from `MappedFile` to `INFO.yaml`. |
| 4 | `docs/ROADMAP.md`, "Next, in order" | What to do, and what has been deliberately *not* scheduled. |
| 5 | `docs/EXTENDING.md` | Only when you know which kind of thing you are adding. |

Do not start by reading the source. The layering is not obvious from the files,
and `CODE_TOUR.md` is an hour that saves several.

## The loop

```sh
cmake --preset linux-gcc && cmake --build --preset linux-gcc --parallel
ctest --preset linux-gcc
```

Before committing, in **this order** — it is not interchangeable:

```sh
git diff --name-only | grep -E '\.(cpp|h)$' | xargs clang-format -i
python3 scripts/gen_docs.py      # regenerates docs/reference/ from the source
python3 scripts/check_docs.py    # fails the build if they disagree
```

`gen_docs.py` records the **file and line** of every diagnostic code and attrs
key. Formatting moves lines. Run it before formatting and `check_docs` fails on
a diff you just created; a `Docs.CheckDocsScriptPasses` failure with no obvious
cause is almost always this.

Then the other two toolchains, both of which must be green:

```sh
cmake --build --preset linux-clang --parallel && ctest --preset linux-clang
cmake --build --preset linux-asan  --parallel && ctest --preset linux-asan   # ~7 min
```

## What "done" means here

A change is finished when all of this is true:

- gcc, clang and **ASan** are green. ASan is not optional: this code reads
  attacker-controlled offsets, and it is the only thing that proves a bounds
  check works.
- `check_docs.py` passes, and any new diagnostic code has an entry in
  `docs/reference/diagnostics.yaml` with a *meaning* and an *action*.
- The new test **fails without the fix.** Verify that by reverting the fix and
  watching it fail. A test that passes either way is not a test.
- It was run against the corpus, not only against fixtures. A fixture proves
  the code does what you meant; the corpus proves you meant the right thing.
- The prose says what was *measured*, not what is expected to be true.

## Working against evidence

`corpus/` is a local, git-ignored evidence corpus. **Never commit an image** —
it has never happened and `.gitignore` line 21 is why. Check with
`git log --all --oneline -- 'corpus/*'` if you are ever unsure; it should be
empty.

Write cases to `/var/tmp`, never into `corpus/` and never onto the evidence
media. Watch free space: a QNX case is now ~34 GB with the 32 GiB carve ceiling,
and `--tar-filesystems` roughly doubles a case again. `analyze` will not fill the
disk it writes to, but it will stop short and say so, which wastes the run.

Typical runtimes on this hardware, for sanity-checking a slow run: router 6 s,
Router-nand 13 s, auto-ivi eMMC 107 s, auto-emmc 123 s, audio 147 s, QNX 15.7 GB 460 s.

## Traps that have already cost time

Each of these looked like a bug in the code and was not.

**Wall-clock time lies.** An analysis reported 43,317 seconds for work that
takes 107. The machine had suspended one second after it started. Before
believing a slow run, check `journalctl --since ... | grep -i suspend`, and
wrap long runs in `systemd-inhibit --what=sleep:idle`.

**A capped list reported as a total understates the finding.** Take totals
*before* truncating a list, and assert the property (`same + changed + only_a
== total`) rather than the numbers.

**A comparison that compares nothing passes.** Three separate times a corpus
comparison reported success with both sides empty. Make the check refuse to
report success when it found none of the thing under test.

**`$'...\x00...'` in bash truncates at the NUL.** A `grep -F` for a gzip header
written that way searched for three bytes, matched every gzip in the image, and
produced a confident, wrong conclusion. Use Python for byte-exact searches.

**`pkill -f <script>` matches your own shell**, whose command line contains that
string. It killed a heredoc mid-write and left a truncated file.

**A `while read` loop whose body touches stdin ends early and says it finished.**
A runner reported "all done" after 6 of 15 images. Read the list into an array
first, or redirect `< /dev/null` inside the loop.

**An edit script whose anchor no longer matches writes nothing.** After
clang-format reflows a line, a Python `assert old in s` fires — or worse,
`str.replace` silently does nothing if you skipped the assert, the build
succeeds, and you test the old code. Always assert the anchor, and check the
result rather than the exit status.

**A fixture that is not like real data fails in a way that looks like a code
bug.** All three of these happened while writing the kallsyms decoder: a token
table whose tokens were all one byte (real ones vary, and the uniform case is
ambiguous), a 64-bit kernel placed at a 32-bit address (the address check was
right to refuse it), and a blob dropped at an unaligned offset (real images are
word-aligned). When a fixture fails, ask whether the fixture is wrong before
changing the code.

## Decisions already made

Do not re-open these without a reason that is new:

| Decision | Where |
|---|---|
| No web UI until the core is released | `core-before-ui`; `ROADMAP.md` Phase 4 |
| moria is a design reference and parity baseline, never a dependency | `docs/MORIA_SPIKE.md` |
| Free-space carving inside a filesystem is **not scheduled** | `ROADMAP.md` "Next" §1, `DEVELOPMENT_PLAN.md` post-MVP |
| A report is a typed `Document`, never concatenated strings | `docs/REPORT.md` |
| Third-party dependencies only if they static-link | `CLAUDE.md`; `vcpkg.json` + `cmake/Deps.cmake` + `CONTRIBUTING.md` row |
| Entropy reports `random`, never "encrypted" | `docs/formats/entropy.md` |

## Where things are

```
include/omnitrace/<layer>/   public headers — the interfaces
src/<layer>/                 core, discovery, images, containers, filesystems,
                             output, analyzers, artifacts, rules, report, diff
apps/cli/                    the CLI; section building for reports lives here
tests/unit/<layer>/          one test file per thing, globbed by CMake
tests/parity/                run.py (one image), sweep.py (many) vs unblob/moria
tests/fixtures/generate.py   synthetic images + their expected.yaml
docs/reference/              generated — never hand-edit; run gen_docs.py
scripts/gen_docs.py          source → docs/reference/
scripts/check_docs.py        the gate
```

Per-layer CMake globs sources and tests, so **adding a file never needs a CMake
edit**. Adding a whole layer does: `src/<layer>/CMakeLists.txt` with
`omnitrace_module(<layer> DEPS ...)`, plus `add_subdirectory` in the root
`CMakeLists.txt` and the target in `apps/cli/CMakeLists.txt`.

## The container and releases

`docker build ... -t omnitrace .` plus `scripts/smoke_container.sh` is the
release path; pushing a `v*` tag runs `.github/workflows/release.yml`, which
builds, smoke-tests and then publishes to GHCR. [docs/DOCKER.md](DOCKER.md).

Two traps are already paid for. The vcpkg baseline in `vcpkg.json` was a
commit that **does not exist**, so the Windows and macOS CI jobs had never
actually run; and toml++'s `TOML_EXCEPTIONS 0` is a library-wide setting, so a
package-provided `libtomlplusplus.a` (built with exceptions on) leaves
`toml::v3::noex::parse` undefined. If the vcpkg path breaks again, check those
two before anything else.

## The sample reports

`~/omnitrace-reports/` holds a report per corpus image plus sample diffs, with
`gen_reports.sh` and `make_index.py` beside them. It is outside the repo because
it is derived from evidence. Regenerating it after a behaviour change is the
cheapest way to see that change against fifteen real devices at once — and it
is how the `lib/modules` bug was found, where a head unit was reported as
running kernel `tcc_nand_core.ko`.
