# Testing

Three test tiers, split by JUnit tag. Pick the narrowest one for the change you made.

The tests are in two projects. **ghistabs** (the root, `src/test/`) holds the stabs tests, and the
C++ tests that need a binary's stabs. **ghicpp** (`ghicpp/src/test/`) holds the C++ tests that run on
ghicpp alone. Both use the test fixtures of **ghidrakt** (`ghidrakt/src/testFixtures/`): the `must…`
assertions (`ghidrakt.test`), `CapturingSink` and `TestBinaries`.

A task named without a project path, like `./gradlew integrationTest`, runs in both projects. Give
`--tests` a project path, since a project whose tests the filter doesn't match can fail the run:
`./gradlew :ghicpp:integrationTest --tests 'ghicpp.score.*'`, or `:integrationTest --tests …` for ghistabs.

| Task                        | What runs                                                                                            | Speed    | When                                                           |
| --------------------------- | ---------------------------------------------------------------------------------------------------- | -------- | -------------------------------------------------------------- |
| `./gradlew test`            | Unit tests — pure logic, synthetic inputs (no Ghidra headless boot). Excludes `integration`/`probe`. | seconds  | every change                                                   |
| `./gradlew integrationTest` | `@Tag("integration")` — real-fixture assertion suite + synthetic-program behavioural tests.          | ~minutes | before pushing; after touching the import/materialize pipeline |
| `./gradlew probes`          | `@Tag("probe")` — diagnostic generators (no pass/fail). Writes dumps under `build/test-output/`.     | ~minutes | on demand, when investigating                                  |

Plus one guard task outside the tiers: **`./gradlew noSerializationTest`** re-runs one real-fixture
import with `kotlinx-serialization-json` off the classpath, since main declares it `compileOnly` and the
extension ships without it. Run it after touching dependencies, or after adding a `@Serializable` /
`Json` use anywhere under `src/main/` — if the analyzer path ever reaches for the JSON format, this is
what turns a GUI-only `NoClassDefFoundError` into a build failure. Dumps live in the `cli` source set
(`ghistabs.cli.Dumps`) for the same reason; tests get them off the cli output.

All three print per-test PASS/FAIL/SKIP and a final summary line to the console of the same
command (no XML/HTML spelunking), and archive their report to a per-run timestamped dir
(`build/reports/tests/<task>/<stamp>/index.html`) so a later run never clobbers an earlier one.
`integrationTest`/`probes` always re-run (they never report `UP-TO-DATE`).

## Flags

Two axes, deliberately separate. **`-Pregression`** picks the *suite*; **`-Pfixture`** picks the
*binaries* a suite draws from. Neither implies the other.

- **`-Pregression[=<filename>[,…]]`** — run the fixture matrix and nothing else: one generated class
  per binary × mode (`StabsImportRegressionBase` subclasses, package `ghistabs.fixtures`). Bare, that
  is every binary on disk; with a comma-separated list of exact filenames, **extension included**,
  only those. Nothing but the matrix runs, so the behavioural and fixture-parameterised classes are
  skipped, and so is ghicpp's whole `integrationTest`.
  ```
  ./gradlew integrationTest -Pregression                                   # matrix, every fixture
  ./gradlew integrationTest -Pregression=xmltest_gcc345_fullstabs.exe      # matrix, one fixture
  ```
- **`-Pfixture=<filename>[,…]`** — the corpus `Fixtures` offers to the *other* suites: the
  fixture-parameterised probes, `AoutStabsIntegrationTest`, `StructReturnFixtureIntegrationTest`,
  `StringDedupIntegrationTest`, and `NoReturnFixtureIntegrationTest`, which needs it narrowed to
  exactly one binary to choose its subject. It selects no test class, so those suites keep running.
  A filter that selects nothing from a suite errors loudly.
  ```
  ./gradlew integrationTest -Pfixture=crypto_mi_test_gcc421.exe            # NoReturn picks this one
  ```
- **`-Pmode=<MODE>[,…]`**, `AFTER` by default, `all` for every mode. `AFTER` is the ordering a GUI
  re-import actually takes and what every assertion is written for; `CONCURRENT` and `BEFORE` exist to
  catch ordering effects and cost 3× between them. **`-Pmode=BEFORE` is the fast loop** — it skips
  Ghidra's auto-analysis entirely, so a fixture takes ~10s instead of 90-500s. Anything driven by
  `artifacts.harvest` / `artifacts.registry` / the DTM is valid there; only assertions reading
  auto-analysis output (applied frames and parameters, the demangler and its `/Demangler` stubs,
  `AlignmentDataType`, `StructReturnAnalyzer`'s conventions) need the other modes, and those
  `assumeTrue { mode != Mode.BEFORE }`.
  ```
  ./gradlew integrationTest -Pmode=BEFORE -Pregression=box2d_tests      # seconds, one fixture
  ./gradlew integrationTest -Pmode=all                                     # belt and braces, for CI
  ```
- **`-PregenerateBaselines=true`** — rewrite the baseline JSONs from observed counters instead of
  asserting against them (`countersWithinBaseline`). Review the diff.
- **`-PanalysisCache=auto|off|refresh`**, `auto` by default. In `AFTER` mode the matrix snapshots each
  fixture as auto-analysis left it, to `build/analysis-cache/<binary>.gzf`, and restores it next time
  instead of re-analyzing: the first run over a binary costs the usual 90-500s, every later one a
  second or two. Written and read automatically, never committed, and safe to delete. A snapshot also
  carries *our* non-stabs analyzers (`HullDisassemblyAnalyzer`, `NoReturnAnalyzer`, `MethodConventionAnalyzer`,
  `StructReturnAnalyzer`, `DeferredPopAnalyzer`, `FillerByteAnalyzer`), which run inside the same pass, and nothing keys it to
  the code that produced it — **a change to one of those is only seen under `-Pmode=CONCURRENT`, or after
  `-PanalysisCache=refresh`**, which re-analyzes and overwrites. `off` bypasses the cache in both
  directions. `-PanalysisCacheDir=<dir>` puts the databases somewhere `clean` does not reach.
  A restored fixture runs no analyzers, so it writes no `analysis-times/` entry; the one from the run
  that created the snapshot stays put, to compare the two paths against.

The mode axis subtracts where the suite axis selects: unwanted modes are *excluded* by class name, so
defaulting to `AFTER` cannot take the hand-written integration classes out of an ordinary run with
them. `-Pregression` *includes*, so it does exactly that on purpose.

`ktlint` runs separately: `./gradlew ktlintFormat` (autofix) / `ktlintCheck` (verify). Run before committing.

## Fixtures & baselines

- Binaries live in `src/test/resources/binaries/` — see its README for the corpus and how to add to
  it. `hello.cc` and its builds are ghicpp's, in `ghicpp/src/test/resources/binaries/features/`. Every
  project's tests read both in place through `TestBinaries` (Gradle passes the directories as
  `-DbinariesDir` and `-DhellosDir`), so never spell a path out in a test: `TestBinaries.file("features/hello_gcc421.exe")`
  finds a hello build wherever it is. Most are committed; anything absent (a binary that cannot be redistributed, dropped in locally)
  makes the tests using it *skip*, not fail.
- Baselines live in `src/test/resources/baselines/` (tracked), one per fixture; the baseline for a
  fixture that cannot be redistributed is gitignored alongside its binary, since it is derived from
  it. Same for `src/test/resources/corpus/` descriptor exports. Generated dumps go to
  `build/test-output/` so `./gradlew clean` regenerates them.
- The class scorecards' ground truth and baselines live in `ghicpp/src/test/resources/ghicpp/scorecard/`.
- **No assertion may be keyed to a fixture name.** A test gated on `binaryName == "foo.exe"`, or
  looking up a class only one binary declares, is dead the moment that binary is not on disk — and a
  whole tier of them was, silently, for every clone without the non-redistributable fixtures. Drive the
  assertion from the harvest instead (`artifacts.harvest` / `artifacts.registry`), assert over every
  instance of the shape, and `assumeTrue` on the shape being present at all. It costs nothing and the
  check then runs on 25 binaries rather than one.

## Where the tests live

**Every test — unit, integration, or probe — lives in the package of the code it tests**, not in a
dedicated folder. The `@Tag` (`integration`/`probe`, or none for unit), not the location, is what
decides which task runs it. So a class's unit test, integration test, and probe all sit together next
to the SUT — e.g. `ghistabs.importer` holds `DemanglerReplaceCoreTest` (unit) and
`DemanglerReplaceIntegrationTest` (integration) side by side.

A test sits in ghicpp when it needs nothing of ghistabs, and in the root otherwise. The C++ tests that
import a binary's stabs stay in the root, in their `ghicpp.*` packages: `ClassHierarchyIntegrationTest`,
`ItaniumClassAnalyzerStabsIntegrationTest`, `Gcc2SecondaryVtableIntegrationTest`,
`VtableRecordIntegrationTest`, `TypeinfoReaderIntegrationTest` and `VxTableTagIntegrationTest`.

Run **`./gradlew listTests`** to see every ghistabs test class grouped by tag (it doesn't list ghicpp's), with its test count — the way to
find where a test lives. It asks JUnit rather than reading sources, so it sees the generated fixture
classes and tags inherited from a base class; the price is that it needs the tests compiled first.
`@ParameterizedTest` classes list as `(parameterized)`, since a dry run never expands them.

- **`StabsImportRegressionTest`** (`ghistabs`) — the core suite. Runs the full import over each fixture
  in both analyzer modes (`CONCURRENT`/`AFTER`) and asserts the materialized output + baseline counters.
  Most fixture-specific assertions live here.
- **Synthetic behavioural** (fast, build a tiny `ProgramBuilder` program, no fixture): the
  `*IntegrationTest` classes under `ghistabs.importer` / `ghistabs.materialize` / `ghistabs`, and in
  ghicpp under `ghicpp.abi` / `ghicpp.recover`, such as `TypeinfoStructsDedupIntegrationTest` (`ghicpp.abi.itanium`).
- **Probes** (`@Tag("probe")`, generators only, run via `probes`): `DegradationDumpProbe` (`ghistabs`),
  `SourceSkeletonProbe` (`render`), `StringTypeProbe` / `TypedefShorteningProbe` (`materialize`).

`Fixtures` (`ghistabs`) is the single source of the fixture corpus and the `-Pfixture`
narrowing — parameterised suites draw their list from it (`select(...)` or `@MethodSource`).

## Adding a test

- A fixture-wide invariant about imported output → a method on `StabsImportRegressionTest` (it already
  imports every fixture). Gate on the *shape* the invariant needs — "no register locals in this
  fixture", "no populated vftable" — never on the fixture's name.
- A suite that needs *a* fixture of a given shape rather than the corpus → `Fixtures
  .orDefault("<committed fixture>")`, which `-Pfixture` can still redirect.
- Logic testable without a real binary → a `test` (unit) test, or a synthetic behavioural class.
- A C++ test → `ghicpp/src/test/`, unless it imports stabs; then the root's `src/test/`, in the same package.
- A diagnostic dump with no assertion → tag it `@Tag("probe")`, not `integration`.

## In CI

CI runs each project's `integrationTest` in its own job, side by side, and only when the change can
affect it: a change under `ghicpp/` runs ghicpp's, one under `src/` (or the root build files) runs
ghistabs', and a change to what both use (`ghidrakt/`, `build-logic/`, Gradle, the CI workflow, the
binary fixtures) runs both. Docs and lint configs run neither. `.github/scripts/changed_suites.py`
holds the rules; `--self-test` checks them.

Both suites run anyway on a push to `main`, on a manual run of the workflow (its `integration` input
set to `all`, the default), and on a PR carrying the **`run-all-integration`** label; adding the label
starts the run. The `baselines` job always runs: it fails when any job failed or a counter left its
committed baseline, and a skipped suite writes no shifted baselines, so it never counts as a move.

GitHub cancels whole runs, never one job, so to drop a slow suite, cancel the run once the other has
finished: `baselines` still runs and checks the finished suite's results and baselines, and reports
the cancelled one as a warning. It fails when every selected suite was cancelled.

The `build` job also lists every compiler warning on the run's summary page, deprecated API use first,
plus Gradle's own deprecations (`.github/scripts/build_warnings.py`), and annotates each compiler warning
on the PR's diff. Warnings never fail the job. All jobs run on `ubuntu-26.04`, pinned rather than
`ubuntu-latest`.
