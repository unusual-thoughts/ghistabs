# Testing

Three test tiers, split by JUnit tag. Pick the narrowest one for the change you made.

| Task                        | What runs                                                                                            | Speed    | When                                                           |
| --------------------------- | ---------------------------------------------------------------------------------------------------- | -------- | -------------------------------------------------------------- |
| `./gradlew test`            | Unit tests — pure logic, synthetic inputs (no Ghidra headless boot). Excludes `integration`/`probe`. | seconds  | every change                                                   |
| `./gradlew integrationTest` | `@Tag("integration")` — real-fixture assertion suite + synthetic-program behavioural tests.          | ~minutes | before pushing; after touching the import/materialize pipeline |
| `./gradlew probeDump`       | `@Tag("probe")` — diagnostic generators (no pass/fail). Writes dumps under `build/test-output/`.     | ~minutes | on demand, when investigating                                  |

Plus one guard task outside the tiers: **`./gradlew noSerializationTest`** re-runs one real-fixture
import with `kotlinx-serialization-json` off the classpath, since main declares it `compileOnly` and the
extension ships without it. Run it after touching dependencies, or after adding a `@Serializable` /
`Json` use anywhere under `src/main/` — if the analyzer path ever reaches for the JSON format, this is
what turns a GUI-only `NoClassDefFoundError` into a build failure. Dumps live in the `cli` source set
(`ghistabs.diagnose.Dumps`) for the same reason; tests get them off the cli output.

All three print per-test PASS/FAIL/SKIP and a final summary line to the console of the same
command (no XML/HTML spelunking), and archive their report to a per-run timestamped dir
(`build/reports/tests/<task>/<stamp>/index.html`) so a later run never clobbers an earlier one.
`integrationTest`/`probeDump` always re-run (they never report `UP-TO-DATE`).

## Flags

Two axes, deliberately separate. **`-Pregression`** picks the *suite*; **`-Pfixture`** picks the
*binaries* a suite draws from. Neither implies the other.

- **`-Pregression[=<filename>[,…]]`** — run the fixture matrix and nothing else: one generated class
  per binary × mode (`StabsImportRegressionBase` subclasses, package `ghistabs.fixtures`). Bare, that
  is every binary on disk; with a comma-separated list of exact filenames, **extension included**,
  only those. Nothing but the matrix runs, so the behavioural and fixture-parameterised classes are
  skipped.
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

The mode axis subtracts where the suite axis selects: unwanted modes are *excluded* by class name, so
defaulting to `AFTER` cannot take the hand-written integration classes out of an ordinary run with
them. `-Pregression` *includes*, so it does exactly that on purpose.

`ktlint` runs separately: `./gradlew ktlintFormat` (autofix) / `ktlintCheck` (verify). Run before committing.

## Fixtures & baselines

- Binaries live in `src/test/resources/binaries/` — see its README for the corpus and how to add to
  it. Most are committed; anything absent (a binary that cannot be redistributed, dropped in locally)
  makes the tests using it *skip*, not fail.
- Baselines live in `src/test/resources/baselines/` (tracked), one per fixture; the baseline for a
  fixture that cannot be redistributed is gitignored alongside its binary, since it is derived from
  it. Same for `src/test/resources/corpus/` descriptor exports. Generated dumps go to
  `build/test-output/` so `./gradlew clean` regenerates them.
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

Run **`./gradlew listTests`** to see every test class grouped by tag, with its test count — the way to
find where a test lives. It asks JUnit rather than reading sources, so it sees the generated fixture
classes and tags inherited from a base class; the price is that it needs the tests compiled first.
`@ParameterizedTest` classes list as `(parameterized)`, since a dry run never expands them.

- **`StabsImportRegressionTest`** (`ghistabs`) — the core suite. Runs the full import over each fixture
  in both analyzer modes (`CONCURRENT`/`AFTER`) and asserts the materialized output + baseline counters.
  Most fixture-specific assertions live here.
- **Synthetic behavioural** (fast, build a tiny `ProgramBuilder` program, no fixture): the
  `*IntegrationTest` classes under `ghistabs.importer` / `ghistabs.materialize` / `ghistabs` +
  `RttiStructsDedupIntegrationTest` (`materialize.itanium`).
- **Probes** (`@Tag("probe")`, generators only, run via `probeDump`): `DegradationDumpProbe` (`ghistabs`),
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
- A diagnostic dump with no assertion → tag it `@Tag("probe")`, not `integration`.
