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

- **`-Pfixture=<filename>[,<filename>…]`** — narrow every parameterised suite *at the source* (via
  `IntegrationFixtures`) to the listed binaries, so only those are imported. A comma-separated list of
  exact filenames, **extension included**: `bouniafbouniaf.exe`, `xmltest`, `bouniaf.exe`, `box2d_tests`,
  `bouniaf.exe`, `unbouniaf.exe` (+ the extended gcc-4.2.1/3.4.5 corpus). A filter that selects
  nothing from a suite errors loudly.
  ```
  ./gradlew integrationTest -Pfixture=bouniafbouniaf.exe,box2d_tests
  ```
- **`-PregenerateBaselines=true`** — rewrite the baseline JSONs from observed counters instead of
  asserting against them (`StabsImportRegressionTest.countersWithinBaseline`). Review the diff.

`ktlint` runs separately: `./gradlew ktlintFormat` (autofix) / `ktlintCheck` (verify). Run before committing.

## Fixtures & baselines

- Binaries live in `src/test/resources/binaries/` — hand-placed, **gitignored** (bouniaf).
  A missing fixture makes the test *skip*, not fail.
- Baselines live in `src/test/resources/baselines/` (tracked). Generated dumps go to
  `build/test-output/` so `./gradlew clean` regenerates them.

## Where the tests live

**Every test — unit, integration, or probe — lives in the package of the code it tests**, not in a
dedicated folder. The `@Tag` (`integration`/`probe`, or none for unit), not the location, is what
decides which task runs it. So a class's unit test, integration test, and probe all sit together next
to the SUT — e.g. `ghistabs.importer` holds `DemanglerReplaceCoreTest` (unit) and
`DemanglerReplaceIntegrationTest` (integration) side by side.

Run **`./gradlew listTests`** to see every test class grouped by tag, with its package, file, and test
count — the way to find where a test lives.

- **`StabsImportRegressionTest`** (`ghistabs`) — the core suite. Runs the full import over each fixture
  in both analyzer modes (`CONCURRENT`/`AFTER`) and asserts the materialized output + baseline counters.
  Most fixture-specific assertions live here.
- **Synthetic behavioural** (fast, build a tiny `ProgramBuilder` program, no fixture): the
  `*IntegrationTest` classes under `ghistabs.importer` / `ghistabs.materialize` / `ghistabs` +
  `RttiStructsDedupIntegrationTest` (`materialize.itanium`).
- **Probes** (`@Tag("probe")`, generators only, run via `probeDump`): `DegradationDumpProbe` (`ghistabs`),
  `SourceSkeletonProbe` (`render`), `StringTypeProbe` / `TypedefShorteningProbe` (`materialize`).

`IntegrationFixtures` (`ghistabs`) is the single source of the fixture corpus and the `-Pfixture`
narrowing — parameterised suites draw their list from it (`select(...)` or `@MethodSource`).

## Adding a test

- A fixture-wide invariant about imported output → a method on `StabsImportRegressionTest` (it already
  imports every fixture; gate to a fixture subset with `assumeTrue(binaryName in IntegrationFixtures.CORE)`).
- Logic testable without a real binary → a `test` (unit) test, or a synthetic behavioural class.
- A diagnostic dump with no assertion → tag it `@Tag("probe")`, not `integration`.
