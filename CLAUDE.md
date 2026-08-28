# ghistabs

A Ghidra extension (Kotlin) that imports STABS debug info (`.stab`/`.stabstr`) from
Cygwin/MinGW **gcc 3.x** PE binaries — types, function signatures, locals, C++ classes,
vtables — and reconstructs per-file source **skeletons** and annotated **decompilations**.

This file orients AI agents working in this repo. Read it before making changes.

## Ghidra locations

- **Install:** `/opt/ghidra` (override with `GHIDRA_INSTALL_DIR`). The build applies
  `$GHIDRA_INSTALL_DIR/support/buildExtension.gradle` and links against its jars, so this must be
  set to build or test at all.
- **Sources:** `~/git/ghidra` — the full Ghidra source tree. Read it to check API behaviour
  (calling-convention/storage internals, `PrototypeModel`, cspec `.cspec` files under
  `Ghidra/Processors/x86/data/languages/`, help docs) rather than guessing.

## Layout

- `src/main/kotlin/ghistabs/` — the extension.
  - `StabsAnalyzer` — entry point; auto-runs once per program. `importer/StabsImporter`
    drives the passes.
  - `parse/` (stab grammar → AST), `harvest/` (AST → resolved model, attribution),
    `materialize/` (model → Ghidra DataTypes, classes, typedef shortening),
    `importer/` (apply to the program), `render/` (skeleton/decomp output).
  - Standalone analyzers (discovered by Ghidra's `ClassSearcher`, no manifest needed) e.g.
    `StructReturnAnalyzer`.
- `src/test/kotlin/ghistabs/` — unit tests + `integration/` (headless-Ghidra, `@Tag("integration")`).
- `src/test/resources/binaries/` — real fixtures (x86:LE:32 gcc PEs: `*.exe`; x86-64 ELF: `box2d`, `xmltest`, …).
- `docs/kotlin-style.md` — **house style, mandatory read before writing Kotlin.**
- `docs/notes/render-backlog.md` — **the work backlog** (open/DONE items, findings). Start here.

## Build & test

```bash
export GHIDRA_INSTALL_DIR=/opt/ghidra     # or pass -PGHIDRA_INSTALL_DIR=...
./gradlew compileKotlin                   # compile
./gradlew ktlintFormat                    # autoformat (run before every commit)
./gradlew ktlintCheck                     # verify formatting
./gradlew detekt                          # static analysis (part of `check`)
./gradlew test                            # fast unit tests (excludes integration)
./gradlew integrationTest                 # headless-Ghidra tests against fixtures (slow, ~minutes)
./gradlew noSerializationTest             # guards the compileOnly split (see TESTING.md)
```

Dependency versions live in `gradle/libs.versions.toml` — declare them there, never inline in
`build.gradle.kts`. `kotlinx-serialization-json` is `compileOnly` for main: JSON dumps belong to the
`cli` source set and the tests, and the extension must not ship the jar.

Build logic lives in `build-logic/src/main/kotlin/ghistabs/build/` (fixture matrix, test conventions,
console reporting, CLI launcher, extension install). `build.gradle.kts` should hold decisions — which
tasks exist, what they depend on — not mechanism. `build-logic` is an included build (not `buildSrc`,
which is unaddressable), so the root `ktlintCheck`/`ktlintFormat`/`test` fan out to it automatically;
`./gradlew -p build-logic <task>` still works to run it alone.

Useful flags on `integrationTest`:

- `-Pregression[=<binary>[,…]]` — run only the fixture matrix, optionally narrowed to those binaries.
- `-Pfixture=<binary>[,…]` — the corpus the *other* fixture-parameterised suites draw from; selects no
  class. The listing of `src/test/resources/binaries/` is the set of valid names.
- `-Pmode=<MODE>[,…]|all` — `AFTER` by default. `-Pmode=BEFORE` skips auto-analysis and is 10-40x
  faster: use it to iterate on anything driven by the harvest/registry/DTM.
- `-PregenerateBaselines=true` — rewrite `RegressionTest` counter baselines from observed counts.
- `--tests 'ghistabs.integration.SourceSkeletonIntegrationTest'` — one class.

Probes write to `build/test-output/{skeletons,decomps}/<fixture>/`; inspect those to eyeball
render changes (the probe tests only assert "something was produced").

## Code style (see `docs/kotlin-style.md`)

- **Terse, expression-first Kotlin.** Pipelines over loops, `?.`/`?:` over null pyramids, no `!!`.
  Fewest lines/intermediates/comments that still read clearly.
- **Comments = why, not what.** No per-line narration, no ass-covering hedges. Provenance goes in
  fields, not spliced into code strings.
- **Prefer the Ghidra API** (`program.symbolTable`/`memory`/`dataTypeManager`) over re-parsing
  PE/ELF/COFF headers or hand-walking serialized dumps.
- ktlint is authoritative for formatting; run `ktlintFormat` on every `.kt` change.
- detekt is configured in `.detekt.yml` (overrides on top of the defaults; each entry carries the
  reason). Rules that punish house style — early return, dispatch tables, catch-and-record at the
  Ghidra boundary — are off there on purpose. Size/complexity thresholds are set from the measured
  distribution over `src/main`, not by feel; re-measure before moving one. `MaxLineLength` stays
  **on** because ktlint's own rule doesn't police comment lines.
- `.detekt-baseline.xml` freezes the pre-existing size/complexity hits so the rules ratchet: shrink
  it as those functions get split, don't regenerate it to paper over a new violation.

## Tests

Two kinds only — **never add mocks** (no `FakeDataTypeManager`, no synthetic-importer harnesses):

- **Kind 1** — pure unit test of a pure core (`Layout`, `FunctionSpans`, `TemplateNameShortener`…).
  Prefer this whenever the logic is pure.
- **Kind 2** — real headless Ghidra against a fixture (`extends AbstractGhidraHeadlessIntegrationTest`,
  `@Tag("integration")`).

Add a test only when it can fail for a real reason (non-obvious logic, a fixed bug, an invariant).
Don't test getters or that a `data class` copies.

## Commits

- Imperative subject; optional `type(scope):` prefix (`fix(test):`, `refactor(diagnose):`,
  `docs(render-backlog):`) — match `git log`.
- Run `ktlintFormat` and the relevant tests before committing.
- Keep accidental/large files out of history with `git rm --cached` + `.gitignore` — never `rm`.
- Record backlog progress by editing `docs/notes/render-backlog.md` (mark items `— DONE` with a
  short findings note), not by leaving `// TODO` fossils in source.
