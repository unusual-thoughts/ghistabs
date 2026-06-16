# Testing Convention (applies to all phases)

**No mocks in new tests.** Every test added by this implementation plan is one of two kinds. Nothing in between.

## Kind 1 — Pure unit tests

Operate on plain Kotlin data only. Forbidden imports inside `src/test/kotlin/` for these tests:

- `ghidra.program.model.*`
- `ghidra.program.database.*`
- `ghidra.framework.*`
- `org.mockito.*`, `org.mockito.kotlin.*`
- `ghistabs.importer.ImportContext` (it wraps a `Program`)

Allowed:

- Plain Kotlin/JVM classes
- `ghistabs.parse.Ast.*` (sealed hierarchy is pure)
- `ghistabs.diagnose.StabsDiagnostics` (POKO)
- Extracted algorithm-core classes introduced by this plan (named `XyzCore` or similar)

**Extraction discipline.** Wherever a phase task names a fix in Ghidra-touching code (e.g.
`ClassBuilder.buildAndApplyVtable`, `TypeRegistry.materialiseBody`, `StabsImporter.applyLocal`), the decidable algorithm
inside that fix MUST be extracted to a pure function or class operating on plain records. That extracted core gets a
unit test. The Ghidra-side glue (the adapter that translates `Structure`/`Function`/etc. ↔ plain records and then calls
the core) is NOT unit-tested — its coverage comes from Kind 2.

Concrete extraction patterns by phase:

- Phase 2 — `IncludeContext` is pure already; the `dataTypeFor` cross-batch fallback decision extracts to
  `fun classifyRef(refId: TypeId, currentCu: Int, byId: Set<TypeId>, placeholders: Set<TypeId>, rawSnapshot: Set<TypeId>, includeMap: Map<Int, HeaderFile>): ResolverDecision`.
- Phase 3 — `StructuralDiff.diff` takes `List<ComponentRecord>`, not `Structure`. Adapter (
  `Structure.toComponentRecords(): List<ComponentRecord>`) lives next to it. `DemanglerReplacer` decision extracts to
  `fun chooseReplaceOps(stubs: List<StubRecord>, replacements: Map<String, ReplacementRecord>): List<ReplaceOp>`.
- Phase 5 — `fun planBaseInsertions(bases: List<BaseDecl>, resolveBase: (TypeDecl) -> ResolvedBase?): List<InsertOp>`
  returns insertions; adapter applies via `replaceAtOffset`.
- Phase 6 — `firstPolymorphicBase(body)` and `hasPolymorphicBaseSubobject(body)` are pure (touch only AST).
  `chooseVfptrAction(body, polyBase, existingFirstComponent): VfptrAction` extracts the decision logic in
  `ensureVfptrFirstField`. `mangledZtvCandidates(className: String): List<String>` extracts the variant list.
- Phase 7 — `computePairs` is already pure. `shouldEmitScopePlate(localsInScope): Boolean` and
  `bssCoverageDecision(addr, harvest): CoverageResult` extract.
- Phase 8 — `fun shouldSkipLocal(name: String, paramNames: Set<String>, localNames: Set<String>): SkipReason?` and
  `fun bucketApplyError(throwable: Throwable): String` extract.

## Kind 2 — Real Ghidra headless integration tests

Use `ghidra.test.AbstractGhidraHeadlessIntegrationTest` (from Ghidra's Test JARs) as the JUnit base class. Internally
this drives `HeadlessAnalyzer`/`TestEnv` to bootstrap a real Project, import a real binary via `PeLoader`, run
`AutoAnalysisManager` until completion (which fires `StabsAnalyzer.added()` via the analyzer registration), and then
query the resulting `Program` directly.

**Conventions:**

- Test class lives under `src/test/kotlin/ghistabs/integration/`.
- All such tests carry `@Tag("integration")` so they're excluded from `./gradlew test` and run only via
  `./gradlew integrationTest`.
- Binary fixtures live under `src/test/resources/binaries/`. The reference fixture is `xapasmcsr.exe`, copied from
  `~/.wine/drive_c/ADK_Toolkit_1.2.16.22_x64/tools/bin/xapasmcsr.exe`.
- Every test that needs a binary fixture begins with
  `Assumptions.assumeTrue(fixture.exists(), "skipping: <fixture> absent")`. Never `fail()` on missing binary.
- The test bootstraps with `env = TestEnv(); program = env.redirectProgram(fixture)` (or the equivalent `importBinary`
  path), waits for analysis via `env.waitForBackgroundProcessing()`, then asserts on
  `program.dataTypeManager.allDataTypes`, `program.listing.getDefinedData(true)`,
  `program.symbolTable.getPrimarySymbol(addr)`, etc.
- `MessageLog` captured during analysis is read via `getMessages(env)` (or the project's existing capture pattern);
  tag-frequency parsing is via a small helper in the integration test base.

**Build wiring** (`build.gradle.kts`):

- Add Ghidra test JARs to `testImplementation`: typically
  `${ghidraInstallDir}/Ghidra/Test/Helpers/lib/Generic_Helpers.jar`, plus whichever JARs declare
  `AbstractGhidraHeadlessIntegrationTest` and its base classes. The exact set varies by Ghidra version; resolve at
  task-implementor time by following the `apply(from = "${ghidraInstallDir}/support/buildExtension.gradle")` resolved
  classpath and adding the test-only artifacts.
- The `integrationTest` task already exists at `build.gradle.kts` (uses `includeTags("integration")`); no new gradle
  task needed.

**Skip behaviour:**

- If `GHIDRA_INSTALL_DIR` not set → integration test class fails-fast at static init time (not a per-test skip; the
  harness can't even start). That's acceptable — `./gradlew integrationTest` already requires it.
- If `xapasmcsr.exe` fixture absent → individual `@Test` methods skip via `Assumptions.assumeTrue`. Other integration
  tests in the same class that don't need the binary still run.

## What this convention forbids

- No mockito for any of: `Program`, `Function`, `Listing`, `DataTypeManager`, `SymbolTable`, `MessageLog`,
  `TaskMonitor`, `Address`, `DataType`, `Structure`, `BookmarkManager`, `FunctionManager`.
- No `FakeDataTypeManager`-style hand-rolled fakes for these types either.
- No mockito at all in new test files. Existing mock-based tests in the repo (`buildImporterForSyntheticTest`,
  `FakeDataTypeManager`, `MockDtmTracker`) are NOT extended; they're left alone and replaced over time by the
  pure/headless tests this plan adds. When a phase task says "extend `TypeRegistryTest.kt`", read that as "add new test
  cases that follow this convention", not "extend the existing mock-based patterns".

## What this convention allows

- Existing mock-based tests in the repo continue to run. This plan does not delete them.
- Pure unit tests may use ordinary JUnit 5 + AssertJ-style assertions, parameterised tests, etc.
- Integration tests may use Ghidra's `ProgramBuilder` ONLY for constructing tiny test fixtures inline (e.g. seeding a
  single label or symbol) — that's still a real Program object, not a mock.

## ktlint — mandatory before every commit

Every task in this plan that adds or modifies `*.kt` files MUST run the configured ktlint task before committing.
Concretely:

1. **Resolve the task name once at execution start.** Inspect `build.gradle.kts` for `ktlint` plugin configuration.
   Likely candidates: `./gradlew ktlintFormat` (auto-format) and `./gradlew ktlintCheck` (verify). If neither is
   configured, surface to the user before proceeding — do not commit Kotlin changes without lint enforcement.
2. **Run `ktlintFormat` then `ktlintCheck`** as the last step before each `git commit -m "..."` invocation in each task.
   If `ktlintCheck` fails after formatting, fix the violations manually and re-run — do NOT bypass with `--no-verify` or
   by skipping the check.
3. **The task-implementor subagent inherits this rule.** When dispatching a subagent to implement a task, include in its
   prompt: "Run `./gradlew ktlintFormat && ./gradlew ktlintCheck` before each commit. Do not commit if the check fails."

This applies to every Kotlin file added or modified across all 8 phases, in both `src/main/kotlin/` and
`src/test/kotlin/`.
