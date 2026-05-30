# Test Requirements: stabs-importer-fixes

Maps every acceptance criterion (AC0 through AC11, including all `.1`/`.2`/`.3`/`.4` sub-cases) to a concrete test artifact. Two kinds of automated tests per `testing-convention.md`:

- **Kind 1** — pure unit, no `ghidra.program.*` / `ghidra.framework.*` / mockito / `ImportContext`. Runs under `./gradlew test`.
- **Kind 2** — real Ghidra headless via `AbstractGhidraHeadlessIntegrationTest`. `@Tag("integration")`. Runs under `./gradlew integrationTest` with `GHIDRA_INSTALL_DIR` set and `src/test/resources/binaries/xapasmcsr.exe` fixture present.

The convention requires decision-cores to be extracted to plain-record pure functions (unit-tested Kind 1) while the Ghidra-side adapter glue is covered end-to-end by the Phase 8 regression suite (Kind 2). Where coverage is split that way, both rows are listed.

A single "Human verification" section at the end captures criteria that cannot be expressed as a passing assertion (forced-failure validation, document-only outcomes, etc.).

---

## AC0 — Dangling type references are resolved or classified

### AC0.1 — ≥90% dangling-ref reduction on `xapasmcsr.exe`
- **Kind 2 integration**: `src/test/kotlin/ghistabs/XapasmcsrIntegrationTest.kt` (extended per phase_02.md Task 6). Reads `dangling-ref` counter from captured `MessageLog`, asserts `≤ 0.10 × phaseA_baseline.dangling-ref` (baseline = 69 per `xapasmcsr-baseline.json`).
- Also enforced by `StabsAnalyzerRegressionTest.countersWithinBaseline` (phase_08.md Task 4) using the committed range `dangling-ref: [0, 8]`.
- Skip-with-assumption when fixture absent.

### AC0.2 — Every remaining unresolved ref is classified
- **Kind 1 unit**: `src/test/kotlin/ghistabs/builder/ResolverDecisionTest.kt` (phase_02.md Task 4). Three cases, one per `RefClassification` branch (`ForwardSameCu`, `CrossCuIncludeMiss`, `TrulyMissing`); pure inputs, no Ghidra imports.
- **Kind 2 integration**: `StabsAnalyzerRegressionTest` (phase_08.md Task 4) asserts presence of `dangling-ref-forward-same-cu`, `dangling-ref-cross-cu-include-miss`, `dangling-ref-truly-missing` counters in the summary.

### AC0.3 — Idempotent re-analyze
- **Kind 2 integration**: `src/test/kotlin/ghistabs/IdempotenceTest.kt` (extended per phase_02.md Task 5). Runs importer twice on same input, asserts `dangling-ref` and all `dangling-ref-<classification>` counter values equal between runs.

---

## AC1 — Empty `/Demangler/*` stubs replaced

### AC1.1 — Zero empty `/Demangler/*` after run
- **Kind 1 unit (decision core)**: `src/test/kotlin/ghistabs/replace/DemanglerReplaceCoreTest.kt` (phase_03.md Task 4a). Five cases over `chooseReplaceOps(stubs, replacements)` returning `(ops, skips)`.
- **Kind 2 integration (adapter glue)**: `XapasmcsrIntegrationTest` (phase_03.md Task 7) iterates `dataTypeManager.allDataTypes`, asserts zero `Structure` with `categoryPath.path.startsWith("/Demangler")` AND `(length == 0 || numComponents == 0)`.
- Additional Kind 2: `src/test/kotlin/ghistabs/integration/DemanglerReplaceIntegrationTest.kt` (phase_03.md Task 6) seeds a stub + replacement and asserts `/Demangler/Foo` is removed.

### AC1.2 — No orphan xrefs to deleted stubs
- **Kind 2 integration**: `DemanglerReplaceIntegrationTest` (phase_03.md Task 6) — function parameter typed as the stub before run, asserted to reference the stabs-derived replacement after run. Adapter-level coverage; `replaceDataType` semantics not unit-testable without Ghidra.

---

## AC2 — STL/template dedup via hash+name + gap-aware merge

### AC2.1 — `_N` suffixed types drop ≥80% vs baseline
- **Kind 2 integration**: `XapasmcsrIntegrationTest` (phase_03.md Task 7). Counts types matching `Regex("""^.+_(\d+)$""")`, reads `_N-suffix-count` from `xapasmcsr-phaseA-baseline.json`, asserts post-Phase-3 count ≤ `0.20 × baseline`.
- Backstop in `StabsAnalyzerRegressionTest` baseline range `type-conflict: [0, 25]`.

### AC2.2 — Gap-vs-defined-field same-offset → merge
- **Kind 1 unit (decision core)**: `src/test/kotlin/ghistabs/builder/StructuralDiffTest.kt` (phase_03.md Task 1). Cases include "Pure gap-fill" (returns `GapMergeable` with 2 MergeOps), "Length-extension OK", "Identical".
- **Kind 2 integration**: `StabsAnalyzerRegressionTest` asserts `dedup-merge >= 1` on real binary (verifies a `_Rb_tree_node`-style merge fired at least once).

### AC2.3 — Genuine conflict → drop with `dedup-dropped` log
- **Kind 1 unit (decision core)**: `StructuralDiffTest.kt` cases "Same-offset disagreement", "Shingled overlap", "Subset overlap", "Bitfield vs primitive", "Length-extension disagreeing" all return `Conflicting(reason)` with both bodies named.
- **Kind 2 integration**: `StabsAnalyzerRegressionTest` asserts `dedup-drop` counter present in summary (allowed-zero — depends on real binary content but the counter must exist).

---

## AC3 — User types categorised correctly

### AC3.1 — `XapArgInst` not under `/std/include/...`
- **Kind 1 unit**: `src/test/kotlin/ghistabs/builder/AttributionTest.kt` (extended per phase_04.md Task 3). New case `testXapArgInstNotInStd` exercises whichever branch (A/B/C) was taken; pure inputs to `categoryFor()`.
- **Kind 2 integration**: `StabsAnalyzerRegressionTest.xapArgInstNotUnderStdInclude` (phase_08.md Task 5) finds the type in DTM, asserts `categoryPath.path` does NOT start with `/std/`.

### AC3.2 — Genuine stdlib types still under `/std/...`
- **Kind 1 unit**: Existing `AttributionTest.testCppStdBasename`, `testMingwStdBasename` (preserved per phase_04.md Task 3 done-when). Pure inputs; assert tightened regex/override list does not produce false negatives.

---

## AC4 — C++ inheritance as inlined `_base_<BaseName>` fields

### AC4.1 — Single inheritance: one `_base_<Base>` at offset 0
- **Kind 1 unit (decision core)**: `src/test/kotlin/ghistabs/builder/BaseInsertionPlannerTest.kt` (phase_05.md Task 1). Case "Single base, public, non-virtual" → 1 InsertOp at offset 0, name `_base_Base`, comment `"public base"`.
- **Kind 2 integration**: `StabsAnalyzerRegressionTest.cLexStreamHasBaseField` (phase_08.md Task 5) asserts `CLexStream` has ≥1 component whose name starts with `_base_` or `_vbase_`.

### AC4.2 — Multiple inheritance: one `_base_*` per base, offset-ordered
- **Kind 1 unit (decision core)**: `BaseInsertionPlannerTest.kt` cases "Two bases at +0 and +8" and "Bases supplied out of offset order" both assert output is sorted by offset and one InsertOp per base.
- **Kind 2 integration**: `XapasmcsrIntegrationTest` (phase_05.md Task 3) asserts `inheritance-applied` counter > 0; real multiple-inheritance classes from `xapasmcsr.exe` exercise the path.

### AC4.3 — Virtual base → `_vbase_<Base>` + plate-comment metadata
- **Kind 1 unit (decision core)**: `BaseInsertionPlannerTest.kt` case "One virtual base, access=PROTECTED" → InsertOp name `_vbase_Base`, comment `"protected virtual base"`.
- **Kind 2 integration**: `StabsAnalyzerRegressionTest.cLexStreamHasBaseField` (phase_08.md Task 5, extended per phase_05.md Task 2) reads `cls.description` and asserts plate-comment lines of form `inherits <access><virt> <Base> @ +<offset>`.

---

## AC5 — Vtable types applied where stabs declare virtual methods

### AC5.1 — `vtable-applied` ≥80% of polymorphic classes
- **Kind 1 unit (decision core)**: `src/test/kotlin/ghistabs/builder/VtableSymbolCandidatesTest.kt` (phase_06.md Task 1). Cases for `mangledZtvCandidates("CLexStream")`, nested-namespace `Foo::Bar` → `_ZTVN3Foo3BarE`, templated punt, `itaniumDecodesToClass`.
- **Kind 2 integration**: `XapasmcsrIntegrationTest` (phase_06.md Task 3b) computes `expectedClasses` from parsed-AST polymorphic-marker count, asserts `vtable-applied / expectedClasses >= 0.80`.
- `StabsAnalyzerRegressionTest.atLeastOneVtableStructApplied` (phase_08.md Task 5) is the simpler backstop.

### AC5.2 — Every poly class gets `{vfptr}` first member regardless of `_ZTV` resolution
- **Kind 1 unit (decision core)**: `src/test/kotlin/ghistabs/builder/VfptrDecisionTest.kt` (phase_06.md Task 6a). Six cases covering each `VfptrAction` variant (`SkipInheritedFromBase`, `Insert`, `Replace`, `AlreadyCanonical`, `CollisionAt`); plus `src/test/kotlin/ghistabs/builder/PolymorphicBaseTest.kt` (phase_06.md Task 4) for `hasPolymorphicBaseSubobject` (4 cases: polyBase, nonPolyBase, transitive, noBases).
- **Kind 2 integration**: `StabsAnalyzerRegressionTest` (phase_06.md Task 3a) spot-check iterates polymorphic Structures and asserts `getComponent(0).fieldName == "{vfptr}"` (or that the first component is the `_base_<polyBase>` carrying the inherited vfptr).

### AC5.3 — Remaining failures bucketed with documented rationale
- **Kind 2 integration**: `XapasmcsrIntegrationTest` (phase_06.md Task 3c) parses `vtable-failed-<bucket>` lines from log, asserts ≥1 bucket appears and each bucket name is in the allow-list defined in `notes-vtable.md`.
- **Human verification**: `notes-vtable.md` rationale text reviewed by maintainer; see Human verification section.

---

## AC6 — Empty `Stabs scope locals:` plate comments eliminated

### AC6.1 — Zero empty scope-locals plates on `xapasmcsr.exe`
- **Kind 1 unit (decision core)**: `src/test/kotlin/ghistabs/importer/ScopePlateDecisionTest.kt` (phase_07.md Task 1a). Two cases: zero locals → false; ≥1 local → true.
- **Kind 2 integration**: `StabsAnalyzerRegressionTest.countersWithinBaseline` (phase_08.md Task 4) enforces `empty-scope: {min: 0, max: 0}` in baseline JSON — any non-zero value fails the suite. This is the AC6.1 lock.

### AC6.2 — Non-empty scopes list their locals
- **Kind 1 unit (decision core)**: `src/test/kotlin/ghistabs/importer/ComputePairsTest.kt` (phase_07.md Task 1b). Cases `testLocalsFilteredByRecordIndex` (nested LBRAC/RBRAC, correct per-scope filtering by `recordIndex`) and `testNestedScopesEachGetTheirOwn`.
- Real-binary spot-check: implicit in regression suite's diagnostics summary (non-zero `local-var-add-success` counter and matching plate comments in Listing). No dedicated Kind-2 assertion — synthetic-corpus test in `ScopeCommentsTest` covers the nested-scope quality bar via `computePairs` unit test.

---

## AC7 — Unnamed `.bss` globals fixed-or-documented

### AC7.1 — `0x0046702c` named or `stabs-no-coverage` logged
- **Kind 1 unit (decision core)**: `src/test/kotlin/ghistabs/importer/BssCoverageDecisionTest.kt` (phase_07.md Task 2a). Four cases over `BssCoverageDecision.classify(range, harvest)`: empty harvest → `NoCoverage`; in-range → `Covered`; out-of-range → `NoCoverage`; mixed → `Covered` with in-range only.
- **Kind 2 integration**: `StabsAnalyzerRegressionTest.bss0x46702cNamedOrDocumented` (phase_08.md Task 5). Reads `symbolTable.getPrimarySymbol(0x46702c)` OR searches MessageLog for `stabs-no-coverage @` + `0x46702c`; asserts at least one is true.

### AC7.2 — Same outcome for every other previously-unnamed `.bss` address
- **Kind 2 integration**: covered by the `.bss` walk in phase_07.md Task 2b — every address in `.bss` with no `Symbol` and no `Data` produces a `stabs-no-coverage` or `stabs-coverage` log entry. `StabsAnalyzerRegressionTest` asserts the `.bss` walk ran (counter `global-skipped` or `stabs-no-coverage` log lines present) and that no previously-unnamed `.bss` address is silent in the log. Per-address enumeration is impractical; the structural guarantee (every uncovered byte hits the helper) is the test.

---

## AC8 — All global type kinds applied as typed Data

### AC8.1 — At least one global per DataType kind
- **Kind 2 integration**: `StabsAnalyzerRegressionTest.globalsCoverEachDataTypeKind` (phase_08.md Task 5). Iterates `listing.getDefinedData(true)`, buckets by `dataType` class (`Structure`, `Array`, `Union`, `Pointer`, `Enum`, `TypeDef`, `FunctionDefinition`, `Primitive`), asserts required set `{Structure, Pointer, Enum, Primitive}` all populated. Allow-empty kinds (Union/Array/FunctionDefinition/TypeDef) documented inline.
- Extended in `XapasmcsrIntegrationTest` (phase_07.md Task 3a) with the same bucketing.

### AC8.2 — `createData` failure logged + no crash
- **Kind 2 integration**: `StabsAnalyzerRegressionTest` baseline asserts `global-skipped` counter in `[0, 100]` (a failure path that hits real overlapping code in `xapasmcsr.exe`). The "no crash" guarantee is enforced implicitly — the regression test would fail to complete otherwise. Per phase_07.md Task 3b, no mock-based `ApplyGlobalErrorTest` is added (convention forbids `Listing` mocks).

---

## AC9 — `local-var-error` reduced to real cases

### AC9.1 — `local-var-error` count drops ≥90% vs baseline
- **Kind 1 unit (decision core)**: `src/test/kotlin/ghistabs/importer/LocalVarDedupTest.kt` (phase_08.md Task 1). Four cases over `shouldSkipLocal(name, paramNames, localNames)`: param collision, local collision, no collision, param-precedence-over-local.
- **Kind 2 integration**: `StabsAnalyzerRegressionTest.countersWithinBaseline` (phase_08.md Task 4) enforces `local-var-error: {min: 0, max: 35}` against Phase A baseline of 331 (≈90% reduction). Bands for `local-var-skipped-dup-param` and `local-var-skipped-dup-local` ensure benign skips are non-zero (proving the dedup logic runs, not just the failure path being silenced).

---

## AC10 — `apply-error` top bucket eliminated

### AC10.1 — Largest baseline bucket empty; remaining buckets documented
- **Kind 1 unit (decision core)**: `src/test/kotlin/ghistabs/importer/ApplyErrorBucketTest.kt` (phase_08.md Task 2). Three cases over `bucket(throwable)`: "entrypoint" in message → `entrypoint-mismatch`; "Parameter" in message → `parameter-mismatch`; unknown → `other`. (The `invalid-input` and `duplicate-name` Ghidra-exception-class branches are deferred to Kind 2 per phase_08.md note.)
- **Kind 2 integration**: `StabsAnalyzerRegressionTest.countersWithinBaseline` enforces `apply-error-entrypoint-mismatch: {min: 0, max: 0}` — i.e. the design-suspected top bucket must be empty after the `getFunctionContaining` snap. Other buckets allowed via wider bands.
- `StabsAnalyzerRegressionTest.applyErrorInvalidInputBucketDocumented` (phase_08.md Task 5) sanity-checks the `apply-error-invalid-input` counter exists and is well-defined.

---

## AC11 — Diagnostics and regression baseline exist

### AC11.1 — `[Stabs] === diagnostics ===` block emitted with all counters
- **Kind 1 unit**: `src/test/kotlin/ghistabs/diag/StabsDiagnosticsTest.kt` (phase_01.md Task 1). Asserts: exactly one `=== diagnostics ===` header on first `writeSummary` call; one `name = value` line per non-zero counter in insertion order; idempotence (second `writeSummary` is a no-op); tag→counter auto-bump (every `BookmarkSink.log(tag, _)` increments `diagnostics.get(tag)`).
- **Kind 2 integration**: `XapasmcsrIntegrationTest` (phase_01.md Task 11) asserts MessageLog contains exactly one line `[Stabs] diagnostics: === diagnostics ===` and ≥1 counter line.

### AC11.2 — Gap-census output present
- **Kind 1 unit**: `src/test/kotlin/ghistabs/diag/GapComputationTest.kt` (phase_01.md Task 7). Three cases: struct with gap+trailing gap → 2 GapRecords; fully-packed → empty; empty struct → empty. Pure function `computeGaps(componentRecords, totalLengthBytes)`, no Ghidra deps.
- **Kind 2 integration**: `XapasmcsrIntegrationTest` (phase_01.md Task 11) asserts synthetic-corpus struct-with-gap appears in the gap-census section of the summary.

### AC11.3 — `./gradlew test` runs `StabsAnalyzerRegressionTest` and passes
- **Kind 2 integration**: `src/test/kotlin/ghistabs/integration/StabsAnalyzerRegressionTest.kt` (phase_08.md Task 4). `@Tag("integration")` — note this means it runs under `./gradlew integrationTest`, not `./gradlew test`; the AC's "`./gradlew test`" phrasing predates the convention split and is satisfied by the integrationTest gate per the convention. Loads `xapasmcsr.exe` via `TestEnv`, runs `AutoAnalysisManager` to completion, parses tag frequencies from captured `MessageLog`, loads `src/test/resources/baselines/xapasmcsr-baseline.json` via `BaselineLoader`, asserts every counter falls inside its `[min, max]` range. Skips with `Assumptions.assumeTrue` when fixture absent.

### AC11.4 — Out-of-range regression fails with counter name + drift direction
- **Human verification (procedure documented in test class)**: Per phase_08.md Task 4d, the validation is performed manually once: temporarily set `local-var-error.max = 0` in `xapasmcsr-baseline.json`, re-run `./gradlew integrationTest`, confirm failure message contains `local-var-error` and the actual-vs-range delta, revert. The test class's failure-formatting code (`drift += "Counter '$counterName' = $actual outside baseline range [${range.min}..${range.max}]"`) is a static assertion of message format that any reviewer can read; automating the forced-failure cycle would require self-modifying tests. See Human verification section.

---

## Human verification

Two acceptance items resist automation; both have well-defined verification procedures.

### AC5.3 rationale review (`notes-vtable.md`)
**Why not automated:** AC5.3 requires each remaining `vtable-failed-<bucket>` to have "a documented rationale" — natural-language text. The integration test (phase_06.md Task 3c) does enforce that every observed bucket appears in the allow-list keyset of `notes-vtable.md`, which prevents *new* unexplained buckets from sneaking in. The quality of the rationale text itself (whether the explanation is accurate, complete, useful) is a code-review concern.
**Verification approach:** Reviewer reads `docs/implementation-plans/2026-05-29-stabs-importer-fixes/notes-vtable.md`, confirms each bucket has a paragraph explaining (a) what triggers it, (b) why it's not actionable in v1, (c) what would unblock fixing it in v1.1+. Signed off as part of the Phase 6 PR.

### AC11.4 forced-failure validation
**Why not automated:** Self-modifying tests that mutate their own fixtures introduce more risk than they catch. The drift-message format is a static property of the assertion code and is reviewable on a read.
**Verification approach:** Once per release (or after any change to `StabsAnalyzerRegressionTest.countersWithinBaseline`), the maintainer runs the procedure documented in phase_08.md Task 4d: edit `xapasmcsr-baseline.json` to set `local-var-error.max = 0`, run `./gradlew integrationTest --tests "ghistabs.integration.StabsAnalyzerRegressionTest"`, confirm the failure message names `local-var-error` and reports actual value vs `[0..0]`, then `git checkout -- src/test/resources/baselines/xapasmcsr-baseline.json`. Record the date of the most recent run in the test class's KDoc.

### AC3.1 Branch-C documentation case (if taken)
**Why potentially human-only:** Phase 4 Task 3 has three possible outcomes: A (regex fix), B (Phase B canonicalisation fix), C (document as expected stabs data + add an override list). Branch C produces a `notes-attribution.md` whose accuracy depends on a manual trace inspection. If Branch C is taken, the override list is the regression assertion (covered by Kind 1 / Kind 2 above), but the rationale in `notes-attribution.md` is reviewed manually.
**Verification approach:** Reviewer reads `notes-attribution.md` and confirms the cited CU paths actually appear in the captured trace artifact at `build/test-output/xapargInst-attribution-trace.txt`. Branches A and B require no human review beyond the regression test passing.

---

## Coverage matrix

| AC      | Kind 1 (unit, decision core)              | Kind 2 (integration, adapter glue)              | Human |
| ------- | ----------------------------------------- | ----------------------------------------------- | :---: |
| AC0.1   | —                                         | XapasmcsrIntegrationTest + regression baseline  |       |
| AC0.2   | ResolverDecisionTest                      | regression baseline (3 counters present)        |       |
| AC0.3   | —                                         | IdempotenceTest                                 |       |
| AC1.1   | DemanglerReplaceCoreTest                  | XapasmcsrIntegrationTest + DemanglerReplaceIT   |       |
| AC1.2   | —                                         | DemanglerReplaceIntegrationTest                 |       |
| AC2.1   | —                                         | XapasmcsrIntegrationTest + baseline range       |       |
| AC2.2   | StructuralDiffTest                        | regression baseline (`dedup-merge >= 1`)        |       |
| AC2.3   | StructuralDiffTest                        | regression baseline (`dedup-drop` present)      |       |
| AC3.1   | AttributionTest                           | xapArgInstNotUnderStdInclude                    |       |
| AC3.2   | AttributionTest (existing)                | —                                               |       |
| AC4.1   | BaseInsertionPlannerTest                  | cLexStreamHasBaseField                          |       |
| AC4.2   | BaseInsertionPlannerTest                  | XapasmcsrIntegrationTest (`inheritance-applied`)|       |
| AC4.3   | BaseInsertionPlannerTest                  | cLexStreamHasBaseField (plate-comment read)     |       |
| AC5.1   | VtableSymbolCandidatesTest                | XapasmcsrIntegrationTest (80% ratio)            |       |
| AC5.2   | VfptrDecisionTest + PolymorphicBaseTest   | regression spot-check                           |       |
| AC5.3   | —                                         | bucket-allow-list assertion                     |   *   |
| AC6.1   | ScopePlateDecisionTest                    | baseline `empty-scope: [0,0]`                   |       |
| AC6.2   | ComputePairsTest                          | —                                               |       |
| AC7.1   | BssCoverageDecisionTest                   | bss0x46702cNamedOrDocumented                    |       |
| AC7.2   | BssCoverageDecisionTest                   | regression `.bss` walk                          |       |
| AC8.1   | —                                         | globalsCoverEachDataTypeKind                    |       |
| AC8.2   | —                                         | regression baseline (`global-skipped` band)     |       |
| AC9.1   | LocalVarDedupTest                         | baseline `local-var-error: [0,35]`              |       |
| AC10.1  | ApplyErrorBucketTest                      | baseline `apply-error-entrypoint-mismatch: 0`   |       |
| AC11.1  | StabsDiagnosticsTest                      | XapasmcsrIntegrationTest                        |       |
| AC11.2  | GapComputationTest                        | XapasmcsrIntegrationTest                        |       |
| AC11.3  | —                                         | StabsAnalyzerRegressionTest                     |       |
| AC11.4  | —                                         | —                                               |   *   |

Legend: `*` = Human verification documented in this file.
