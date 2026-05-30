# Phase 1: Diagnostic instrumentation Implementation Plan

**Goal:** Add a run-scoped `StabsDiagnostics` aggregator that counts every drop/conflict/gap/skipped-vtable across the analyzer, emit an end-of-run `[Stabs] === diagnostics ===` summary block, with no behaviour change.

**Architecture:** Single new value class `StabsDiagnostics` attached to `ImportContext`. Seven probe-site call-sites add `ctx.diagnostics.<recordXxx>(...)` lines next to existing `ctx.sink.log(...)` calls. Summary emitted via `ctx.sink.log("diagnostics", ...)` at end of `StabsImporter.run()` (before `runOnRecords()` returns).

**Tech Stack:** Kotlin, Ghidra extension SDK, JUnit 5.11.3.

**Testing convention:** All new tests follow `docs/implementation-plans/2026-05-29-stabs-importer-fixes/testing-convention.md` — pure unit (no Ghidra types, no mocks) for algorithm cores; real Ghidra headless via `AbstractGhidraHeadlessIntegrationTest` for wiring, `@Tag("integration")` gated. Read it before writing any test in this phase.

**Scope:** 1 of 8 phases (Phase A of design).

**Codebase verified:** 2026-05-30

---

## Acceptance Criteria Coverage

This phase implements and tests:

### stabs-importer-fixes.AC11: Diagnostics and regression baseline exist
- **stabs-importer-fixes.AC11.1 Success:** A baseline run on `xapasmcsr.exe` produces a single `[Stabs] === diagnostics ===` block listing all counters defined in `StabsDiagnostics`.
- **stabs-importer-fixes.AC11.2 Success:** Gap-census output identifies structs with internal gaps, distinguishing user-defined types (expected to reach zero gaps post-fix) from genuinely-packed/aligned cases.

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->
<!-- START_TASK_1 -->
### Task 1: StabsDiagnostics core class

**Verifies:** stabs-importer-fixes.AC11.1 (counter registry + summary emission)

**Files:**
- Create: `src/main/kotlin/ghistabs/diag/StabsDiagnostics.kt`

**Implementation:**
A run-scoped class holding:
- A `LinkedHashMap<String, Long>` of named counters with `inc(name, by=1)` / `get(name)` / `snapshotCounters(): Map<String, Long>` ops (insertion-ordered so summary output is stable).
- **Tag→counter auto-bump contract**: when `BookmarkSink.log(tag, message)` is called, it MUST also call `diagnostics.inc(tag)` so every distinct `[Stabs] <tag>:` log line has a corresponding counter. This contract is what later phases (especially Phase 8's regression harness) rely on — they read counter values like `local-var-error` directly from `StabsDiagnostics` instead of re-parsing the log. Phase 1 Task 2 wires this by giving `BookmarkSink` a reference to `diagnostics` (either at construction or via `ImportContext`).
- Bounded example lists per category: `examples: MutableMap<String, MutableList<String>>` capped at top-N (N=10) with `recordExample(category, msg)`.
- A `gapCensus: MutableMap<String, List<GapRecord>>` keyed by fully-qualified struct name (`<categoryPath>/<name>`). `GapRecord(offsetBits: Long, lengthBits: Long, prevField: String?, nextField: String?)`. Recorded by `recordStructGaps(qualifiedName, List<GapRecord>)`.
- Record methods, each updates the matching counter AND appends to its example bucket:
  - `recordUnresolvedRef(refKey: String, referrer: String, cu: String)`
  - `recordPlaceholder(name: String, category: String, reason: String)`
  - `recordDedup(kind: String /*rename|merge|drop*/, name: String, detail: String)`
  - `recordVtable(className: String, outcome: String /*applied|skipped|failed*/, reason: String? = null)`
  - `recordEmptyScope(addr: String, function: String?)`
  - `recordGlobal(addr: String, outcome: String /*applied|skipped*/, dtKind: String, reason: String? = null)`
- `writeSummary(sink: BookmarkSink)`:
    1. Emit single header: `sink.log("diagnostics", "=== diagnostics ===")`
    2. For each counter in insertion order: `sink.log("diagnostics", "$name = $value")`
    3. For each non-empty example bucket: `sink.log("diagnostics", "$category top examples:")` then each capped example on its own line (still under `diagnostics` tag, prefixed `"  - $msg"`).
    4. For gap census: a single grouped section listing per-struct gaps as `"$qualifiedName: gap @+$offsetBits bits len=$lengthBits between $prevField..$nextField"`.
- **Idempotence contract for `writeSummary`**: after the first invocation, `StabsDiagnostics` enters a sealed state (`isSealed = true`). A second call is a NO-OP that returns immediately without emitting any output and without throwing. Counters/example lists remain readable via `get`/`snapshotCounters` after sealing. The regression test parses the log expecting EXACTLY ONE `=== diagnostics ===` block; no dedup logic needed downstream.

Keep class as POKO (no Ghidra dependencies) so it can be unit-tested without `Application.initialize()`.

**Testing (Kind 1 — pure unit per testing-convention.md):**
- Test file: `src/test/kotlin/ghistabs/diag/StabsDiagnosticsTest.kt`. No Ghidra type imports; no mockito; no extension of `GhidraTestBase`.
- Capturing strategy: write a real concrete `BookmarkSink` against a real `MessageLog` — `MessageLog` is a tiny Ghidra utility class (not a heavy program type) and is safe under the convention; the test asserts on `messageLog.toString()`. If even `MessageLog` is undesirable, swap to a thin interface `LogSink { fun log(tag: String, msg: String) }` adopted by `BookmarkSink` and pass a list-recording test impl. Pick whichever the task implementor verifies as simplest at write-time.
- Cases verify:
  - stabs-importer-fixes.AC11.1: After several `record*` calls, `writeSummary` produces exactly one `=== diagnostics ===` header line, one `name = value` line per non-zero counter (in insertion order), example sections only when bucket non-empty.
  - **Idempotence-on-second-call**: call `writeSummary` twice; assert the sink received output ONLY on the first call (sealed contract).
  - stabs-importer-fixes.AC11.2: Gap census section lists each registered struct's gaps with offset/length and adjacent field names; structs with empty gap lists appear in no output line (genuinely-packed structs don't pollute the report).
  - **Tag→counter auto-bump**: write a series of `bookmarkSink.log("foo-tag", ...)` calls and assert `diagnostics.get("foo-tag")` matches the call count.

**Verification:**
- Run: `./gradlew test --tests "ghistabs.diag.StabsDiagnosticsTest"`
- Expected: All tests pass.

**Commit:** `feat(diag): add StabsDiagnostics aggregator`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: Attach StabsDiagnostics to ImportContext

**Verifies:** None (wiring only)

**Files:**
- Modify: `src/main/kotlin/ghistabs/importer/ImportContext.kt:26-36`

**Implementation:**
Add a `val diagnostics: StabsDiagnostics = StabsDiagnostics()` line alongside the existing `sink: BookmarkSink` initializer. Add the import. No constructor signature change — the field is initialized at instance creation, matching the existing `sink` / `resolver` / `dtm` / `symtab` pattern at lines 32-34.

**Verification:**
- Run: `./gradlew compileKotlin`
- Expected: Compiles without errors.
- Run: `./gradlew test`
- Expected: All existing tests still pass (no behaviour change).

**Commit:** `feat(diag): attach StabsDiagnostics to ImportContext`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->
### Task 3: Emit end-of-run summary

**Verifies:** stabs-importer-fixes.AC11.1 (end-of-run emission point)

**Files:**
- Modify: `src/main/kotlin/ghistabs/importer/StabsImporter.kt:23-79` (specifically the `runOnRecords()` tail — just before its return statement)

**Implementation:**
At the end of `runOnRecords()`, after all analysis work and before returning the `PassResult`, call `ctx.diagnostics.writeSummary(ctx.sink)`. Guard with `if (ctx.options.<flag>)` ONLY if a runtime gate is required by the existing options pattern — otherwise unconditional (Phase A is supposed to always run for the baseline).

**Testing:**
- Verifies on the integration test path: `XapasmcsrIntegrationTest`'s synthetic corpus run should now produce a `[Stabs] diagnostics: === diagnostics ===` line in the captured `MessageLog`.
- Add assertion in `XapasmcsrIntegrationTest` (synthetic-corpus test, lines 52-72): after invoking the importer, assert the `MessageLog` contains a line starting with `[Stabs] diagnostics: === diagnostics ===`.

**Verification:**
- Run: `./gradlew test`
- Expected: All tests pass including new diagnostics-emission assertion.

**Commit:** `feat(diag): emit end-of-run diagnostics summary`
<!-- END_TASK_3 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 4-10) -->
<!-- START_TASK_4 -->
### Task 4: Probe site — TypeRegistry unresolved (fileNum,typeNum) refs

**Verifies:** stabs-importer-fixes.AC11.1 (the `dangling-ref` counter populates)

**Files:**
- Modify: `src/main/kotlin/ghistabs/builder/TypeRegistry.kt:365-371` (the existing `TypeDecl.Ref` "Dangling ref" branch)

**Implementation:**
Adjacent to the existing `sink.log("dangling-ref", ...)` call, add `ctx.diagnostics.recordUnresolvedRef("(${body.id.cu},${body.id.n})", ast.name, ast.cu /* or whatever the CU field is named in the surrounding scope */)`. Investigate the surrounding method signature to confirm `ctx` is accessible — if not, thread it via the existing constructor/parameter pattern (TypeRegistry already receives a sink in its constructor; add the diagnostics there OR change the constructor to take an `ImportContext` and derive both — match the prevailing pattern).

**Testing (Kind 2 — real Ghidra headless per testing-convention.md):**
- Per-probe behavior is covered by the Phase 8 headless regression suite, which asserts `dangling-ref >= 1` against the synthetic corpus running through `AbstractGhidraHeadlessIntegrationTest`. Do NOT extend the existing mock-based `TypeRegistryTest.kt` with new cases (the convention prohibits extending mock-based patterns); the auto-bump contract from Task 1 guarantees that any `[Stabs] dangling-ref:` log line increments the counter, so the probe's correctness is verified end-to-end by the headless regression suite asserting baseline counters.

**Verification:**
- Run: `./gradlew test --tests "ghistabs.builder.TypeRegistryTest"`
- Expected: New test passes, existing tests still pass.

**Commit:** `feat(diag): record unresolved (fileNum,typeNum) refs`
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Probe site — TypeRegistry.makePlaceholder

**Verifies:** stabs-importer-fixes.AC11.1 (`placeholder-created` counter)

**Files:**
- Modify: `src/main/kotlin/ghistabs/builder/TypeRegistry.kt:203-220`

**Implementation:**
Inside `makePlaceholder()` after the new placeholder DataType is constructed (just before return), call `ctx.diagnostics.recordPlaceholder(name, category.toString(), reason = "fwd-decl|unresolved-ref|other")`. The reason string should come from the calling site's context; if `makePlaceholder` is called from multiple sites, add a `reason: String` parameter and pass per call-site (`"fwd-decl"` from the materialise loop, `"ref-stub"` from the Ref resolve path). Audit call sites with `grep -n makePlaceholder TypeRegistry.kt`.

**Testing (Kind 2 — real Ghidra headless):**
- Covered by Phase 8's headless regression suite asserting `placeholder-created >= 1` against the synthetic corpus. Do not add new cases to mock-based test files.

**Verification:**
- Run: `./gradlew test --tests "ghistabs.builder.TypeRegistryTest"`
- Expected: passes.

**Commit:** `feat(diag): record placeholder creation`
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: Probe site — TypeRegistry dedup decision

**Verifies:** stabs-importer-fixes.AC11.1 (`dedup-rename` counter — Phase C will add `dedup-merged`/`dedup-dropped`)

**Files:**
- Modify: `src/main/kotlin/ghistabs/builder/TypeRegistry.kt:374-405` (the `registerWithConflict()` body)

**Implementation:**
Where the existing rename log fires (line ~399 area, `sink.log("type-conflict", ...)`), add `ctx.diagnostics.recordDedup(kind = "rename", name = name, detail = "renamed-to-${name}_$n")`. Leave room (a comment marker) for Phase C to add `kind="merge"` and `kind="drop"` cases.

**Testing (Kind 2 — real Ghidra headless):**
- Covered by Phase 8's headless regression suite asserting `dedup-rename >= 0` (allowed-zero — Phase 3 shifts most renames to merge/drop).

**Verification:**
- Run: `./gradlew test --tests "ghistabs.builder.TypeRegistryTest"`
- Expected: passes.

**Commit:** `feat(diag): record dedup rename decisions`
<!-- END_TASK_6 -->

<!-- START_TASK_7 -->
### Task 7: Probe site — struct gap census

**Verifies:** stabs-importer-fixes.AC11.2

**Files:**
- Modify: `src/main/kotlin/ghistabs/builder/TypeRegistry.kt:303-333` (the `TypeDecl.Struct` branch of `materialiseBody()`)

**Implementation:**
After the placeholder Structure is finalised (after the `replaceAtOffset` / `add` loop completes), walk `struct.components` and compute gaps: for every consecutive pair of components, if `prev.offset + prev.length < next.offset` (in bytes; convert to bits if the AST is bits-oriented) record a `GapRecord`. Also consider a final trailing gap if `lastOffset + lastLength < struct.length`. Aggregate per struct as `List<GapRecord>` and call `ctx.diagnostics.recordStructGaps("${category}/${name}", gaps)` only if the list is non-empty.

Care: design says "distinguishing user-defined types from genuinely-packed/aligned cases" — the distinction is the *consumer* of the diagnostic, not the producer. We just emit gaps; the gap census section in `writeSummary` lists them all, and the user/reviewer judges whether each is intentional padding. No further filtering at probe time.

**Testing (Kind 1 — pure unit on extracted core):**
- The gap-computation algorithm extracts to a pure function `fun computeGaps(componentRecords: List<ComponentRecord>, totalLengthBytes: Int): List<GapRecord>` taking plain records (offset, length, fieldName, dtPathName), zero Ghidra deps. Unit-tested in `src/test/kotlin/ghistabs/diag/GapComputationTest.kt`:
  - 16-byte struct, components at [0..4) and [8..12) → one GapRecord(offsetBytes=4, lengthBytes=4, prev="...", next="...") plus one trailing GapRecord(offsetBytes=12, lengthBytes=4, ...).
  - Fully-packed struct → empty list.
  - Empty struct → empty list.
- The Ghidra adapter `Structure.toComponentRecords(): List<ComponentRecord>` lives next to it and is verified end-to-end via Phase 8's headless regression suite asserting gap-census presence.

**Verification:**
- Run: `./gradlew test --tests "ghistabs.builder.TypeRegistryTest"`
- Expected: passes.

**Commit:** `feat(diag): per-struct gap census`
<!-- END_TASK_7 -->

<!-- START_TASK_8 -->
### Task 8: Probe site — ClassBuilder.buildAndApplyVtable

**Verifies:** stabs-importer-fixes.AC11.1 (`vtable-applied`/`vtable-skipped`/`vtable-failed` counters)

**Files:**
- Modify: `src/main/kotlin/ghistabs/builder/ClassBuilder.kt:196-283`

**Implementation:**
Add `ctx.diagnostics.recordVtable(className, "applied")` at the success path (~line 253-255 area). Add `"skipped"` with reason `"no-virtuals"` at the early return at line 216. Add `"failed"` with reason `"unresolved-_ZTV-symbol"` at the address-resolution-failure branch (~line 247-250). Add `"failed"` with reason `"virtual-method-unresolved"` at lines 270-279 if those represent failure-to-apply (verify by reading the surrounding logic). If `ctx` is not in scope, thread it via the constructor — Phase F (vtable fix) will need full `ctx` access anyway.

**Testing (Kind 2 — real Ghidra headless):**
- Covered by Phase 8's headless regression suite which asserts both `vtable-applied >= 1` AND `vtable-failed >= 0` on the real binary. Do not extend the mock-based `ClassBuilderTest.kt`.

**Verification:**
- Run: `./gradlew test --tests "ghistabs.builder.ClassBuilderTest"`
- Expected: passes.

**Commit:** `feat(diag): record vtable apply/skip/fail outcomes`
<!-- END_TASK_8 -->

<!-- START_TASK_9 -->
### Task 9: Probe site — StabsImporter empty-scope plate emission

**Verifies:** stabs-importer-fixes.AC11.1 (`empty-scope` counter)

**Files:**
- Modify: `src/main/kotlin/ghistabs/importer/StabsImporter.kt` (around the scope-locals plate emission near line 371-388 per investigator — locate the exact line where the "Stabs scope locals:" comment string is composed)

**Implementation:**
Just before emitting the plate comment, if the locals list is empty, call `ctx.diagnostics.recordEmptyScope(addr.toString(), enclosingFunctionName)`. The existing emission still proceeds in Phase A — suppression is Phase G.

**Testing (Kind 2 — real Ghidra headless):**
- Covered by Phase 8's headless regression suite asserting `empty-scope` is present in the summary output (value may be 0 post-Phase-7 fix).

**Verification:**
- Run: `./gradlew test`
- Expected: passes.

**Commit:** `feat(diag): record empty-scope plate occurrences`
<!-- END_TASK_9 -->

<!-- START_TASK_10 -->
### Task 10: Probe site — StabsImporter.applyGlobal

**Verifies:** stabs-importer-fixes.AC11.1 (`global-applied`/`global-skipped` counters)

**Files:**
- Modify: `src/main/kotlin/ghistabs/importer/StabsImporter.kt:421-440`

**Implementation:**
At the four exit branches of `applyGlobal()`:
- Unresolved address (line ~426-429): `recordGlobal(addr, "skipped", dtKind = "unknown", reason = "unresolved-symbol")`
- `dataType == null` early return (line ~430): `recordGlobal(addr, "skipped", dtKind = "unknown", reason = "no-resolved-type")`
- `createData` failure (line ~434, `apply-error` log): `recordGlobal(addr, "skipped", dtKind = dataType.displayName, reason = "create-data-failed")`
- Success path: `recordGlobal(addr, "applied", dtKind = dataType.displayName)`

Where `dtKind` discriminates primitive/structure/array/etc. — use Ghidra's class hierarchy probe (`dataType is Structure`, `dataType is Array`, `dataType is Pointer`, etc.) and fall back to `dataType.displayName`. This gives Phase G the per-kind buckets it needs.

**Testing (Kind 2 — real Ghidra headless):**
- Per-kind coverage is asserted in Phase 7 Task 3 (globals must cover each DataType kind) and Phase 8 Task 5 (`globalsCoverEachDataTypeKind` spot-check) via the headless regression suite. The createData-failure path is exercised when the real binary has overlapping code, surfaced via the `global-skipped` counter — also covered by Phase 8 baseline assertions. Do not extend `SymbolApplyTest.kt`.

**Verification:**
- Run: `./gradlew test --tests "ghistabs.importer.SymbolApplyTest"`
- Expected: passes.

**Commit:** `feat(diag): record global apply/skip outcomes per DataType kind`
<!-- END_TASK_10 -->
<!-- END_SUBCOMPONENT_B -->

<!-- START_SUBCOMPONENT_C (task 11) -->
<!-- START_TASK_11 -->
### Task 11: Phase 1 integration test — diagnostics block end-to-end

**Verifies:** stabs-importer-fixes.AC11.1, stabs-importer-fixes.AC11.2 (end-to-end emission)

**Files:**
- Modify: `src/test/kotlin/ghistabs/XapasmcsrIntegrationTest.kt:52-72` (synthetic-corpus test that always runs)

**Implementation:**
Extend the synthetic-corpus assertion block:
1. Run the analyzer (already done in the existing test).
2. Capture the `MessageLog` contents.
3. Assert exactly one line equals `[Stabs] diagnostics: === diagnostics ===`.
4. Assert at least one counter line of form `[Stabs] diagnostics: <name> = <number>` follows.
5. Assert the synthetic corpus's known struct-with-gap (use one with deliberate padding) appears in the gap-census section, OR — if the synthetic corpus has no gap structs — add one to the corpus generator (lines 156-205) and assert it appears.

**Verification:**
- Run: `./gradlew test --tests "ghistabs.XapasmcsrIntegrationTest"`
- Expected: passes.

**Commit:** `test(diag): assert diagnostics block in integration test`
<!-- END_TASK_11 -->
<!-- END_SUBCOMPONENT_C -->

**Phase 1 done when:**
- `./gradlew test` passes (all unit + lifecycle + idempotence tests).
- `./gradlew integrationTest` runs and emits `[Stabs] === diagnostics ===` block in the log (verified manually against `xapasmcsr.exe` once if accessible; otherwise via the synthetic corpus assertion in Task 11).
- All seven probe sites fire at least once on the synthetic corpus (verified by non-zero counter assertions).
- No existing `[Stabs] <tag>: ...` log line is removed or rewritten.
