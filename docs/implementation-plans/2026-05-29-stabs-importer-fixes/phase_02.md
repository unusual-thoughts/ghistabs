# Phase 2: Dangling-ref root cause + two-pass resolver

**Goal:** Eliminate the dangling-ref class of warnings at the source by (a) parsing N_BINCL/N_EINCL/N_EXCL so
include-shared types map correctly across CUs, (b) building an explicit global `Map<TypeId, TypeAst>` index from the
harvest, and (c) classifying every remaining unresolved ref.

**Architecture:** Extend `passAHarvest()` to maintain a per-CU `IncludeContext` (fileNum→HeaderFile table, includeStack,
BINCL/EINCL/EXCL handling) and rewrite TypeIds that originate inside a BINCL/EXCL region so they're keyed off the
canonical `(filename, checksum)` header instead of the local fileNum. Expose `rawTypesById: Map<TypeId, TypeAst>` to
`TypeRegistry`. Add a final classification pass over unresolved refs.

**Tech Stack:** Kotlin, Ghidra extension SDK, JUnit 5.

**Testing convention:** All new tests follow
`docs/implementation-plans/2026-05-29-stabs-importer-fixes/testing-convention.md` — pure unit (no Ghidra types, no
mocks) for algorithm cores; real Ghidra headless via `AbstractGhidraHeadlessIntegrationTest` for wiring,
`@Tag("integration")` gated. Read it before writing any test in this phase.

**Scope:** 2 of 8 phases.

**Codebase verified:** 2026-05-30

---

## Acceptance Criteria Coverage

### stabs-importer-fixes.AC0: Dangling type references are resolved or classified

- **stabs-importer-fixes.AC0.1 Success:** Two-pass resolver brings dangling-ref count on `xapasmcsr.exe` to ≤10% of the
  Phase A baseline (≥90% reduction).
- **stabs-importer-fixes.AC0.2 Success:** Every remaining unresolved `(fileNum,typeNum)` ref is logged with a
  classification: `forward-same-cu`, `cross-cu-include-miss`, or `truly-missing`.
- **stabs-importer-fixes.AC0.3 Edge:** Re-running the analyzer on the same program (re-analyze) produces identical
  resolver counters (idempotent).

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->
<!-- START_TASK_1 -->

### Task 1: HeaderFile + IncludeContext data structures

**Verifies:** None (data only — exercised by tasks 2-5)

**Files:**

- Create: `src/main/kotlin/ghistabs/parser/IncludeContext.kt`

**Implementation:**
Two POKOs:

- `data class HeaderFile(val filename: String, val checksum: Long, val originatingCu: String)` — represents one
  BINCL-or-source-file entity. Two CUs that EXCL the same `(filename, checksum)` share a single `HeaderFile` instance.
- `class IncludeContext(val cuFile: String)`:
    - `private val fileNumToHeader: MutableMap<Int, HeaderFile> = mutableMapOf()` — 1-based fileNum → header.
    - `private val includeStack: ArrayDeque<HeaderFile> = ArrayDeque()` — current BINCL nesting.
    - `private var nextFileNum: Int = 1`
    - Companion object `HeaderRegistry` with `globalByFilenameChecksum: MutableMap<Pair<String, Long>, HeaderFile>` (
      static across the run, populated by BINCL, looked up by EXCL).
    - `fun openSource(filename: String): Int` — for N_SO at start of CU. Allocates fileNum=1, registers the CU's own
      header as `HeaderFile(filename, checksum=0L, originatingCu=filename)`. Returns fileNum.
    - `fun switchSource(filename: String): Int` — for N_SOL. Allocates next fileNum, registers (filename, 0L, cuFile) —
      line-number context only.
    - `fun beginInclude(filename: String, checksum: Long): Int` — for N_BINCL. Either retrieves the existing
      `HeaderFile` from `HeaderRegistry.globalByFilenameChecksum` (then we'll see a duplicate definition stream — let
      TypeRegistry's content-hash dedup handle that), or creates a new one and registers globally. Pushes onto
      includeStack. Allocates next fileNum, maps it to the header. Returns fileNum.
    - `fun endInclude()` — for N_EINCL. Pops includeStack. No fileNum change.
    - `fun reMountExcluded(filename: String, checksum: Long): Int` — for N_EXCL. Looks up `(filename, checksum)` in
      `HeaderRegistry.globalByFilenameChecksum`. If found, allocates next fileNum and maps it to that pre-existing
      header. If NOT found (forward EXCL before BINCL — possible per GCC 3.4 quirks), allocate fileNum and map to a
      placeholder header `HeaderFile(filename, checksum, originatingCu = "<unknown>")` (the placeholder stays — no later
      transparent replacement; if a matching BINCL arrives later it gets its own slot and its types live in their own
      header). Emit `ctx.sink.log("forward-excl", "$filename checksum=$checksum")`. Returns fileNum. Does NOT push
      includeStack (EXCL doesn't open a scope).
    - `fun headerForFileNum(fileNum: Int): HeaderFile?` — lookup for ref resolution.
    - `fun canonicalTypeId(localId: TypeId): TypeId` — rewrites a TypeId observed inside the current CU's stream into a
      canonical form that's stable across CUs that share the same header. Implementation: lookup
      `headerForFileNum(localId.cu)` → if header is BINCL-originated, return `TypeId(header.canonicalCu, localId.n)`
      where `header.canonicalCu` is a stable integer derived from the (filename, checksum) (e.g., hashCode). If header
      is the CU's own source, leave TypeId as-is but disambiguated with the CU's own canonical key.

**Testing (Kind 1 — pure unit):**

- New unit test: `src/test/kotlin/ghistabs/parser/IncludeContextTest.kt`. No Ghidra type imports, no mockito.
- Tests verify:
    - `openSource` allocates fileNum=1.
    - `beginInclude("h.h", 0x123)` allocates fileNum=2; second CU with `reMountExcluded("h.h", 0x123)` allocates a
      different fileNum (e.g., 5) but `headerForFileNum(5)` returns the SAME `HeaderFile` instance as CU1's fileNum=2.
    - `canonicalTypeId(TypeId(5, 7))` in CU2 equals `canonicalTypeId(TypeId(2, 7))` in CU1 (so types defined inside the
      shared header have the SAME canonical TypeId across CUs).
    - `endInclude` decreases stack depth.
    - Forward EXCL (no prior BINCL): allocates a placeholder header with `originatingCu = "<unknown>"`, emits one
      `forward-excl` log line.

**Verification:**

- Run: `./gradlew test --tests "ghistabs.parse.IncludeContextTest"`
- Expected: passes.

**Commit:** `feat(parser): add IncludeContext + HeaderFile for BINCL/EINCL/EXCL`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->

### Task 2: passAHarvest handles N_BINCL/N_EINCL/N_EXCL

**Verifies:** stabs-importer-fixes.AC0.1 (cross-CU refs that previously dangled now resolve via shared header)

**Files:**

- Modify: `src/main/kotlin/ghistabs/importer/StabsImporter.kt:81-209` (passAHarvest switch statement)
- Modify: `src/main/kotlin/ghistabs/importer/StabsImporter.kt` (introduce a per-CU `IncludeContext` instance maintained
  across the record loop)

**Implementation:**
At the top of `passAHarvest`, maintain `var currentInclude: IncludeContext? = null`. On N_SO, instantiate
`IncludeContext(filename)` and call `openSource(filename)`. On N_SOL, call `switchSource(filename)`. Add explicit cases:

```kotlin
StabType.N_BINCL.code -> {
    val filename = record.symbolString ?: continue
    val checksum = record.value  // 32-bit checksum
    currentInclude?.beginInclude(filename, checksum)
}
StabType.N_EINCL.code -> {
    currentInclude?.endInclude()
}
StabType.N_EXCL.code -> {
    val filename = record.symbolString ?: continue
    val checksum = record.value
    currentInclude?.reMountExcluded(filename, checksum)
}
```

Where `TypeAst` instances are created from `N_LSYM` type definitions, rewrite the local `TypeId(localFileNum, n)` to
`currentInclude.canonicalTypeId(localId)` BEFORE construction so the AST's `id` is in the canonical namespace.

When the parser encounters a `TypeDecl.Ref(localId)` while walking a type definition's body, the same canonicalisation
must apply. Locate where `TypeDecl.Ref` is constructed (likely `Parser.kt`'s type-reference parsing); thread an
`IncludeContext` through the parse call, or perform a post-parse rewrite of all `TypeDecl.Ref.id` against the
`IncludeContext` snapshot for that record.

**Testing (Kind 2 — real Ghidra headless):**

- Covered by Phase 8's headless regression suite reading `dangling-ref` and `dangling-ref-*` classification counters
  from the real `xapasmcsr.exe` run. The BINCL/EXCL plumbing is structurally verified by the ≥90% dangling-ref-reduction
  assertion. Do not add mock-based tests under `src/test/kotlin/ghistabs/importer/`.

**Verification:**

- Run: `./gradlew test --tests "ghistabs.importer.IncludeHandlingTest"`
- Expected: passes.

**Commit:** `feat(parser): handle N_BINCL/N_EINCL/N_EXCL in passAHarvest`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->

### Task 3: Persist global rawTypesById across harvest into TypeRegistry

**Verifies:** stabs-importer-fixes.AC0.1 (explicit global index closes cross-batch gaps)

**Files:**

- Modify: `src/main/kotlin/ghistabs/builder/TypeRegistry.kt:136-158` (`materialiseAll`)
- Modify: `src/main/kotlin/ghistabs/importer/StabsImporter.kt:51-59` (call site)

**Implementation:**
Today the registry computes `byName` internally from the input list. Replace the input contract:

- New method (or extended signature): `fun materialiseAll(rawTypesById: Map<TypeId, TypeAst>, attribution: ...)`.
- Inside, compute `val asts = rawTypesById.values.toList()` and `val byName = asts.groupBy { it.name }` exactly as
  today, but additionally seed an explicit `rawByIdSnapshot: Map<TypeId, TypeAst>` that survives across multiple
  `materialiseAll` invocations on the same `TypeRegistry` instance (Phase G/H may import in multiple passes).
- In `dataTypeFor(decl)` at `TypeRegistry.kt:160-165`, when a `TypeDecl.Ref(id)` misses `byId` AND `placeholders`, FIRST
  consult `rawByIdSnapshot[id]` — if found, that means the AST was indexed but not yet materialised in this batch's
  loop: synthesise a placeholder for it on-the-fly via `makePlaceholder` and continue. Only if `rawByIdSnapshot` also
  lacks the id is the ref truly dangling.
- The pre-seed loop at lines 143-150 still pre-seeds for the current batch — but the `rawByIdSnapshot` provides a
  fallback for refs whose target wasn't yet pre-seeded (e.g., a ref encountered during materialiseBody before the loop
  reaches the target).

Then at the StabsImporter call site, change from `materialiseAll(typeAsts) { ... }` to
`materialiseAll(typeAsts.associateBy { it.id }) { ... }`. If two TypeAsts share the same canonical id (post-Task 2
deduplication via headers), the second is dropped by associateBy — that's fine; they're identical bodies.

**Testing (Kind 2 — real Ghidra headless):**

- Covered by Phase 8's regression suite asserting the dangling-ref counter dropped to ≤10% of Phase A. Single-batch
  forward-ref correctness is implicitly regression-guarded by the existing (mock-based) `TypeRegistryTest.kt`
  self-pointer/mutual-cycle cases — do not extend those.

**Verification:**

- Run: `./gradlew test --tests "ghistabs.materialize.TypeRegistryTest"`
- Expected: passes.

**Commit:** `feat(resolver): explicit global rawTypesById index`
<!-- END_TASK_3 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 4-5) -->
<!-- START_TASK_4 -->

### Task 4: Classify remaining unresolved refs

**Verifies:** stabs-importer-fixes.AC0.2

**Files:**

- Create: `src/main/kotlin/ghistabs/builder/ResolverDecision.kt` (pure classifier — required extraction per
  testing-convention.md)
- Modify: `src/main/kotlin/ghistabs/builder/TypeRegistry.kt:365-371` (the dangling-ref branch in materialiseBody — call
  the pure classifier)

**Implementation:**

**a) Extract pure core** `ResolverDecision.kt`:

```kotlin
package ghistabs.materialize

import ghistabs.parse.TypeId
import ghistabs.parse.IncludeContext  // pure already

sealed class RefClassification(val tag: String) {
    object ForwardSameCu : RefClassification("forward-same-cu")
    object CrossCuIncludeMiss : RefClassification("cross-cu-include-miss")
    object TrulyMissing : RefClassification("truly-missing")
}

object ResolverDecision {
    fun classifyRef(
        refId: TypeId,
        refererCu: Int,
        knownTypeIds: Set<TypeId>,
        knownFileNums: Set<Int>,
    ): RefClassification = when {
        refId in knownTypeIds -> error("Refs that resolve must not reach the classifier")
        refId.cu == refererCu -> RefClassification.ForwardSameCu
        refId.cu in knownFileNums -> RefClassification.CrossCuIncludeMiss
        else -> RefClassification.TrulyMissing
    }
}
```

**Testing (Kind 1 — pure unit) for ResolverDecision:** test all three branches in
`src/test/kotlin/ghistabs/builder/ResolverDecisionTest.kt` — no Ghidra imports.

**b) At the dangling-ref detection site in `materialiseBody`**, build `knownTypeIds = rawByIdSnapshot.keys` and
`knownFileNums = includeMapForCu.fileNumToHeader.keys.toSet()`, call
`ResolverDecision.classifyRef(body.id, ast.id.cu, knownTypeIds, knownFileNums)`, then:

- Call `ctx.diagnostics.recordUnresolvedRef(refKey, referrer = ast.name, cu = ast.cuFile)` AND
  `ctx.diagnostics.inc("dangling-ref-${classification.tag}")`.
- Keep the existing `sink.log("dangling-ref", ...)` line but append `[${classification.tag}]` to its message.

The `IncludeContext` for the ast's CU has to be reachable from the registry — pass via a
`Map<String /*cuFile*/, IncludeContext>` snapshot stored on the registry at Task 3.

**Testing (Kind 1 — pure unit on the extracted core):**

- Pure-unit tests for the classifier live in `ResolverDecisionTest.kt` (created in this task). Three cases — one per
  branch. End-to-end classifier-counter wiring is verified by Phase 8's headless suite asserting all three
  `dangling-ref-*` counters appear in the diagnostics summary.

**Verification:**

- Run: `./gradlew test --tests "ghistabs.materialize.TypeRegistryTest"`
- Expected: passes.

**Commit:** `feat(resolver): classify remaining dangling refs`
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->

### Task 5: Idempotence assertion in resolver

**Verifies:** stabs-importer-fixes.AC0.3

**Files:**

- Modify: `src/test/kotlin/ghistabs/IdempotenceTest.kt` (5.9 KB — existing idempotence harness)

**Implementation:**
Add an assertion: after running the importer twice on the same input, the values of `diagnostics.get("dangling-ref")`
and all `dangling-ref-<classification>` counters are identical between run 1 and run 2.

Within the existing test harness:

1. Snapshot `ctx.diagnostics` counter map after run 1 (deep-copy).
2. Reset (or instantiate a fresh `ImportContext`/`StabsDiagnostics`).
3. Run again.
4. Assert counter maps are equal for resolver-related counters.

**Verification:**

- Run: `./gradlew test --tests "ghistabs.IdempotenceTest"`
- Expected: passes.

**Commit:** `test(resolver): idempotence of dangling-ref classification`
<!-- END_TASK_5 -->
<!-- END_SUBCOMPONENT_B -->

<!-- START_SUBCOMPONENT_C (task 6) -->
<!-- START_TASK_6 -->

### Task 6: Phase 2 integration baseline check

**Verifies:** stabs-importer-fixes.AC0.1 (≥90% reduction on `xapasmcsr.exe`)

**Files:**

- Modify: `src/test/kotlin/ghistabs/XapasmcsrIntegrationTest.kt:90-104` (real-binary test that runs only when
  `src/test/resources/binaries/xapasmcsr.exe` is present, gated by `@Tag("integration")`)

**Implementation:**
After analyzer completes, parse the `[Stabs] diagnostics: dangling-ref = <N>` line from the captured MessageLog. Read
the Phase 1 baseline value from a committed file (Task 6b:
`src/test/resources/baselines/xapasmcsr-phaseA-baseline.json`, with at minimum `{"dangling-ref": <N0>}`). Assert
post-Phase-B count ≤ 0.10 × N0.

If the baseline file does not yet exist (Phase 1 run before this test added), the test must
`Assumptions.assumeTrue(file.exists(), "...")` — skip with clear message, NOT fail. Phase H regression harness will
produce the baseline file definitively.

**Testing:** This task IS a test.

**Verification:**

- Run: `./gradlew integrationTest --tests "ghistabs.XapasmcsrIntegrationTest"` (requires the binary present)
- Expected: passes if binary present; skips with assumption-violated message if not.

**Commit:** `test(resolver): assert ≥90% dangling-ref reduction vs Phase A baseline`
<!-- END_TASK_6 -->
<!-- END_SUBCOMPONENT_C -->

**Phase 2 done when:**

- `./gradlew test` passes (unit suite incl. new IncludeContext/IncludeHandling tests).
- `./gradlew integrationTest` passes the dangling-ref-reduction assertion against committed baseline (or skips cleanly
  if binary absent).
- IdempotenceTest verifies resolver counters are stable across re-runs.
- `dangling-ref-forward-same-cu`, `dangling-ref-cross-cu-include-miss`, `dangling-ref-truly-missing` counters appear in
  the Phase 1 diagnostics summary block.
