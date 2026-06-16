# Phase 3: Demangler stub replacement + STL dedup with merge

**Goal:** Replace empty `/Demangler/*` stubs with their stabs-derived equivalents via
`DataTypeManager.replaceDataType()`. Collapse STL template `_2/_3/…` duplicates via hash+name match, gap-aware
structural merge, and clean drop logging.

**Architecture:** New `DemanglerReplacer` class in `src/main/kotlin/ghistabs/replace/` invoked from
`StabsImporter.applyAllSymbols()` BEFORE the function-apply loop. Extends `TypeRegistry.registerWithConflict()` with a
`dedupOrMerge()` that does explicit byte-coverage structural diff (since `ContentHash` ignores offsets) and uses
`replaceDataType()` for merges. Algorithm collapses any overlap-with-disagreement into a hard `Conflicting` outcome — no
partial merges.

**Tech Stack:** Kotlin, Ghidra `DataTypeManager` API (`replaceDataType`, NOT the design-document's `replace(...)` which
does not exist).

**Testing convention:** All new tests follow
`docs/implementation-plans/2026-05-29-stabs-importer-fixes/testing-convention.md` — pure unit (no Ghidra types, no
mocks) for algorithm cores; real Ghidra headless via `AbstractGhidraHeadlessIntegrationTest` for wiring,
`@Tag("integration")` gated. Note in particular: `StructuralDiff` operates on plain `List<ComponentRecord>`, NOT on
Ghidra `Structure`. `DemanglerReplacer`'s decision logic extracts to `chooseReplaceOps(stubs, replacements)`. The
replace-via-DTM glue is integration-tested only.

**Scope:** 3 of 8 phases.

**Codebase verified:** 2026-05-30

---

## Acceptance Criteria Coverage

### stabs-importer-fixes.AC1: Empty `/Demangler/*` stubs are replaced by stabs-derived types

- **stabs-importer-fixes.AC1.1 Success:** After analyzer run on `xapasmcsr.exe`, `DataTypeManager` contains zero empty
  structs under any `/Demangler/...` category.
- **stabs-importer-fixes.AC1.2 Success:** Every class method that previously used a `/Demangler/X` stub now references
  the stabs-derived `X`; no orphan xrefs to deleted stubs remain.

### stabs-importer-fixes.AC2: STL/template duplicates collapse via hash+name + gap-aware merge

- **stabs-importer-fixes.AC2.1 Success:** Conflict-renamed types (suffixed `_2`, `_3`, …) on `xapasmcsr.exe` drop by
  ≥80% versus Phase A baseline.
- **stabs-importer-fixes.AC2.2 Success:** When two same-named types differ only in gap-vs-defined-field at the same
  offset, the result is a single merged type whose fields are the union of resolved fields (verified on at least one
  `_Rb_tree_node<…>` instance).
- **stabs-importer-fixes.AC2.3 Failure:** When two same-named types have a genuine conflict (different *defined* fields
  at the same offset), the later is dropped with a `dedup-dropped` log entry naming both bodies.

---

<!-- START_SUBCOMPONENT_A (tasks 1-3) -->
<!-- START_TASK_1 -->

### Task 1: StructuralDiff helper (byte-coverage, overlap-as-conflict)

**Verifies:** stabs-importer-fixes.AC2.2 (provides the diff classification merge depends on)

**Files:**

- Create: `src/main/kotlin/ghistabs/builder/StructuralDiff.kt`

**Implementation:**
A pure helper operating on plain `ComponentRecord` lists — **no Ghidra type imports** per testing-convention.md.

```kotlin
package ghistabs.materialize

data class ComponentRecord(
    val offsetBytes: Int,
    val lengthBytes: Int,
    val fieldName: String?,
    val dtPathName: String,    // e.g. "/std/int" — opaque identity string
    val isBitfield: Boolean,
)

sealed class StructDiffResult {
    object Identical : StructDiffResult()
    data class GapMergeable(val mergePlan: List<MergeOp>) : StructDiffResult()
    data class Conflicting(val reason: String) : StructDiffResult()
}
data class MergeOp(val sourceFromLeft: Boolean, val sourceComponent: ComponentRecord, val targetOffsetBytes: Int)

object StructuralDiff {
    fun diff(
        left: List<ComponentRecord>, leftLengthBytes: Int,
        right: List<ComponentRecord>, rightLengthBytes: Int,
    ): StructDiffResult
}
```

A separate **adapter** (`Structure.toComponentRecords(): List<ComponentRecord>` extension or top-level helper) lives in
`src/main/kotlin/ghistabs/builder/StructureAdapters.kt`. The adapter is one-line-per-component and is integration-tested
only (Kind 2), never unit-tested.

Algorithm (collapse-on-overlap):

1. **Internal-overlap defensive check.** Build each side's `byteCoverage: Array<ComponentRef?>` of length
   `structure.length`. For each side, while filling, if any byte already has a ref → return
   `Conflicting("internal overlap in <side>")`. (Should be impossible in a well-formed Ghidra Structure but guard.)
2. **Length-extension policy.** If `left.length != right.length`, the longer side must have NO defined component past
   `min(left.length, right.length)` that disagrees with the other side. Specifically: if the longer side has defined
   components beyond the shorter side's end → those can only become MergeOps to extend the shorter side; if the shorter
   side has any defined components within the overlap region that DISAGREE → `Conflicting`. Practical implementation:
   walk both up to `max(length)` and on the shorter side beyond its end, treat coverage as `null` (gap).
3. **Byte-walk.** For `i in 0 until max(left.length, right.length)`:
    - `L = leftCoverage.getOrNull(i)`, `R = rightCoverage.getOrNull(i)`.
    - Both null → continue.
    - One null, other defined → mark the defined component as a "merge candidate" into the gap side.
    - Both defined → require equality of `(componentStartOffset, length, dataType.pathName, fieldName)`. If equal →
      identical at i; else → `Conflicting("disagreement at byte $i: $leftField vs $rightField")` early return.
4. **Merge candidate validation.** A defined component flagged as merge-into-X is only valid if its ENTIRE byte span on
   X is gap. If even one byte of its span is defined on X (i.e. shingled overlap with X) →
   `Conflicting("shingled overlap of <component> at offset")`. Deduplicate merge candidates: each unique component
   contributes exactly one `MergeOp`.
5. **Bitfield carve-out.** If either side has a `DataTypeComponent.isBitFieldComponent` in a byte where the other side
   is also defined (whether bitfield or not) → `Conflicting("bitfield collision at byte $i")`. Bitfield equivalence
   modeling is out of scope for Phase 3.
6. If no conflicts and no merge candidates → `Identical`.
7. If no conflicts and ≥1 merge candidate → `GapMergeable(mergeOps)`.

Use only stable Ghidra `Structure` API: `getComponent(idx)`, `getNumComponents()`, `getLength()`,
`getComponentAt(offset)`,
`DataTypeComponent.getOffset() / getLength() / getDataType() / getFieldName() / isBitFieldComponent`.

**Testing (Kind 1 — pure unit per testing-convention.md):**

- Unit test: `src/test/kotlin/ghistabs/builder/StructuralDiffTest.kt`. **No Ghidra imports; no `GhidraTestBase`; no
  mockito.** Build `ComponentRecord` instances directly in-memory.
- Cases (one assertion per):
    - **Identical**: two 16-byte structs with identical `(offset, name, dtype)` fields → `Identical`.
    - **Pure gap-fill**: A defines `[0..4)` only; B defines `[4..8)` only; both 8 bytes → `GapMergeable` with 2
      MergeOps (A→B's gap @4, B→A's gap @0).
    - **Same-offset disagreement**: both define `[0..4)` with different dtype (int32 vs float32) →
      `Conflicting("disagreement at byte 0: ...")`.
    - **Shingled overlap**: A has int32 at `[0..4)` and int32 at `[4..8)`; B has int64 at `[0..8)` →
      `Conflicting("disagreement at byte 0: ...")` (any byte both define).
    - **Subset overlap**: A defines `[0..8)`; B defines `[2..4)` inside A's span → `Conflicting`.
    - **Bitfield vs primitive**: A has bitfield at byte 0; B has int32 at `[0..4)` →
      `Conflicting("bitfield collision at byte 0")`.
    - **Length-extension OK**: A is 8 bytes with field at `[0..4)` only; B is 16 bytes with same field at `[0..4)` and
      additional field at `[12..16)` → `GapMergeable` (extend A by one MergeOp at byte 12).
    - **Length-extension disagreeing**: A is 8 bytes with int32 at `[4..8)`; B is 16 bytes with float32 at `[4..8)` →
      `Conflicting`.

**Verification:**

- Run: `./gradlew test --tests "ghistabs.materialize.StructuralDiffTest"`
- Expected: all 8 cases pass.

**Commit:** `feat(builder): add StructuralDiff with byte-coverage overlap-as-conflict`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->

### Task 2: dedupOrMerge in registerWithConflict

**Verifies:** stabs-importer-fixes.AC2.1, stabs-importer-fixes.AC2.2, stabs-importer-fixes.AC2.3

**Files:**

- Modify: `src/main/kotlin/ghistabs/builder/TypeRegistry.kt:374-405`

**Implementation:**
Replace the existing hash-mismatch fallback. New flow:

1. Existing-types lookup as today (lines 380, 384).
2. If existing == null → `addDataType` (unchanged).
3. If `existingHash == hash` → return existing (unchanged idempotent path).
4. **Hash mismatch — branch on structural comparison:**
    - If both `existing` and `dt` are `Structure`:
        - Compute `StructuralDiff.diff(existing as Structure, dt as Structure)`.
        - `Identical` → return existing (rare hash collision; safe).
        - `GapMergeable(plan)` → execute the merge plan: for each `MergeOp(srcIdx, offset)`, take the source field from
          the side it came from (closure-captured during diff) and apply via
          `existing.replaceAtOffset(offset, sourceField.dataType, sourceField.length, sourceField.fieldName, sourceField.comment)`.
          Update `byPath[category to name]` to a new content hash recomputed over the merged result. Call
          `ctx.diagnostics.recordDedup("merge", name, "merged ${plan.size} fields")`,
          `sink.log("dedup-merged", "$name: ${plan.size} fields merged")`. Return `existing`.
        - `Conflicting(reason)` → call `ctx.diagnostics.recordDedup("drop", name, reason)`,
          `sink.log("dedup-dropped", "$name: $reason")`. Return `existing` (drop the new one — DO NOT allocate `_N` slot
          for Structures).
    - If `existing` is NOT a Structure (typedef, enum, union, function-def collision): keep current rename-to-`_N`
      behaviour and call `ctx.diagnostics.recordDedup("rename", name, "non-struct conflict → renamed to ${name}_$n")`.
      The `_N` allocator remains in place ONLY for this case.

The merge plan capture needs each `MergeOp` to carry source-side info; extend `MergeOp` to include the actual
`DataTypeComponent` snapshot (
`MergeOp(sourceFromLeft: Boolean, sourceComponent: DataTypeComponent, targetOffsetBytes: Int)`) — `DataTypeComponent` is
a stable Ghidra interface.

**Testing (Kind 2 — real Ghidra headless per testing-convention.md):**

- The merge/drop wiring is verified by Phase 8's headless regression suite against `xapasmcsr.exe`: assert
  `dedup-merge >= 1` (a `_Rb_tree_node`-style merge fires at least once) and `dedup-drop` counter present.
- The merge plan algorithm itself is fully covered by `StructuralDiffTest.kt` (Kind 1, Task 1) — so unit coverage of the
  decision is already in place; Phase 3 Task 2 only adds adapter glue, which is verified end-to-end by the headless
  suite. **Do not extend the mock-based `TypeRegistryTest.kt`.**
- The existing mock-based `testConflictNaming` in the legacy suite remains as-is (the convention forbids modifying
  mock-based tests). When the new wiring lands, that legacy test may fail because Structures no longer get `_N`
  suffixes — at that point the legacy test is to be **deleted** (one-shot exception to "do not extend mock-based tests",
  justified because the legacy test asserts a contract that no longer exists). Document the deletion in the commit
  message.

**Verification:**

- Run: `./gradlew test --tests "ghistabs.materialize.TypeRegistryTest"`
- Expected: passes.

**Commit:** `feat(resolver): gap-aware dedupOrMerge replacing rename for structs`
<!-- END_TASK_2 -->

<!-- START_TASK_3 -->

### Task 3: Wire dedup counters into diagnostics summary

**Verifies:** stabs-importer-fixes.AC2.1 (counter visible in summary block)

**Files:**

- Modify: `src/main/kotlin/ghistabs/diag/StabsDiagnostics.kt`

**Implementation:**
Ensure `recordDedup("merge", ...)` increments counter `"dedup-merge"`, `recordDedup("drop", ...)` increments
`"dedup-drop"`, `recordDedup("rename", ...)` increments `"dedup-rename"`. Phase 1's `recordDedup(kind, name, detail)`
already keys on `kind`; verify the counter name pattern `"dedup-$kind"` and adjust if Phase 1 used a different
convention.

**Testing (Kind 1 — pure unit):**

- Extend `src/test/kotlin/ghistabs/diag/StabsDiagnosticsTest.kt` (already pure per Phase 1) to assert these three
  counter names appear after the appropriate `recordDedup` calls.

**Verification:**

- Run: `./gradlew test --tests "ghistabs.diagnose.StabsDiagnosticsTest"`
- Expected: passes.

**Commit:** `feat(diag): explicit dedup-merge/drop/rename counters`
<!-- END_TASK_3 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 4-6) -->
<!-- START_TASK_4 -->

### Task 4: chooseReplaceOps pure core + DemanglerReplacer adapter

**Verifies:** stabs-importer-fixes.AC1.1, stabs-importer-fixes.AC1.2

**Files:**

- Create: `src/main/kotlin/ghistabs/replace/DemanglerReplaceCore.kt` (pure core — required extraction per
  testing-convention.md)
- Create: `src/main/kotlin/ghistabs/replace/DemanglerReplacer.kt` (Ghidra adapter)

**Implementation:**

**a) Extract pure core** in `DemanglerReplaceCore.kt`:

```kotlin
package ghistabs.replace

data class StubRecord(
    val pathName: String,         // e.g. "/Demangler/Foo"
    val simpleName: String,       // e.g. "Foo"
    val isEmptyStructure: Boolean,
)
data class ReplacementRecord(
    val pathName: String,         // e.g. "/proj/Foo"
    val simpleName: String,
    val dependsOnPathNames: Set<String>,  // simulated dependsOn lookup
)
data class ReplaceOp(val stubPath: String, val replacementPath: String)

sealed class Skip(val reason: String) {
    data class NoReplacement(val name: String) : Skip("no-replacement-for-$name")
    data class WouldBeCycle(val name: String)  : Skip("would-be-cycle-$name")
    data class StubAlreadyMissing(val path: String) : Skip("already-replaced-$path")
}

object DemanglerReplaceCore {
    fun chooseReplaceOps(
        stubs: List<StubRecord>,
        replacements: Map<String /*simpleName*/, ReplacementRecord>,
    ): Pair<List<ReplaceOp>, List<Skip>>   // returns (ops, skips)
}
```

Pure algorithm:

1. For each stub where `isEmptyStructure == true`, look up `replacements[stub.simpleName]`.
2. If absent → emit `Skip.NoReplacement(stub.simpleName)`.
3. If `stub.pathName in replacement.dependsOnPathNames` → emit `Skip.WouldBeCycle(stub.simpleName)`.
4. Else → emit `ReplaceOp(stub.pathName, replacement.pathName)`.

**Testing (Kind 1 — pure unit)**:

- `src/test/kotlin/ghistabs/replace/DemanglerReplaceCoreTest.kt`. No Ghidra imports.
- Cases:
    - Stub with matching replacement → 1 op, 0 skips.
    - Stub with no replacement → 0 ops, 1 NoReplacement skip.
    - Stub whose replacement depends on the stub's path → 0 ops, 1 WouldBeCycle skip.
    - Non-empty stub → ignored entirely (not in input filter).
    - Multiple stubs, mixed outcomes — counts add up.

**b) Adapter** `DemanglerReplacer.kt` — single-purpose Ghidra glue:

```kotlin
class DemanglerReplacer(private val ctx: ImportContext, private val registry: TypeRegistry) {
    fun run() {
        val dtm = ctx.dtm
        // Build pure-record snapshot for the planner.
        val stubs = mutableListOf<StubRecord>()
        val replacements = mutableMapOf<String, Pair<ReplacementRecord, DataType>>()
        val stubDtByPath = mutableMapOf<String, DataType>()
        val allDts = dtm.allDataTypes
        while (allDts.hasNext()) {
            val dt = allDts.next()
            if (dt.categoryPath.path.startsWith("/Demangler") && dt is Structure) {
                stubs += StubRecord(dt.pathName, dt.name, isEmptyStructure = dt.length == 0 || dt.numComponents == 0)
                stubDtByPath[dt.pathName] = dt
            } else {
                val candidate = registry.findByName(dt.name) ?: continue
                if (candidate !== dt) continue
                val deps = collectDependsOnPaths(dt)  // small helper walking dt.dataTypeComponents
                replacements[dt.name] = ReplacementRecord(dt.pathName, dt.name, deps) to dt
            }
        }
        val (ops, skips) = DemanglerReplaceCore.chooseReplaceOps(
            stubs,
            replacements.mapValues { it.value.first },
        )
        for (skip in skips) ctx.sink.log("demangler-skip", skip.reason)
        for (op in ops) {
            val stubDt = stubDtByPath[op.stubPath] ?: continue
            val replDt = replacements.values.firstOrNull { it.first.pathName == op.replacementPath }?.second ?: continue
            if (!dtm.contains(stubDt)) continue
            try {
                dtm.replaceDataType(stubDt, replDt, /* updateCategoryPath = */ false)
                ctx.diagnostics.inc("replaced-demangler")
                ctx.sink.log("replaced-demangler", "${stubDt.pathName} -> ${replDt.pathName}")
            } catch (e: DataTypeDependencyException) {
                ctx.diagnostics.inc("replaced-demangler-failed")
                ctx.sink.log("replaced-demangler-failed", "${stubDt.pathName}: ${e.message}")
            }
        }
    }
}
```

**Idempotence guarantees:**

- The empty-stub predicate matches only undefined stubs, so successive runs find nothing new.
- `dtm.contains(stub)` guards against double-replace.
- `dtm.replaceDataType` is internally locked.

**Why `updateCategoryPath = false`:** keeps the stabs-derived replacement at its real category (e.g. `/std/foo`); we
don't want `std::foo` dragged into `/Demangler/`.

**Testing (Kind 1 + Kind 2 split per testing-convention.md):**

- Decision logic fully covered by `DemanglerReplaceCoreTest.kt` (Kind 1, pure — written in this Task's part (a)).
- The Ghidra-side adapter (this Task's part (b)) is covered by Phase 8's headless regression suite asserting (a) zero
  empty `/Demangler/*` after analyzer run, (b) `replaced-demangler` counter ≥ 1 on `xapasmcsr.exe`. **Do not
  extend `FakeDataTypeManager` or add any mock-based test.**

**Verification:**

- Run: `./gradlew test --tests "ghistabs.replace.DemanglerReplaceCoreTest"`
- Expected: passes.

**Commit:** `feat(replace): DemanglerReplacer using replaceDataType`
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->

### Task 5: TypeRegistry.findByName lookup

**Verifies:** None (supports Task 4)

**Files:**

- Modify: `src/main/kotlin/ghistabs/builder/TypeRegistry.kt`

**Implementation:**
Add a small public method:

```kotlin
fun findByName(simpleName: String): DataType? {
    val matches = byPath.keys.filter { it.second == simpleName }
    if (matches.size != 1) {
        if (matches.size > 1) sink.log("demangler-ambiguous", "multiple types named '$simpleName' in: ${matches.map { it.first }}")
        return null
    }
    val (cat, name) = matches.single()
    return dtm.getDataType(cat, name)
}
```

Ambiguity policy: if the same simple name resolves to multiple categories (`/std/Foo` and `/proj/Foo`), return null — an
arbitrary pick would corrupt xrefs. Surfaced via `demangler-ambiguous` log for Phase H triage.

**Testing (Kind 2 — real Ghidra headless):**

- `findByName` correctness is implicitly covered by Phase 8's regression suite (a successful `replaced-demangler` event
  requires `findByName` to have returned non-null on the real binary). Ambiguity is observable via the
  `demangler-ambiguous` counter ≥ 0 (allow-zero — depends on real binary content). **Do not
  extend `TypeRegistryTest.kt`.**

**Verification:**

- Run: `./gradlew test --tests "ghistabs.materialize.TypeRegistryTest"`
- Expected: passes.

**Commit:** `feat(resolver): findByName with ambiguity guard`
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->

### Task 6: Wire DemanglerReplacer into applyAllSymbols

**Verifies:** stabs-importer-fixes.AC1.1, stabs-importer-fixes.AC1.2 (end-to-end)

**Files:**

- Modify: `src/main/kotlin/ghistabs/importer/StabsImporter.kt` — insert before line 238 (right after the counters init
  at 226-237, before the `for (open in openFunctions)` loop)

**Implementation:**
Insert:

```kotlin
DemanglerReplacer(ctx, typeRegistry).run()
```

Unconditional in Phase 3; runtime toggle via `StabsOptions` if needed later (Phase H tuning).

**Testing:**

- Add `src/test/kotlin/ghistabs/integration/DemanglerReplaceIntegrationTest.kt` extending
  `AbstractGhidraHeadlessIntegrationTest`, `@Tag("integration")`. Use `TestEnv` to bootstrap a real Project + small
  empty Program (no mocks).
- Programmatically: (a) seed a `/Demangler/Foo` empty struct into the DTM via
  `dtm.addDataType(new StructureDataType(new CategoryPath("/Demangler"), "Foo", 0), DataTypeConflictHandler.KEEP_HANDLER)`; (
  b) add a function with a parameter typed as that stub; (c) seed a stabs-derived `/proj/Foo` with full body via
  `registry`; (d) call `DemanglerReplacer(...).run()`; (e) assert `/Demangler/Foo` no longer in DTM, function param now
  references `/proj/Foo`.

**Verification:**

- Run: `./gradlew test` (unit) and `./gradlew integrationTest` (integration).
- Expected: passes.

**Commit:** `feat(importer): invoke DemanglerReplacer before symbol application`
<!-- END_TASK_6 -->
<!-- END_SUBCOMPONENT_B -->

<!-- START_SUBCOMPONENT_C (task 7) -->
<!-- START_TASK_7 -->

### Task 7: Phase 3 baseline assertions

**Verifies:** stabs-importer-fixes.AC1.1, stabs-importer-fixes.AC2.1

**Files:**

- Modify: `src/test/kotlin/ghistabs/XapasmcsrIntegrationTest.kt:90-104`

**Implementation:**
After analyzer completes on `xapasmcsr.exe`:

1. Iterate `program.dataTypeManager.allDataTypes` and assert zero `Structure` instances with
   `categoryPath.path.startsWith("/Demangler")` AND `(length == 0 || numComponents == 0)`.
2. Count types with names matching `Regex("""^.+_(\d+)$""")` (specifically `_<digit>` suffix), excluding
   intentionally-numbered names from the baseline allow-list. Read
   `src/test/resources/baselines/xapasmcsr-phaseA-baseline.json`'s `_N-suffix-count` field. Assert post-Phase-3 count ≤
   0.20 × baseline.
3. Skip-with-assumption if baseline JSON not present.

**Verification:**

- Run: `./gradlew integrationTest --tests "ghistabs.XapasmcsrIntegrationTest"`
- Expected: passes if binary + baseline present; skips with assumption-violated message otherwise.

**Commit:** `test(replace): assert /Demangler/* clearance + _N reduction`
<!-- END_TASK_7 -->
<!-- END_SUBCOMPONENT_C -->

**Phase 3 done when:**

- `./gradlew test` passes with new `StructuralDiff`, `DemanglerReplacer`, `findByName`, dedup-merge tests.
- `./gradlew integrationTest` shows `/Demangler/*` empty count == 0 and `_N`-suffix drop ≥ 80% vs baseline.
- Re-running analyzer on same program yields same `replaced-demangler` / `dedup-merge` / `dedup-drop` counter values.
