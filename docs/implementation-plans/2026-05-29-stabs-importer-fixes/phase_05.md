# Phase 5: Struct inheritance modelling

**Goal:** Materialise C++ base classes as inlined `_base_<BaseName>` (or `_vbase_<BaseName>` for virtual) fields at
their declared byte offsets inside derived structs. Record access/virtual metadata in the struct's plate comment.

**Architecture:** Extend `TypeRegistry.materialiseBody()` `TypeDecl.Struct` branch to iterate `body.bases` before the
existing field loop, inserting one component per base via `struct.replaceAtOffset()`. Generate a plate-comment summary
on the resolved Structure DataType.

**Tech Stack:** Kotlin, Ghidra Structure API.

**Testing convention:** All new tests follow
`docs/implementation-plans/2026-05-29-stabs-importer-fixes/testing-convention.md`. Extract
`planBaseInsertions(bases, resolveBase): List<InsertOp>` from the materialiseBody base-loop; unit-test the planner. The
`replaceAtOffset` adapter is integration-tested via headless run against `xapasmcsr.exe`.

**Scope:** 5 of 8 phases.

**Codebase verified:** 2026-05-30

---

## Acceptance Criteria Coverage

### stabs-importer-fixes.AC4: C++ inheritance modelled as inlined `_base_<BaseName>` fields

- **stabs-importer-fixes.AC4.1 Success:** A class with single inheritance shows exactly one `_base_<BaseName>` field at
  offset 0 of type `BaseName` (verified on a known case in `xapasmcsr.exe`).
- **stabs-importer-fixes.AC4.2 Success:** A class with multiple inheritance shows one `_base_*` field per base, each at
  its declared offset, in offset order.
- **stabs-importer-fixes.AC4.3 Edge:** Virtual base classes are emitted as `_vbase_<BaseName>` with a `// virtual base`
  field comment; access/virt metadata is preserved in the struct's plate comment.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->

### Task 1: planBaseInsertions pure core + materialiseBody adapter

**Verifies:** stabs-importer-fixes.AC4.1, stabs-importer-fixes.AC4.2, stabs-importer-fixes.AC4.3

**Files:**

- Create: `src/main/kotlin/ghistabs/builder/BaseInsertionPlanner.kt` (pure core — required extraction per
  testing-convention.md)
- Modify: `src/main/kotlin/ghistabs/builder/TypeRegistry.kt:303-333` (the `TypeDecl.Struct` branch in
  `materialiseBody` — call the planner then apply ops)

**Implementation:**

**a) Extract pure core** in `BaseInsertionPlanner.kt`:

```kotlin
package ghistabs.materialize

import ghistabs.parse.BaseDecl
import ghistabs.parse.TypeDecl

data class ResolvedBase(
    val simpleName: String,
    val lengthBytes: Int,
)

data class InsertOp(
    val offsetBytes: Int,
    val fieldName: String,    // "_base_<Name>" or "_vbase_<Name>"
    val comment: String,      // "public base", "protected virtual base", etc.
    val baseSimpleName: String,
)

object BaseInsertionPlanner {
    fun planBaseInsertions(
        bases: List<BaseDecl>,
        resolveBase: (TypeDecl) -> ResolvedBase?,
    ): List<InsertOp> {
        return bases.sortedBy { it.offsetBits }.mapNotNull { base ->
            val resolved = resolveBase(base.type) ?: return@mapNotNull null
            if (resolved.lengthBytes <= 0) return@mapNotNull null
            val fieldName = if (base.isVirtual) "_vbase_${resolved.simpleName}" else "_base_${resolved.simpleName}"
            val comment = buildString {
                append(base.access.name.lowercase())
                if (base.isVirtual) append(" virtual")
                append(" base")
            }
            InsertOp((base.offsetBits / 8).toInt(), fieldName, comment, resolved.simpleName)
        }
    }
}
```

**Testing (Kind 1 — pure unit)**: `src/test/kotlin/ghistabs/builder/BaseInsertionPlannerTest.kt`. No Ghidra imports.

- Cases:
    - Single base, public, isVirtual=false → 1 InsertOp at offset 0 with name `_base_Base`, comment `"public base"`.
    - Two bases at +0 and +8, both public → 2 InsertOps in offset order.
    - One virtual base, access=PROTECTED → InsertOp with name `_vbase_Base`, comment `"protected virtual base"`.
    - Base whose `resolveBase` returns null → mapped to null, not in output (no exception).
    - Base whose resolved length is 0 → skipped.
    - Bases supplied out of offset order → output sorted by offset.

**b) Adapter** in `materialiseBody` (before the existing field loop at line 312):

```kotlin
is TypeDecl.Struct -> {
    val struct: Composite = if (body.kind == AggrKind.UNION) placeholder as Union else placeholder as Structure

    // Phase E: insert base classes as inlined components.
    if (struct is Structure) {
        val resolveBase: (TypeDecl) -> ResolvedBase? = { typeDecl ->
            val dt = dataTypeFor(typeDecl) ?: return@resolveBase null
            ResolvedBase(simpleName = dt.name, lengthBytes = dt.length)
        }
        val ops = BaseInsertionPlanner.planBaseInsertions(body.bases, resolveBase)
        for (op in ops) {
            val baseDt =
                dataTypeFor(body.bases.first { (it.offsetBits / 8).toInt() == op.offsetBytes }.type) ?: continue
            try {
                struct.replaceAtOffset(op.offsetBytes, baseDt, baseDt.length, op.fieldName, op.comment)
                ctx.diagnostics.inc("inheritance-applied")
            } catch (e: Exception) {
                sink.log("base-layout", "Failed to insert base '${op.baseSimpleName}' in '${ast.name}': ${e.message}")
                ctx.diagnostics.inc("inheritance-failed")
            }
        }
    }

    // Existing field loop (unchanged).
    for (field in body.fields) { /* ... */
    }
    struct
}
```

Edge cases handled:

- Unions skip the base insertion (C++ disallows non-POD bases in unions; defensive).
- Bases referencing an unresolved type land in `dataTypeFor` returning null → skip with no log spam (the dangling-ref
  path will already have logged the underlying ref).
- Field-vs-base offset overlap: if a stabs `FieldDecl` later in the same struct lands at the same offset as the base,
  `replaceAtOffset` overwrites silently — fine, because the base's component is canonical and the field is an artefact
  of how gcc lays out inherited members. If overwrite fails, the field-loop's existing `field-layout` catch logs it.

**Testing (Kind 1 + Kind 2 split):**

- Planner cases above cover the decision logic (Kind 1, pure).
- Adapter behaviour (real `replaceAtOffset` on a real Structure) is covered by Phase 8's headless regression suite
  asserting `_base_*` / `_vbase_*` components are present on known polymorphic classes in `xapasmcsr.exe`. Do not extend
  `TypeRegistryTest.kt`.

**Verification:**

- Run: `./gradlew test --tests "ghistabs.materialize.TypeRegistryTest"`
- Expected: passes; previously-failing tests untouched.

**Commit:** `feat(builder): materialise C++ base classes as _base_/_vbase_ fields`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->

### Task 2: Plate-comment summary on the derived struct

**Verifies:** stabs-importer-fixes.AC4.3 (access/virt metadata preserved)

**Files:**

- Modify: `src/main/kotlin/ghistabs/builder/TypeRegistry.kt` (same struct branch; after the merged components are built)

**Implementation:**
After the field loop completes (line 332), if `body.bases.isNotEmpty()`, build a multi-line description and attach it as
the Structure's description:

```kotlin
if (body.bases.isNotEmpty() && struct is Structure) {
    val lines = body.bases.sortedBy { it.offsetBits }.joinToString("\n") { base ->
        val baseName = (dataTypeFor(base.type)?.name) ?: "<unresolved>"
        val virt = if (base.isVirtual) " virtual" else ""
        "inherits ${base.access.name.lowercase()}$virt $baseName @ +${base.offsetBits / 8}"
    }
    val existing = struct.description ?: ""
    struct.description = if (existing.isEmpty()) lines else "$existing\n$lines"
}
```

This uses `Structure.setDescription(String)` — the Ghidra Structure-level description is rendered as the plate comment
of the struct DataType.

**Testing (Kind 2 — real Ghidra headless):**

- Plate-comment correctness is verified by Phase 8 spot-check `cLexStreamHasBaseField` (extended to also read
  `cls.description`). Do not extend mock-based tests.

**Verification:**

- Run: `./gradlew test --tests "ghistabs.materialize.TypeRegistryTest"`
- Expected: passes.

**Commit:** `feat(builder): plate-comment lists inherited bases`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (task 3) -->
<!-- START_TASK_3 -->

### Task 3: Phase 5 integration check on xapasmcsr.exe

**Verifies:** stabs-importer-fixes.AC4.1, stabs-importer-fixes.AC4.2 (real-binary)

**Files:**

- Modify: `src/test/kotlin/ghistabs/XapasmcsrIntegrationTest.kt:90-104`

**Implementation:**
After analyzer runs:

1. Locate at least one known polymorphic class from `xapasmcsr.exe` (start with `CLexStream` per design) by iterating
   the DTM for `Structure` types with that name.
2. Assert it has at least one component whose name starts with `_base_` or `_vbase_`.
3. Assert `inheritance-applied` counter from the diagnostics block is > 0.
4. (Optional sanity) Compare gap-census counts pre/post — derived structs should show reduced gaps because the base
   subobject now fills bytes that were previously unaccounted for.

Skip-with-assumption if binary absent.

**Verification:**

- Run: `./gradlew integrationTest --tests "ghistabs.XapasmcsrIntegrationTest"`
- Expected: passes if binary present.

**Commit:** `test(builder): assert _base_ field present on CLexStream`
<!-- END_TASK_3 -->
<!-- END_SUBCOMPONENT_B -->

**Phase 5 done when:**

- All four unit tests in Task 1 pass.
- `_base_<Name>` / `_vbase_<Name>` components are visible in Listing struct definitions for derived classes in
  `xapasmcsr.exe`.
- `inheritance-applied` counter > 0 in diagnostics; `inheritance-failed` provides per-class log for outliers.
- Gap census reduction visible vs Phase 1 baseline for derived structs.
