# Phase 6: Vtable root-cause + fix

**Goal:** Increase vtable-applied count on `xapasmcsr.exe` to ≥80% of polymorphic classes by widening `_ZTV` symbol search and adding an `.rdata` pattern-scan fallback. Lock in AC5.2 with a regression test. Fix the parser-emitted `_vptr$<class>` collision with `{vfptr}` and correctly handle the vfptr/inheritance interaction (do not double-insert when a polymorphic base subobject already contributes one).

**Architecture:** Extend `ClassBuilder.buildAndApplyVtable()` resolver lookups to try multiple Cygwin/PE symbol-prefix variants and an `.rdata`-pattern-scan fallback. Add a `hasPolymorphicBaseSubobject(body)` helper used both in `TypeRegistry.materialiseBody` (to skip parser-emitted `_vptr$<class>` field on collision) and in `ClassBuilder.ensureVfptrFirstField` (to gate insertion). Normalize the parser-emitted `_vptr$<class>` field name and type to canonical `{vfptr}: <Class>_vtable*` when not skipped.

**Tech Stack:** Kotlin, Ghidra `SymbolTable`, `Memory`, `Listing`, `Structure`.

**Testing convention:** All new tests follow `docs/implementation-plans/2026-05-29-stabs-importer-fixes/testing-convention.md`. Pure-extract: `mangledZtvCandidates(className): List<String>`, `firstPolymorphicBase(body)` / `hasPolymorphicBaseSubobject(body)`, `chooseVfptrAction(body, polyBase, existingFirstComponent): VfptrAction`, `itaniumDecodesToClass(symName, className)`. These get unit tests. Symbol-table and Memory access happen in the adapter and are integration-tested via headless run.

**Scope:** 6 of 8 phases.

**Codebase verified:** 2026-05-30

---

## Acceptance Criteria Coverage

### stabs-importer-fixes.AC5: Vtable types applied where stabs declare virtual methods
- **stabs-importer-fixes.AC5.1 Success:** Vtable applied count on `xapasmcsr.exe` is >0 and accounts for ≥80% of classes whose stabs records contain `~%<id>;` markers.
- **stabs-importer-fixes.AC5.2 Success:** Every class with at least one virtual method gets a `{vfptr}` field inserted as its first member (regardless of whether `_ZTV` resolved).
- **stabs-importer-fixes.AC5.3 Failure:** Remaining `failed(reason)` cases are bucketed in the diagnostic log; each bucket has a documented rationale in the same log block.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: VtableSymbolCandidates pure core + widened _ZTV symbol search

**Verifies:** stabs-importer-fixes.AC5.1

**Files:**
- Create: `src/main/kotlin/ghistabs/builder/VtableSymbolCandidates.kt` (pure core — required extraction per testing-convention.md)
- Modify: `src/main/kotlin/ghistabs/builder/ClassBuilder.kt:237-250`

**Implementation:**

**a) Extract pure core** in `VtableSymbolCandidates.kt`:
```kotlin
package ghistabs.builder

object VtableSymbolCandidates {
    /** Ordered candidate symbol names that may resolve to a vtable for [className]. */
    fun mangledZtvCandidates(className: String): List<String> {
        val itaniumMangled = itaniumMangleClassName(className)
        val gcc2 = "_vt\$${className}\$"
        return listOf(
            "_ZTV$itaniumMangled",       // Itanium canonical
            "__ZTV$itaniumMangled",      // Cygwin/PE leading-underscore variant
            gcc2,                          // gcc2 fallback
            "${className}::vtable",       // some compilers emit this
        )
    }

    /** True if [symbolName] (with any leading underscore stripped) decodes
     *  to the Itanium-mangled form of [className]. Used by the symbol-iterator fallback. */
    fun itaniumDecodesToClass(symbolName: String, className: String): Boolean {
        if (!symbolName.startsWith("_ZTV")) return false
        val rest = symbolName.removePrefix("_ZTV")
        return rest == itaniumMangleClassName(className)
    }

    /** Itanium-mangle a (possibly nested) class name. Templated names not supported. */
    fun itaniumMangleClassName(name: String): String {
        if ('<' in name) return name  // templated → caller falls back
        val parts = name.split("::").filter { it.isNotEmpty() }
        return if (parts.size == 1) {
            "${parts[0].length}${parts[0]}"
        } else {
            "N" + parts.joinToString("") { "${it.length}$it" } + "E"
        }
    }
}
```

**Testing (Kind 1 — pure unit)**: `src/test/kotlin/ghistabs/builder/VtableSymbolCandidatesTest.kt`. No Ghidra imports.
- `mangledZtvCandidates("CLexStream")` returns exactly `["_ZTV9CLexStream", "__ZTV9CLexStream", "_vt$CLexStream$", "CLexStream::vtable"]`.
- `mangledZtvCandidates("Foo::Bar")` first entry is `"_ZTVN3Foo3BarE"`.
- `itaniumMangleClassName("vector<int>")` returns `"vector<int>"` (templated punt).
- `itaniumDecodesToClass("_ZTV9CLexStream", "CLexStream")` returns true.
- `itaniumDecodesToClass("XYZ_ZTV9CLexStream", "CLexStream")` returns false (no underscore-strip without explicit prefix).

**b) Wire into `ClassBuilder.buildAndApplyVtable`:**

```kotlin
val candidates = VtableSymbolCandidates.mangledZtvCandidates(className)

if ('<' in className) {
    sink.log("vtable-templated-skip", "class '$className' has template args; _ZTV lookup unsupported in v1")
}

val addr = candidates.mapNotNull { resolver.resolve(it) }.firstOrNull() ?: run {
    // Symbol-table fallback: scan for any symbol whose name decodes to this class.
    val symtab = program.symbolTable
    val prefix = "_ZTV"
    val match = symtab.symbolIterator
        .asSequence()
        .firstOrNull { sym ->
            val n = sym.name
            (n.startsWith(prefix) || n.startsWith("_$prefix")) &&
                itaniumDecodesToClass(n.removePrefix("_"), className)
        }
    match?.address ?: run {
        ctx.diagnostics.recordVtable(className, "failed", "no _ZTV symbol")
        sink.log("vtable-unresolved", "no _ZTV symbol for $className (tried ${candidates.joinToString()})")
        return
    }
}
ctx.diagnostics.recordVtable(className, "applied")
```

Where `itaniumDecodesToClass(symbolName: String, className: String): Boolean` is a small helper: after stripping `_ZTV` prefix, the remainder should equal the result of `itaniumMangleClassName(className)`. For templated names this returns false (and we keep the existing skip log).

**Testing (Kind 2 — real Ghidra headless):**
- Symbol search variants are observable via Phase 8's headless regression suite: assert `vtable-applied >= 1` on `xapasmcsr.exe` (proves at least one of the candidates resolved). The pure core test (above) covers candidate generation correctness; the adapter is verified end-to-end via the regression run. **Do not extend mock-based `ClassBuilderTest.kt`.**

**Verification:**
- Run: `./gradlew test --tests "ghistabs.builder.ClassBuilderTest"`
- Expected: passes.

**Commit:** `fix(builder): widen _ZTV symbol search for Cygwin PE variants`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: .rdata pattern-scan fallback

**Verifies:** stabs-importer-fixes.AC5.1 (recovers cases where the symbol IS in `.rdata` but the address-resolver can't reach via name)

**Files:**
- Modify: `src/main/kotlin/ghistabs/builder/ClassBuilder.kt` (extend the fallback inside `buildAndApplyVtable`)

**Implementation:**
After the symbol-iterator fallback in Task 1 returns null, before bailing, attempt a memory scan of `.rdata`:
1. Get `program.memory.getBlock(".rdata")`. If absent, skip the fallback.
2. Find every label in that block whose name starts with `_ZTV` (use `program.symbolTable.getSymbols(block.addressRange)` or iterate labels via `program.symbolTable.symbolIterator(block.start, true)` clipped to block end).
3. For each candidate label, decode its Itanium-mangled name (strip `_ZTV`, run reverse of `itaniumMangleClassName`); if it matches `className`, return that address.

The Itanium-reverse decoder is the same simple parser used in `itaniumDecodesToClass` (Task 1).

If even this fails:
- Bucket the failure: if the class has no `~%<id>;` markers but `hasVTablePointerMarker` was true → bucket `"no-virtual-methods-flagged-but-marker-set"`. If the class is templated → bucket `"templated-unsupported"`. Otherwise → `"truly-missing"`.
- Call `ctx.diagnostics.recordVtable(className, "failed", bucket)` and emit `sink.log("vtable-failed-$bucket", ...)`.

**Testing (Kind 2 — real Ghidra headless):**
- `.rdata` fallback correctness is observable via Phase 8's regression suite (any vtable-applied event that came through the fallback increments the same counter). Bucket diagnostics surface which path resolved each class. **Do not extend mock-based `ClassBuilderTest.kt`.**

**Verification:**
- Run: `./gradlew test --tests "ghistabs.builder.ClassBuilderTest"`
- Expected: passes.

**Commit:** `fix(builder): .rdata pattern-scan fallback for vtable resolution`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (task 3) -->
<!-- START_TASK_3 -->
### Task 3: AC5.2 regression guard + Phase 6 integration assertion

**Verifies:** stabs-importer-fixes.AC5.2, stabs-importer-fixes.AC5.1, stabs-importer-fixes.AC5.3

**Files:**
- Modify: `src/test/kotlin/ghistabs/builder/ClassBuilderTest.kt` (AC5.2 regression)
- Modify: `src/test/kotlin/ghistabs/XapasmcsrIntegrationTest.kt:90-104` (AC5.1, AC5.3)

**Implementation:**

a) **AC5.2 regression (Kind 2 — real Ghidra headless)**: in Phase 8's `StabsAnalyzerRegressionTest`, add a spot-check that iterates `program.dataTypeManager.allDataTypes`, finds every `Structure` named after a known polymorphic class (read from the synthetic-corpus list or the real binary), and asserts `structDt.getComponent(0).fieldName == "{vfptr}"` regardless of whether `vtable-applied` fired for that class. Pure unit coverage of the gating decision is already in Task 6's `ChooseVfptrActionTest`.

b) **AC5.1 integration**: in `XapasmcsrIntegrationTest`, after analyzer runs, read counters:
- `expectedClasses = (number of polymorphic classes detected — from stabs-source-of-truth, either a corpus baseline value or computed from `body.hasVTablePointerMarker || body.methods.any { virt == VIRTUAL }` in the parsed ASTs).
- Assert `vtable-applied / expectedClasses >= 0.80`.

c) **AC5.3**: parse the diagnostics log for `vtable-failed-<bucket>` lines. Assert at least one bucket appears (so we know the new bucketing code ran), and that each bucket name appears in a documented allow-list (e.g. `templated-unsupported`, `truly-missing`). The allow-list itself lives in `notes-vtable.md` (NEW: `docs/implementation-plans/2026-05-29-stabs-importer-fixes/notes-vtable.md`) — write one paragraph per bucket explaining what it means and why it's not actionable in v1.

**Verification:**
- Run: `./gradlew test --tests "ghistabs.builder.ClassBuilderTest"` — AC5.2 regression passes.
- Run: `./gradlew integrationTest --tests "ghistabs.XapasmcsrIntegrationTest"` — AC5.1, AC5.3 pass if binary present; skip otherwise.

**Commit:** `test(builder): AC5.2 vfptr regression + AC5.1/AC5.3 integration`
<!-- END_TASK_3 -->
<!-- END_SUBCOMPONENT_B -->

<!-- START_SUBCOMPONENT_C (tasks 4-6) -->
<!-- START_TASK_4 -->
### Task 4: hasPolymorphicBaseSubobject helper

**Verifies:** None (helper for Tasks 5–6)

**Files:**
- Modify: `src/main/kotlin/ghistabs/builder/ClassBuilder.kt` (add helper near `resolveBaseAst` at line 338)

**Implementation:**
Add a recursive predicate:

```kotlin
/**
 * Returns the lowest-offset polymorphic base subobject of `body`, or null if none.
 * "Polymorphic" = has its own vtable pointer marker, has a virtual method, or
 * recursively has a polymorphic base. Used to determine whether a derived class
 * inherits its vfptr slot from a base (no need to insert one) and at what offset.
 */
fun firstPolymorphicBase(body: TypeDecl.Struct): BaseDecl? {
    return body.bases
        .sortedBy { it.offsetBits }
        .firstOrNull { base ->
            val baseStruct = resolveBaseAst(base.type) ?: return@firstOrNull false
            baseStruct.hasVTablePointerMarker ||
                baseStruct.methods.any { it.virt == VirtKind.VIRTUAL } ||
                firstPolymorphicBase(baseStruct) != null
        }
}

fun hasPolymorphicBaseSubobject(body: TypeDecl.Struct): Boolean =
    firstPolymorphicBase(body) != null
```

These are `internal` so `TypeRegistry` can call them too.

**Testing (Kind 1 — pure unit):**
- New unit test file: `src/test/kotlin/ghistabs/builder/PolymorphicBaseTest.kt`. No Ghidra imports — the helpers touch only AST types (`TypeDecl.Struct`, `BaseDecl`), all of which are pure.
- Cases:
  - `polyBase`: Base with `hasVTablePointerMarker = true`; Derived has `Base` as a base → `hasPolymorphicBaseSubobject(Derived) == true`.
  - `nonPolyBase`: Base with no virtuals; Derived has `Base` as a base → false.
  - `transitive`: A → B → C, only A is polymorphic; C reports true via B.
  - `noBases`: empty bases list → false.

**Verification:**
- Run: `./gradlew test --tests "ghistabs.builder.ClassBuilderTest"`
- Expected: passes.

**Commit:** `feat(builder): hasPolymorphicBaseSubobject helper`
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->
### Task 5: Skip parser-emitted _vptr$<class> field on inherited-vfptr collision

**Verifies:** stabs-importer-fixes.AC5.2 (single canonical vfptr per object)

**Files:**
- Modify: `src/main/kotlin/ghistabs/builder/TypeRegistry.kt:303-333` (the `TypeDecl.Struct` field loop)

**Implementation:**
Before iterating `body.fields`, compute `val polyBase = ClassBuilder.firstPolymorphicBase(body)` (or call via a static helper passed through `ImportContext` — pick whichever respects module boundaries). Inside the field loop, before `replaceAtOffset`/`add`:

```kotlin
val isParserEmittedVptr = field.name.startsWith("_vptr$") || field.name.startsWith("_vptr.") || field.name == "_vptr"
if (isParserEmittedVptr && polyBase != null && field.offsetBits == polyBase.offsetBits) {
    // Inherited vfptr — the _base_<Base> component already carries it. Skip.
    ctx.diagnostics.inc("vptr-skipped-inherited")
    continue
}
```

Note: this happens BEFORE the field loop populates the Structure with the parser-emitted vptr, so `_base_<Base>` (inserted by Phase 5's base-loop earlier in the same materialiseBody pass) stays intact.

If `polyBase` is null OR the offset doesn't match the base's offset, fall through and let the field be inserted normally — Task 6 will normalize it in `ClassBuilder.ensureVfptrFirstField`.

**Testing (Kind 2 — real Ghidra headless):**
- The decision logic is exercised in Phase 8's regression suite via `vptr-skipped-inherited` counter assertions on the real binary. Where polymorphic-base-with-inherited-vfptr classes exist in `xapasmcsr.exe`, the counter > 0. **Do not extend mock-based `TypeRegistryTest.kt`.**

**Verification:**
- Run: `./gradlew test --tests "ghistabs.builder.TypeRegistryTest"`
- Expected: passes.

**Commit:** `fix(resolver): skip parser-emitted _vptr$<class> when inherited from poly base`
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->
### Task 6: chooseVfptrAction pure core + ensureVfptrFirstField adapter with inheritance gate

**Verifies:** stabs-importer-fixes.AC5.2 (canonical vfptr type)

**Files:**
- Create: `src/main/kotlin/ghistabs/builder/VfptrDecision.kt` (pure core — required extraction per testing-convention.md)
- Modify: `src/main/kotlin/ghistabs/builder/ClassBuilder.kt:45` (extend `isPoly`)
- Modify: `src/main/kotlin/ghistabs/builder/ClassBuilder.kt:84-101` (rewrite `ensureVfptrFirstField` to delegate to the pure decision then apply via Ghidra API)

**Implementation:**

**a) Extract pure core** in `VfptrDecision.kt`:
```kotlin
package ghistabs.builder

data class FirstComponentSnapshot(
    val fieldName: String?,
    val offsetBytes: Int,
    val isUndefined: Boolean,
)

sealed class VfptrAction {
    object SkipInheritedFromBase : VfptrAction()
    data class Insert(val offsetBytes: Int) : VfptrAction()
    data class Replace(val offsetBytes: Int, val wasFieldName: String) : VfptrAction()
    object AlreadyCanonical : VfptrAction()
    data class CollisionAt(val offsetBytes: Int, val occupantFieldName: String) : VfptrAction()
}

object VfptrDecision {
    fun chooseVfptrAction(
        hasPolymorphicBaseSubobject: Boolean,
        parserVptrOffsetBytes: Int?,           // null if no _vptr$<class> field present in body
        componentAtTargetOffset: FirstComponentSnapshot?,
        canonicalVfptrFieldName: String,       // "{vfptr}"
    ): VfptrAction {
        if (hasPolymorphicBaseSubobject) return VfptrAction.SkipInheritedFromBase
        val targetOffset = parserVptrOffsetBytes ?: 0
        val existing = componentAtTargetOffset
        if (existing != null && existing.offsetBytes == targetOffset && existing.fieldName == canonicalVfptrFieldName) {
            return VfptrAction.AlreadyCanonical
        }
        if (existing == null || existing.isUndefined) return VfptrAction.Insert(targetOffset)
        val isParserEmitted = existing.fieldName?.let {
            it.startsWith("_vptr\$") || it.startsWith("_vptr.") || it == "_vptr"
        } ?: false
        return if (isParserEmitted)
            VfptrAction.Replace(targetOffset, existing.fieldName!!)
        else
            VfptrAction.CollisionAt(targetOffset, existing.fieldName ?: "<anon>")
    }
}
```

**Testing (Kind 1 — pure unit)**: `src/test/kotlin/ghistabs/builder/VfptrDecisionTest.kt`. No Ghidra imports.
- Each VfptrAction variant gets at least one case.
- Polymorphic base subobject present → SkipInheritedFromBase, regardless of other inputs.
- No parser vptr, no existing component at offset 0 → Insert(0).
- Parser vptr at +4, no existing component there → Insert(4).
- Existing canonical `{vfptr}` at correct offset → AlreadyCanonical.
- Existing `_vptr$Foo` at +0 → Replace(0, "_vptr$Foo").
- Existing `something_else` at +0, no parser vptr → CollisionAt(0, "something_else").

**b) Extend isPoly** in `ClassBuilder.build` so a class whose only marker is the parser-emitted vptr field is still recognised:
```kotlin
val isPoly = body.hasVTablePointerMarker ||
    body.methods.any { it.virt == VirtKind.VIRTUAL } ||
    body.fields.any { it.name.startsWith("_vptr$") || it.name.startsWith("_vptr.") || it.name == "_vptr" }
```

c) **Rewrite ensureVfptrFirstField** to delegate to `VfptrDecision.chooseVfptrAction`:

Skeleton:
```kotlin
private fun ensureVfptrFirstField(
    structDt: Structure,
    body: TypeDecl.Struct,
    className: String,
    category: CategoryPath,
) {
    val parserVptrOffset = body.fields
        .firstOrNull { it.name.startsWith("_vptr\$") || it.name.startsWith("_vptr.") || it.name == "_vptr" }
        ?.let { (it.offsetBits / 8).toInt() }
    val existingComp = runCatching { structDt.getComponentAt(parserVptrOffset ?: 0) }.getOrNull()
    val snapshot = existingComp?.let {
        FirstComponentSnapshot(
            fieldName = it.fieldName,
            offsetBytes = it.offset,
            isUndefined = it.dataType is Undefined1DataType,
        )
    }
    val action = VfptrDecision.chooseVfptrAction(
        hasPolymorphicBaseSubobject = hasPolymorphicBaseSubobject(body),
        parserVptrOffsetBytes = parserVptrOffset,
        componentAtTargetOffset = snapshot,
        canonicalVfptrFieldName = ClassUtils.VFPTR,
    )
    when (action) {
        is VfptrAction.SkipInheritedFromBase -> ctx.diagnostics.inc("vfptr-inherited-from-base")
        is VfptrAction.AlreadyCanonical      -> return
        is VfptrAction.Insert -> {
            val ptrToVtable = ensureVtableTypeAndPointer(className, category)
            structDt.insertAtOffset(action.offsetBytes, ptrToVtable, ptrToVtable.length, ClassUtils.VFPTR, "vtable pointer")
            ctx.diagnostics.inc("vfptr-inserted")
        }
        is VfptrAction.Replace -> {
            val ptrToVtable = ensureVtableTypeAndPointer(className, category)
            structDt.replaceAtOffset(action.offsetBytes, ptrToVtable, ptrToVtable.length, ClassUtils.VFPTR,
                "vtable pointer (was: ${action.wasFieldName})")
            ctx.diagnostics.inc("vfptr-normalized")
        }
        is VfptrAction.CollisionAt -> {
            sink.log("vfptr-collision",
                "$className: cannot place {vfptr} at +${action.offsetBytes} (occupied by ${action.occupantFieldName})")
            ctx.diagnostics.inc("vfptr-collision")
        }
    }
}

private fun ensureVtableTypeAndPointer(className: String, category: CategoryPath): DataType {
    val vtableType = dtm.getDataType(category, "${className}_vtable")
        ?: StructureDataType(category, "${className}_vtable", 0, dtm)
            .let { dtm.addDataType(it, DataTypeConflictHandler.KEEP_HANDLER) }
    return PointerDataType.getPointer(vtableType, dtm)
}
```

d) **Update call site at line 46** to pass `body`:
```kotlin
if (isPoly) ensureVfptrFirstField(structDt, body, name, category)
```

**Testing (Kind 1 + Kind 2 split):**
- All six decision cases above are covered by `VfptrDecisionTest.kt` (Kind 1, pure — written in part (a)).
- Adapter correctness (the actual `Structure.insertAtOffset`/`replaceAtOffset` mechanics, and the `dtm.getDataType` lookup for vtable type) is verified by Phase 8's headless regression suite asserting `{vfptr}` is component[targetOffset] on representative polymorphic classes in `xapasmcsr.exe`, and that `vfptr-normalized` / `vfptr-inherited-from-base` / `vfptr-inserted` counters total to `(# poly classes - # with collision)`. **Do not extend mock-based `ClassBuilderTest.kt`.**

**Verification:**
- Run: `./gradlew test --tests "ghistabs.builder.ClassBuilderTest"`
- Expected: passes.

**Commit:** `fix(builder): normalize _vptr$<class> to {vfptr} with inheritance gate`
<!-- END_TASK_6 -->
<!-- END_SUBCOMPONENT_C -->

**Phase 6 done when:**
- All ClassBuilderTest cases pass (variant-resolution + helper + vfptr/inheritance interaction).
- `vtable-applied` ≥ 80% of polymorphic classes on `xapasmcsr.exe`.
- `vtable-failed` buckets are non-empty AND each bucket name has a documented rationale in `notes-vtable.md`.
- AC5.2 unit regression: `{vfptr}` is the canonical type for every poly class without a polymorphic base subobject; classes with a poly base get the vfptr via their `_base_<Base>` component (not via a duplicate `{vfptr}` insertion).
- New counters `vfptr-normalized`, `vfptr-inserted`, `vfptr-inherited-from-base`, `vfptr-collision`, `vptr-skipped-inherited` appear in the diagnostics summary.
