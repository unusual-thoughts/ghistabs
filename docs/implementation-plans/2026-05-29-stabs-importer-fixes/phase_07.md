# Phase 7: Scope locals + global type application

**Goal:** Suppress empty `Stabs scope locals:` plate comments; correctly filter locals per scope using stab-stream record indices; verify per-DataType-kind global coverage on `xapasmcsr.exe`; investigate unnamed `.bss` globals; document the actual scoped-local failure modes (param-vs-local `this` collision and loop-var shadow collision) for Phase 8 to fix.

**Architecture:** Three small fixes plus integration assertions and one `notes-*.md` document. No new classes.

**Tech Stack:** Kotlin, Ghidra `Listing`, `Function`, `SymbolTable`.

**Testing convention:** All new tests follow `docs/implementation-plans/2026-05-29-stabs-importer-fixes/testing-convention.md`. Pure-extract: `computePairs` (already pure), `shouldEmitScopePlate(localsInScope)`, `bssCoverageDecision(addr, harvest): CoverageResult`. Unit-test those. `Listing.createData` / `Function.addLocalVariable` glue is integration-tested via headless run.

**Scope:** 7 of 8 phases.

**Codebase verified:** 2026-05-30 (against `src/main/kotlin/ghistabs/stabs.log`, a committed baseline run with 499 `[Stabs]` lines).

---

## Acceptance Criteria Coverage

### stabs-importer-fixes.AC6: Empty `Stabs scope locals:` plate comments are eliminated
- **stabs-importer-fixes.AC6.1 Success:** Listing on `xapasmcsr.exe` shows zero plate comments containing the literal text `Stabs scope locals:` followed by nothing.
- **stabs-importer-fixes.AC6.2 Edge:** When the parser actually attaches locals to a scope, the comment lists them — verified by spot-check on a known nested-scope function.

### stabs-importer-fixes.AC7: Unnamed `.bss` globals are investigated and fixed-or-documented
- **stabs-importer-fixes.AC7.1 Success:** `0x0046702c` either has a name applied via `applyGlobal()` *or* the diagnostic log contains a `stabs-no-coverage @ 0x46702c` entry with the records that *do* cover its surrounding range.
- **stabs-importer-fixes.AC7.2 Success:** The same outcome (named-or-documented) holds for every other `.bss` address that was unnamed in the Phase A baseline.

### stabs-importer-fixes.AC8: All global type kinds applied as typed Data
- **stabs-importer-fixes.AC8.1 Success:** For each DataType kind (primitive, enum, typedef, pointer, function pointer, structure, array, union) there is at least one global on `xapasmcsr.exe` whose Listing entry is typed as such a Data item.
- **stabs-importer-fixes.AC8.2 Failure:** When `createData` fails (e.g. would overlap existing code), the failure is logged per address with the conflict reason; analyzer does not crash.

---

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->
<!-- START_TASK_1 -->
### Task 1: Suppress empty scope plate comments + accurate per-scope local filter

**Verifies:** stabs-importer-fixes.AC6.1, stabs-importer-fixes.AC6.2

**Files:**
- Modify: `src/main/kotlin/ghistabs/importer/StabsImporter.kt:371-419` (`applyScopeComments` + `computePairs`)
- Modify: `src/main/kotlin/ghistabs/importer/StabsImporter.kt:484-487` (`LocalRecord` data class — add `recordIndex`)
- Modify: `src/main/kotlin/ghistabs/importer/StabsImporter.kt:475` (`OpenFunction.scopeBrackets` — extend from `Pair<StabType, Long>` to `Triple<StabType, Long, Int>`)
- Modify: `src/main/kotlin/ghistabs/importer/StabsImporter.kt:146-208` (`passAHarvest` collection sites — thread `recordIndex` into LocalRecord and scopeBrackets)

**Implementation:**
Two changes:

a) **Extract pure decision** in `src/main/kotlin/ghistabs/importer/ScopePlateDecision.kt`:
```kotlin
package ghistabs.importer

object ScopePlateDecision {
    /** True iff a Stabs scope-locals plate comment should be emitted at this scope. */
    fun shouldEmitScopePlate(localCount: Int): Boolean = localCount > 0
}
```

Pure-unit-test in `src/test/kotlin/ghistabs/importer/ScopePlateDecisionTest.kt`: zero locals → false; one or more → true. No Ghidra imports.

**Suppress empties in `applyScopeComments`** by delegating:
```kotlin
for ((openOff, _, localsInScope) in pairs) {
    if (!ScopePlateDecision.shouldEmitScopePlate(localsInScope.size)) {
        ctx.diagnostics.recordEmptyScope(addr = "(funcEntry+$openOff)", function = func.name)
        continue
    }
    // existing emission
}
```

b) **Per-scope filter in `computePairs`** (satisfies AC6.2 quality bar):

`OpenFunction` currently stores `locals: MutableList<LocalRecord>` but no positional info. Extend the data model: at the collection site (in `passAHarvest`'s loop), when a local record is added, also capture the **record index in the stab stream** (a monotonically increasing counter incremented per record processed). Add this field to `LocalRecord`:

```kotlin
internal data class LocalRecord(
    val decl: SymbolDecl,
    val rawValue: Long,
    val recordIndex: Int,   // NEW
)
```

Also extend `scopeBrackets` from `Pair<StabType, Long>` to `Triple<StabType, Long, Int>` where the third element is the record index at which that bracket was seen.

Then `computePairs` becomes:
```kotlin
private fun computePairs(
    scopeBrackets: List<Triple<StabType, Long, Int>>,
    locals: List<LocalRecord>,
): List<Triple<Long, Long, List<LocalRecord>>> {
    val pairs = mutableListOf<Triple<Long, Long, List<LocalRecord>>>()
    val stack = mutableListOf<Triple<Int, Long, Int>>()  // (bracketArrayIdx, offset, recordIdx)
    for ((arrIdx, bracket) in scopeBrackets.withIndex()) {
        val (type, off, recIdx) = bracket
        when (type) {
            StabType.N_LBRAC -> stack.add(Triple(arrIdx, off, recIdx))
            StabType.N_RBRAC -> {
                if (stack.isNotEmpty()) {
                    val (_, openOff, openRec) = stack.removeAt(stack.size - 1)
                    val closeOff = off
                    val closeRec = recIdx
                    val localsInScope = locals.filter { it.recordIndex in openRec..closeRec }
                    pairs.add(Triple(openOff, closeOff, localsInScope))
                }
            }
            else -> {}
        }
    }
    return pairs
}
```

**Testing (Kind 1 — pure unit per testing-convention.md):**
- `ScopePlateDecisionTest.kt` covers the emission decision (above; pure).
- `computePairs` is also pure — add `src/test/kotlin/ghistabs/importer/ComputePairsTest.kt` (no Ghidra imports):
  - `testLocalsFilteredByRecordIndex`: build inputs with two nested LBRAC/RBRAC pairs and three locals with `recordIndex` 5, 10, 15. Brackets at recordIndex 3..20 (outer) and 8..12 (inner). Assert outer scope gets all three locals; inner scope gets only the one at recordIndex 10.
  - `testNestedScopesEachGetTheirOwn`: verifies pair offsets for each scope distinguish outer from inner.
- End-to-end suppression (real `Listing.setComment` NOT called for empty scopes) is verified by Phase 8's headless suite asserting `empty-scope` counter equals 0 in the post-fix baseline. **Do not mock `Listing.setComment`.**

**Verification:**
- Run: `./gradlew test --tests "ghistabs.importer.ScopeCommentsTest"`
- Expected: passes.

**Commit:** `fix(importer): suppress empty scope comments + per-scope local filter`
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->
### Task 2: dumpStabsAtAddress diagnostic helper + .bss investigation

**Verifies:** stabs-importer-fixes.AC7.1, stabs-importer-fixes.AC7.2

**Files:**
- Modify: `src/main/kotlin/ghistabs/importer/StabsImporter.kt` (add helper near `applyGlobal`)
- Modify: `src/main/kotlin/ghistabs/importer/StabsImporter.kt:421-440` (`applyGlobal` — wire the skip-side counter)

**Implementation:**
a) **Extract pure decision** in `src/main/kotlin/ghistabs/importer/BssCoverageDecision.kt`:
```kotlin
package ghistabs.importer

data class HarvestedAddr(val symbolName: String, val resolvedAddr: Long?)
data class AddrRange(val start: Long, val endInclusive: Long)

sealed class CoverageResult {
    data class NoCoverage(val range: AddrRange) : CoverageResult()
    data class Covered(val range: AddrRange, val coverers: List<HarvestedAddr>) : CoverageResult()
}

object BssCoverageDecision {
    fun classify(range: AddrRange, harvest: List<HarvestedAddr>): CoverageResult {
        val matching = harvest.filter { it.resolvedAddr != null && it.resolvedAddr in range.start..range.endInclusive }
        return if (matching.isEmpty()) CoverageResult.NoCoverage(range)
               else CoverageResult.Covered(range, matching)
    }
}
```

Pure-unit-test `src/test/kotlin/ghistabs/importer/BssCoverageDecisionTest.kt`:
- Empty harvest → NoCoverage.
- Harvest with one address inside range → Covered with that entry.
- Harvest with addresses outside range → NoCoverage.
- Mix → Covered with only the in-range entries.

**Adapter helper** in `StabsImporter.kt`:
```kotlin
internal fun dumpStabsAtAddressRange(rangeStart: Address, rangeEnd: Address, allHarvested: List<HarvestedSymbol>) {
    val pureRange = AddrRange(rangeStart.offset, rangeEnd.offset)
    val pureHarvest = allHarvested.mapNotNull {
        val name = (it.decl as? SymbolDecl.Global)?.name ?: return@mapNotNull null
        HarvestedAddr(name, ctx.resolver.resolve(name)?.offset)
    }
    when (val r = BssCoverageDecision.classify(pureRange, pureHarvest)) {
        is CoverageResult.NoCoverage -> ctx.sink.log("stabs-no-coverage", "@ ${rangeStart}..${rangeEnd}: no stabs records cover this range")
        is CoverageResult.Covered    -> r.coverers.forEach { ctx.sink.log("stabs-coverage", "@ ${rangeStart}..${rangeEnd}: covered by ${it.symbolName}") }
    }
}
```

b) After all globals are applied in `applyAllSymbols` (second loop, around lines 289-302), iterate the `.bss` block (via `program.memory.getBlock(".bss")` — skip if null); for every address that has no `Symbol` defined and no `Data` defined, call `dumpStabsAtAddressRange(addr, addr + 4)`. This produces the `stabs-no-coverage @ 0x46702c` lines AC7 requires.

c) In `applyGlobal`, the unresolved-symbol branch (lines 426-429) currently logs but doesn't increment the global-skipped counter. Add: `ctx.diagnostics.recordGlobal(decl.name, "skipped", dtKind = "unknown", reason = "unresolved-symbol")`.

**Testing (Kind 1 + Kind 2 split):**
- Pure decision is covered by `BssCoverageDecisionTest.kt` (above).
- Adapter is covered by Phase 8's `bss0x46702cNamedOrDocumented` spot-check (Kind 2, real Ghidra headless).

**Verification:**
- Run: `./gradlew test --tests "ghistabs.importer.BssCoverageTest"`
- Run: `./gradlew integrationTest --tests "ghistabs.XapasmcsrIntegrationTest"`
- Expected: both pass (integration skips with assumption if binary absent).

**Commit:** `feat(importer): .bss coverage diagnostic + stabs-no-coverage log`
<!-- END_TASK_2 -->
<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (task 3) -->
<!-- START_TASK_3 -->
### Task 3: Per-DataType-kind coverage + local-add success ratio + scoped-locals memo

**Verifies:** stabs-importer-fixes.AC8.1, stabs-importer-fixes.AC8.2

**Files:**
- Modify: `src/test/kotlin/ghistabs/XapasmcsrIntegrationTest.kt:90-104` (real-binary test)
- Create: `docs/implementation-plans/2026-05-29-stabs-importer-fixes/notes-scoped-locals.md`
- Modify: `src/main/kotlin/ghistabs/importer/StabsImporter.kt:351-368` (`applyLocal` — add success counter)

**Implementation:**

a) **AC8.1 — integration assertion**: in `XapasmcsrIntegrationTest`, after analyzer runs, iterate `program.listing.getDefinedData(true)` and bucket by `data.dataType`'s class hierarchy: `Structure`, `Array`, `Union`, `Pointer`, `Enum`, `TypeDef`, `FunctionDefinition`, otherwise-primitive. Assert at least one Data item exists per bucket (modulo legitimately-absent kinds — e.g. if the binary genuinely has no global Unions, exempt that bucket via a documented allow-empty list in the test).

b) **AC8.2 — Kind 2 headless coverage**: the createData-failure path triggers naturally when the real binary has overlapping code regions. Phase 8's headless regression suite asserts `global-skipped` counter > 0 with reason `create-data-failed` recorded, and asserts no analyzer crash on `xapasmcsr.exe`. **No mock-based `ApplyGlobalErrorTest`** — the convention forbids `Listing` mocks.

c) **Local-add success counter (new)**: in `applyLocal` at line 357 (after `func.addLocalVariable(lv, source)` returns without throw), add `ctx.diagnostics.inc("local-var-add-success")`. The existing `local-var-error` counter at line 367 already increments via Phase 1's BookmarkSink instrumentation. Integration test reads both and writes the ratio to `build/test-output/local-add-ratio.txt` — NO assertion threshold in Phase 7; Phase 8 sets the bar after AC9 fix.

d) **Scoped-locals memo** (`notes-scoped-locals.md`):

```markdown
# Scoped Local Variables in ghidra-stabs — Real-Data Memo

**Source:** `src/main/kotlin/ghistabs/stabs.log` (baseline run, 499 [Stabs] log lines).

## Wiring (already shipped)

Stack locals are applied via `LocalVariableImpl(name, type, stackOffset, program, source)` + `func.addLocalVariable(...)` at `StabsImporter.kt:355-356`. Register locals are deferred (logged as `regparam-deferred`).

## Actual failure modes (66% of all warnings)

`local-var-error` is the dominant log tag — **331 of 499 lines (66%)**. Two failure modes dominate:

### Mode 1: Parameter-vs-Local `this` collision
Pattern: `A Parameter symbol with name 'this' already exists in namespace <Class>`. Counts: 27 in `Clone`, 23 in `CParser`, 20 in `ParseSymbol`, 18 in `CSymTab`, 16 in `ParseOperand`, 15 in `CRepresentation`, 9 in `ParseInstruction`, 9 in `GetNextTok`.

Root cause: `replaceParameters()` at `StabsImporter.kt:268` has already installed `this` as a parameter from the `N_PSYM` record. GCC then emits `this` AGAIN as an `N_LSYM` local record (gcc-3.4 quirk — see GDB `dbxread.c:process_one_symbol`). `applyLocal` tries to add it via `addLocalVariable`, Ghidra rejects since a parameter with that name exists.

### Mode 2: Loop-var shadow collision
Pattern: `A Local Var symbol with name 'i' already exists in namespace <Func>`. Examples: `__size`/`__osize` (11 each) in `ParseOperand`, `i`/`j` in `EmitSymtab`. Root cause: nested lexical scopes (`for (int i = 0; ...) { ... for (int i = 0; ...) { ... } }`) where each emits an `N_LSYM` record for `i`. Ghidra's `Function` model has one flat local-variable namespace per function, so the second add fails.

## Phase 7 stance

Do not fix — Phase 8 AC9 fixes both modes:
- **Mode 1 fix:** before `addLocalVariable`, check `func.getParameter(name) != null` → skip silently (the parameter slot already covers the symbol).
- **Mode 2 fix:** before `addLocalVariable`, check `func.localVariables.any { it.name == name }` → skip silently (first-defined wins; Ghidra's flat-locals model can't distinguish scopes anyway).

Both skips emit `local-var-skipped-dup` at debug level (not `local-var-error`), keeping AC9.1's ≥90% reduction realistic: 331 × 0.10 ≈ 33 surviving genuine warnings.

## Out of scope (deferred to v1.1+)

- Register-local mapping: stabs register numbers need a per-arch table (XAP2, x86, etc.) → Ghidra register set. Currently `regparam-deferred` logged, no add attempted.
- Nested-scope shadowing visibility: Ghidra has no way to distinguish `i` in two sibling scopes; would need synthetic disambiguation (`i_2`, `i_3`) which conflicts with stabs-name preservation goals.
```

**Verification:**
- Run: `./gradlew test` — pure unit tests pass.
- Run: `./gradlew integrationTest --tests "ghistabs.integration.StabsAnalyzerRegressionTest"` — Kind 2 assertions pass (integration skips if binary absent).

**Commit:** `test(importer): per-DataType-kind global coverage + scoped-locals memo`
<!-- END_TASK_3 -->
<!-- END_SUBCOMPONENT_B -->

**Phase 7 done when:**
- Zero `Stabs scope locals: ` (with empty body) plate comments on `xapasmcsr.exe`.
- Per-DataType-kind global coverage verified across primitive/enum/typedef/pointer/funcptr/structure/array/union (or allowed-empty buckets documented).
- `0x0046702c` has either a name OR a documented `stabs-no-coverage @ 0x46702c` log line.
- Per-scope local filtering works on the synthetic-corpus nested-scope test.
- `notes-scoped-locals.md` committed citing real log data.
- `apply-error` regression test passes; no crash on createData failure.
- `local-var-add-success` and `local-var-error` counters reported as a ratio in test output (no threshold yet; Phase 8 sets it).
