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
