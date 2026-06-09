# TODO

Last triaged: 2026-06-03.
All entries verified against the current `xapasmcsr.exe` regression run
(`src/test/resources/logs/xapasmcsr.log`,
`src/test/resources/harvests/xapasmcsr-harvest.json`).

## Open
- [ ] SymbolDecl vs TypeDecl? 
- [ ] purge forbidden words from git history: csr/qualcomm/adk/xapasmcsr/appquery/bose/qc35/bluecore
- [ ] stop copying test resources to build/
- [ ] figure out Junit 4 vs 5 nonsense (intellij complains)
- [x] handle bool better (fixed ?)
- [ ] ghidra messes up namespaces when demangling names that have :: within <>
- [ ] global/statics are not renamed, they get their name from PE symbols which have a preceding undersocre
- [ ] **gcc per-BINCL include-stack vs our flat `fileNumToHeader`**.
  After the N_GSYM/N_PSYM canonicalisation fix (see Done), every global
  carrying inline-defined types DOES apply, but cross-CU element refs
  can still mistype. Concrete case: `BranchInstructions` is a 16-element
  array (correct length, applied as Data), but the element resolves to
  a builtin `int` instead of the real `EnumInstToken` enum. `inst.cpp`'s
  Ref is `(148, 3)` — slot 148 is an N_EXCL placeholder for sourceloc.h.
  `EnumInstToken` lives at `(143, 3)` in Keywords.cpp — file 143 is an
  N_SOL-tracked `stl_multiset.h` slot. gcc's intent: walk the BINCL stack
  to find the right shared (filename, checksum) and look up "type 3" there.
  Our `headerForFileNum(localId.cu)` returns whichever single slot we
  allocated; we don't model the include stack. Fix needs a stack-aware
  resolver or a content-keyed cross-CU type index that doesn't depend on
  file slot at all.

- [ ] need to tally placeholders that were never replaced in the diagnostics (fwd-decl)
- [ ] is there any point left to rawByIdSnapshot ?

- [ ] **[algo-audit] D1: Fix forward-EXCL placeholder divergence** —
  Ref: stabs-canonicalization.md §6, §4 deviation D1.
  `HeaderRegistry.recall()` creates a non-globally-registered placeholder when N_EXCL
  precedes N_BINCL. The placeholder is never patched when the real BINCL arrives, so
  types attributed to the placeholder get different GlobalTypeIds than the real header
  → hash collisions in appendAsts() (207 in xapasmcsr). Fix: when a real BINCL arrives
  for (filename, checksum) and a placeholder already exists, replace the placeholder
  with the real HeaderFile in all affected IncludeContext instances.
  [out of scope for stabs-algo-audit plan]

- [ ] **[algo-audit] D2: Update Attribution.categoryFor() for HeaderSource** —
  Ref: stabs-canonicalization.md §7.1, deviation D2.
  `Attribution.categoryFor()` does not handle HeaderSource distinctly from CUSource.
  Header-attributed types fall into the multi-CU heuristic branch, producing
  `/headers-untracked/` or `/instantiations/` categories rather than a header-aware path.
  Fix: add a HeaderSource → `/headers/<filename_without_ext>/` routing branch.
  [out of scope for stabs-algo-audit plan]

- [ ] **[algo-audit] D3: Patch forward-EXCL placeholders when real BINCL arrives** —
  Ref: stabs-canonicalization.md §7.2, deviation D3.
  `preSeedHeaders()` two-pass pre-seeding does not patch forward-EXCL placeholders
  when the BINCL arrives. When HeaderRegistry.recall() creates a placeholder for a
  forward EXCL, and a later BINCL arrives, the new real HeaderFile should replace
  the placeholder in all IncludeContext instances that reference it.
  [out of scope for stabs-algo-audit plan]

- [ ] (partial) **dedup code with RTTIGccClassRecoverer / GccTypeinfo /
  RecoverClassesFromRTTIScript** — `RecoveredClassHelper` lives in
  `ghidra_scripts/classrecovery/` (Ghidra script source, not on Ghidra's
  compiled classpath) so a compiled extension can't import it. Full
  delegation would require vendoring ~9 kLOC of script source (Apache-2.0,
  legal but heavy). Convention-level compatibility is done (see Done
  below); we keep our own vtable construction.
- [ ] fix log capture in tests
    - should we use Msg.debug/info/warn/error etc instead of MessageLog ?


- [ ] **invoke `GnuDemangler` directly on stab-derived labels**. Pinned by
  the disabled test `freeFunctionSymbolGetsDemangled`. Root cause: Ghidra's
  demangler is a `BYTE_ANALYZER` that runs once at priority ~897 over the
  loader-added symbol set. We now run at `LOW_PRIORITY` (10000, see
  `StabsAnalyzer.kt`) so labels created via `recordFromStab` only appear
  after the demangler has finished, and Ghidra does not re-trigger the
  demangler for later-added symbols. Fix options:
    1. Call `DemanglerUtil.demangle(name)` in `ProgramAddressResolver.recordFromStab`
       and create the label under the demangled form when it parses.
    2. Add a follow-up pass at the end of `StabsImporter.run` that walks
       all IMPORTED labels starting with `_Z`/`__Z` and demangles each.
       Symptom on xapasmcsr.exe: `_Z11RegToBinary12EnumRegToken` stays mangled.
       Behaviour is identical in both AFTER and CONCURRENT modes — initial
       hypothesis that it was a concurrency race was wrong.

- [ ] **check the logic actual GDB uses to deduplicate / canonicalize
  types and classes**, see if our algorithm makes sense or if we need to
  change or simplify it.

### Likely still broken

- [ ] **`vfptr-collision` on `CLexStream`** —
  `[vfptr-collision] CLexStream: cannot place {vfptr} at +0 (occupied by _base_unknown_0)`.
  CLexStream's base type is in a header gcc didn't fully resolve, so the
  base-insertion path emitted an `_base_unknown_0` synthetic placeholder.
  `firstPolymorphicBase` then can't recognise the placeholder as polymorphic,
  so VfptrDecision falls through to `CollisionAt`. Either teach
  `resolveBaseAstStatic` to follow the synthetic placeholder, or detect the
  case and emit `vfptr-inherited-from-base`. Two remaining
  `[vfptr-collision]` entries on the binary, both CLexStream.

- [ ] **demangled method names sometimes replaced by mangled** —
    - issue related to demangler analysis running simultaneously
    - take with a grain of salt: observed on some renamed methods; the displayed name for non-ctor/dtor
      methods comes from `displayNameFor` and falls back to `m.name` when
      the input mangled name isn't a ctor/dtor pattern, but the user wants
      the fully demangled form (e.g. `Dump`, not `_ZN6DSInst4DumpEPt`).
      Plug Ghidra's `GnuDemangler` and use the demangled form as fallback.

- [ ] **`[class-apply-error]` on long templated `_Rb_tree<…>` names** (216 entries)
  — Ghidra rejects symbol names with `<`/`>`/space. Each rejected
  templated _Rb_tree<…> blocks the project iterator typedefs that wrap it
  (`symtab_iterator_const`, `token_vector_iterator`,
  `symbol_data_map_iterator`, etc. — currently failing as
  `[dangling-ref] … [forward-same-cu]`, 9 entries). Sanitise long
  template names (replace illegal chars with `_`) before creating the
  symbol, or use Ghidra's `SymbolUtilities.replaceInvalidChars`.

### Diagnostic noise / cosmetic

- [ ] **`_Value_type` / `_ValueType` cross-CU dangling-refs** (37 of the 53
  remaining `dangling-ref` entries) — libstdc++ `<bits/type_traits.h>`
  template-internal typedefs. Each template instantiation gets its own
  per-CU canonical id and the typedef body references a TypeId in a
  different canonical CU. Genuine STL noise; cleanup would require
  cross-CU resolution by name+hash for template-parameter typedefs.

- [ ] **3 remaining `[class-not-struct]` entries** —
  `_Rb_tree<…>` template instantiations whose mangled name was rejected
  earlier (downstream of `class-apply-error` above).

### Quality / scope

- [ ] **use Ghidra's GnuDemangler** instead of the hand-rolled
  `VtableSymbolCandidates.itaniumMangleClassName` — currently rebuilds
  the mangled name in Kotlin to look up `_ZTV<class>`. Ghidra's demangler
  could match a class to existing symbols by demangling, side-stepping
  templated-name edge cases.

- [ ] **define structures in the `.stab` section itself** — turn
  StabRecord into a Ghidra Structure overlay so the disassembler view of
  `.stab` shows decoded fields (with refs into `.stabstr` and back into
  code/data for symbols).

- [ ] **`ContentHash.hashDecl` could be a `data class` `hashCode()`** —
  the rest of the AST is already a `data class`; only this one hand-rolled
  hash remains.

### Plan / docs hygiene

- [ ] Sweep tests for trivially-passing assertions (`assertTrue(true)`).
- [ ] Sweep code docs for stale references to "Phase 5", binary names,
  or project-specific types; keep them generic to the importer's design.
- [ ] Add kdoc to `Harvester`, `TypeRegistry`, and `ClassBuilder` covering
  the multi-pass pipeline (Pass A = harvest, materialiseAll = build types,
  applyAllSymbols = apply to program), placeholders, byHash dedup, and the
  cross-CU canonicalisation/`(id, name)` split.
- [ ] README/`docs/` short explainer for the hairy bits: CU canonicalisation,
  placeholders + pre-add to DTM, byHash dedup, the `(TypeId, name)` map,
  and the BINCL collision case.
- [ ] Identify code duplication and vestigial helpers; consolidate
  single-class files into siblings (e.g. small data records that travel
  with `ClassBuilder`).

## Done

### This session (2026-06-02 → 2026-06-04)

- [x] **N_GSYM / N_PSYM / N_RSYM / N_FUN type-decl canonicalisation** —
  globals (and function params, locals, signatures) were parsed and
  stored with RAW local-form TypeIds; only N_LSYM TaggedType/Typedef
  bodies went through `canonicalizeTypeDecl`. Result: a global like
  `BranchInstructions:G(1,1103)=ar(38,4);0;15;(148,3)` ended up with a
  `Ref(148, 3)` that never matched any canonical typeAst id, so
  `dataTypeFor` returned null and the symbol stayed untyped. Now
  `Harvester.harvestSymbol` and the N_FUN/N_PSYM/N_RSYM/N_LSYM paths
  apply the same canonicalisation to symbol-side TypeDecls. xapasmcsr.exe:
  `global-applied` jumped from 56 → 70 (and `BranchInstructions`
  acquired a 16-element array shape). Element-type resolution still
  incomplete — see the include-stack TODO above.

- [x] **`canonicalKey()` filename scoping** — the no-checksum branch
  used `originatingCu` bare, which made every non-checksummed header
  first seen in the same CU collide. Now `"${originatingCu}#${filename}"`,
  matching the structure of the checksummed-header form and letting
  `canonicalTypeId` collapse to a single rule
  (`header?.canonicalKey() ?: "$cuFile#file${localId.cu}"`).

- [x] **Array TypeDecl: derive length from `indexType.Range` when
  `decl.length == null`** — gcc routinely omits the explicit length and
  encodes the array bound only via the index Range
  (`array of EnumInstToken indexed [0..15]` → 16 elements). Old code
  returned null on either condition; now elements fall back to
  `ByteDataType` on unresolved-element and length cascades
  `decl.length → indexType.max - min + 1 → 1`. `Undefined1` was a worse
  fallback because Ghidra's data-reference analyzer reliably re-coalesces
  arrays-of-undefined into individual `undefined4` chunks based on
  scalar refs in code, even after CONCURRENT-mode apply.

- [x] **CONCURRENT-mode global-apply race** — `applyGlobal` now uses
  `DataUtilities.createData(..., CLEAR_ALL_CONFLICT_DATA)` instead of
  `Listing.clearCodeUnits + createData`, so the autoanalysis `undefined4`
  placeholder we race against in CONCURRENT mode is evicted explicitly.

- [x] **Duplicate `this` parameter on class methods** — the
  `openFunctions` loop applied gcc's N_PSYM `this` first (typically
  mistyped, e.g. `int`); the subsequent `ClassBuilder.reparentMethod`
  set `__thiscall` but Ghidra couldn't fully evict the leftover slot,
  so display showed `(<Class>* this, <primitive> this, ...)`. Now the
  openFunctions loop filters out N_PSYM params literally named `this`
  (calling-convention territory). `reparentMethod` switched to
  `DYNAMIC_STORAGE_ALL_PARAMS` with an explicit `this: <Class>*`
  ParameterImpl prepended, so we own the entire param list — no
  auto-injection guessing.

- [x] **Harvest-side diagnostic counters** —
  `harvest-records-read/parsed/-parse-errors`, `harvest-functions`,
  `harvest-symbols`, `harvest-globals`, `harvest-statics`,
  `harvest-typeAsts` with per-kind breakdown, `harvest-cus`,
  `harvest-typeAsts-{unique,dup}-by-id`. Surfaces "how much did we even
  see?" before any apply-side filtering. Counter `vftable-slot-fallback-untyped`
    + `method-param-unresolved` track signature-resolution health.

- [x] **vftable convention compatibility with shift-S workflow** —
  `ClassBuilder.buildAndApplyVtable` now:
    - puts vftable + vtable structs under
      `/ClassDataTypes/<Class>/` (matches `RecoveredClassHelper.DTM_CLASS_DATA_FOLDER_NAME`);
    - renames `<Class>_vmethods` → `<Class>_vftable`;
    - types each slot as `Pointer → FunctionDefinition(method-signature)`
      via `buildVirtualSlotType`, with the auto-injected `this: Class*`
      rewritten to `void*` so the pointer type is reusable across
      inheritance (same trick `RecoveredClassHelper` uses, L4602);
    - adds a `vftable` label at the `_ZTV<class>` address inside the
      class namespace so the helper's substring filter
      (`vftableSymbol.getName().contains("vftable")`) accepts us.
      Pinned by new test `dcinstShiftSCompatibility`. Counter
      `vftable-slot-fallback-untyped` = 8 on xapasmcsr.exe — the rest get
      typed function-pointer slots.

- [x] **`DemanglerReplacer` candidate filter** — when both a `/Demangler/Foo`
  stub and a real `/proj/Foo` exist, the old `nameIndex` saw 2 matches and
  rejected both via `candidates.size == 1`, leaving the stub orphaned.
  Now excludes `/Demangler/...` entries from the index; stubs are matched
  to non-stub replacements as intended.

- [x] **`StabsAnalyzer` priority** — was `AnalysisPriority(200)` (BLOCK
  phase, very early). Now `LOW_PRIORITY` (10000) so we run strictly after
  Ghidra's demangler (897) and every standard analyzer.

- [x] **Regression harness covers both execution-order modes** — the
  harness now parameterises by [Mode] (CONCURRENT vs AFTER); subclasses
  `StabsAnalyzerAfterTest` and `StabsAnalyzerConcurrentTest` exercise
  both. CONCURRENT schedules the analyzer via `mgr.scheduleOneTimeAnalysis`
  so it actually fires inside `startAnalysis`. Mode-specific tests
  (counter-driven `inheritanceWasApplied`, demangler-stub residue) live
  in the AFTER subclass since CONCURRENT runs the analyzer through
  `MessageSinkAdapter` and loses the CapturingSink counters.

- [x] **strip implicit `this` and trailing void sentinel from Method
  params** — gcc 3.x `#`-form member function types encode
  `[this_ptr, p1, ..., pN, void_sentinel]`. Without stripping, Ghidra's
  `__thiscall` auto-injected `this` collided with the stab's `this`,
  yielding `(XapArgInst *this, uint this, uint dest)`. Strip leading
  param only when `func.getParameter(0)?.name == "this"` (i.e. cspec
  accepted `__thiscall` and injected its own `this`), and trailing void
  via post-resolution `dropLastWhile { it is VoidDataType }`.

- [x] **`__thiscall` calling convention + `this: <Class>*`** — `0e51c73`.
  `reparentMethod` now handles `TypeDecl.Method` (not just `FunctionT`)
  and marks the function `__thiscall` BEFORE replacing parameters, so
  Ghidra auto-injects the typed `this`. Regression: `methodsUseThiscall`.

- [x] **vptr-points-at-`+0`** — `3513f77`. Vtable split into
  `<Class>_vmethods` (function pointer array — what `{vfptr}` points to)
  and `<Class>_vtable` (full Itanium record: `offset_to_top` + `rtti` +
  embedded vmethods at `+2*ptrSize`; applied at `_ZTV<class>`).

- [x] **CParser / Token_Type / EAsm dropped at materialiseAll** — `e9be41b`.
  Each CU emits its own private types inside a shared BINCL block, reusing
  local file slots — those all canonicalise to the same `(N, n)`.
  `materialiseAll` now takes `List<TypeAst>` (was `Map` via `associateBy`)
  and uses `(TypeId, name)`-keyed placeholders/byId so each distinct named
  type still reaches the DTM; byId-by-id is kept for Ref lookups (first
  writer wins). Test: `cparserMaterialised`.

- [x] **CSymLexStream attributed to `/std/stl_heap/`** — `3f44182`. Root
  cause: `currentCu` was being overwritten on N_SOL (a *line-number*
  source-file switch), so every type emitted while gcc was line-tracking
  through an STL header got filed under that header. Fix: don't update
  `currentCu` on N_SOL.

- [x] **`[class-not-struct]` spam (705× → 3×)** — `29a2b90`. ClassBuilder
  loop now dedupes ASTs by name and uses the union of cuFiles for
  `Attribution.categoryFor` (matching what `materialiseAll` used to seed
  the placeholder). `Attribution.categoryFor` sorts `definingCUs` before
  scanning so set-iteration order can't make sibling calls disagree.

- [x] **ExprInst empty / EnumInstToken missing** — `c442218`. Each local
  file slot in a CU now gets its own canonical CU
  (`<cuFile>#file<localFile>`); previously all local files keyed on
  `cuFile`, so `EnumInstToken:t(2,3)=…` collided with `long int:t(1,3)=…`
  and was eaten by `associateBy`. Struct/Union placeholders now also
  pre-added to the DTM so mutations land on the DTM-resident object.
  Tests: `exprInstHasComponents`.

- [x] **`apply-error-no-function` (489 → 0)** — `4804887`. When the stab
  asserts a function exists but autoanalysis missed it (typical for ctors
  only called from `__static_initialization_and_destruction_0`), fall back
  to `CreateFunctionCmd`. Also adds Itanium implicit-trivial-special-member
  filter (`_ZN…(C[123]|D[012]|aS)E(v|RKS_|OS_)`) so 423 phantom
  unresolved-method entries become `method-implicit-not-emitted` instead.

- [x] **Exhaustive `StabType` handling + silenced line-noise** — `7b22264`.
  `Harvest.passA`'s `when` is now exhaustive; known-irrelevant types
  (N_SLINE, N_OPT, Apple/Sun cross-toolchain codes) bump a silent counter
  via `BookmarkSink.bump`; `StabType.UNKNOWN` logs loudly with the raw
  byte. Added the missing codes from `binutils/include/aout/stab.def`.
  Coalesced contiguous .bss no-coverage runs. Log size 32 k → 3 k lines.

- [x] **PE/Cygwin underscore demangling in resolver** — `7b22264`.
  `ProgramAddressResolver.resolve` falls back to `_<name>` (and so
  `__<name>` for `_Z…` Itanium symbols). `global-applied` 14 → 50;
  `unresolved-symbol` 1234 → 1116.

- [x] **DCInst inheritance + transitive vtable** — `51f3bf4`.
  `resolveBaseAstStatic` follows `InlineDef(id, XRef body)` via the id
  first; `collectInheritedVirtuals` walks the full inheritance chain so
  derived vtables include all transitively-inherited virtuals (e.g.
  `Inst::GetOffset` ends up in DCInst's vtable).

- [x] **kotlinx.serialization for baselines** — `ffaa808`.
  `BaselineLoader` switched from a regex JSON parser to
  `kotlinx.serialization`; dead `BaselineCompare` + test deleted.

### Earlier sessions

(Already-complete entries kept here for traceability — see git log for
full context.)

- [x] Cross-CU TypeId collision (`(1, n)` collision across CUs) — `4b21a6c`.
- [x] ClassBuilder lookup bug (`dataTypeFor` doesn't handle `TypeDecl.Struct`) — `4b21a6c`.
- [x] Synthesised placeholder for unresolved base types — `4b21a6c`.
- [x] `mingw` compiler pspec for xapasmcsr — `778ea50`.
- [x] Vtable types are produced (18× on xapasmcsr) — `4b21a6c` and follow-ups.
- [x] `_vptr$Inst` field type was `__Normal` — fixed by canonicalisation.
- [x] Function param names + locals — ordering: importer runs after autoanalysis.
- [x] "Function body must contain the entrypoint" — same ordering.
- [x] Replace ad-hoc `Baseline` parsing with kotlinx.serialization.
- [x] Diagnostic dump of the entire AST database (`Harvest.kt` JSON).

## Issue references

- **#40** (Java 21 × Ghidra 11
  `ObjectInputFilter.Config.setSerialFilterFactory` conflict) — resolved
  by `ae5145d`. The `integrationTest` task now passes
  `-Djdk.serialFilterFactory=ghidra.framework.remote.GhidraSerialFilterFactory`
  at JVM startup, matching Ghidra's own `gradle/javaTestProject.gradle`.
