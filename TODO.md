# TODO

Last triaged: 2026-06-10.
All entries verified against the current `xapasmcsr.exe` regression run
(`src/test/resources/logs/xapasmcsr.after.log`,
`src/test/resources/harvests/xapasmcsr-harvest.json`).

## Open

### Admin / scope

- [ ] add any missing documentation for Stabs tokens in the parser (similar to what was done for N_*)
- [ ] take N_SO "directory" entries into account (two N_SO in a row → the first is the directory
  location of the header, store it in a field inside CUSource)
- [ ] does the TypeDecl / SymbolDecl split make sense, or should they merge?
- [ ] purge forbidden words from git history: csr/qualcomm/adk/xapasmcsr/appquery/bose/qc35/bluecore
- [ ] stop copying test resources to build/
- [ ] figure out Junit 4 vs 5 nonsense (intellij complains)
- [ ] fix log capture in tests — should we use Msg.debug/info/warn/error etc instead of MessageLog?
- [ ] **investigate N_RSYM vs N_LSYM register local semantics** (Harvest.kt) — when parsing N_RSYM
  records, determine how register-based locals differ from N_LSYM-declared stack locals; currently
  unclear if the distinction matters for type resolution.
- [ ] **check the logic actual GDB uses to deduplicate / canonicalize types and classes** — see if
  our algorithm makes sense or if we need to change or simplify it.

### Forward-EXCL placeholder divergence (D1 / D3 / include-stack)

- [ ] **D1 / D3: patch forward-EXCL placeholders on BINCL arrival** —
  Ref: stabs-canonicalization.md §2.3, §6, §7.2; deviations D1 and D3.
  When N_EXCL precedes N_BINCL for the same (filename, checksum),
  `HeaderRegistry.recall()` creates a non-globally-registered placeholder
  `HeaderFile(originatingCu=null)`. When the real BINCL arrives later,
  `getOrInsert()` creates a distinct `HeaderFile` instance — the two never
  merge, so types attributed to the placeholder get different GlobalTypeIds
  than types attributed to the real header (207 hash collisions in
  xapasmcsr). Concrete symptom: `BranchInstructions` 16-element array
  resolves element type to wrong slot.
  Fix options:
    1. On real BINCL arrival, replace the placeholder in all affected
       `IncludeContext` instances. Closest to the spec, requires tracking
       which IncludeContexts referenced the placeholder.
    2. Switch to a content-keyed cross-CU type index independent of file
       slot. Heavier refactor but sidesteps the placeholder model entirely.
  Should also add a diagnostic counter for unreplaced placeholders so we
  can spot regressions.

- [ ] **gcc per-BINCL include-stack vs our flat `fileNumToHeader`** —
  Ref: stabs-canonicalization.md §2.5, §4.1.
  gdb uses `this_object_header_files[]` (gdb/stabsread.c
  `add_new_header_file()`, `add_old_header_file()`) — a per-CU stack of
  header contexts. Our flat `IncludeContext.fileNumToHeader` doesn't model
  re-entry stacks for the same header within one CU. Whether this matters
  in practice depends on whether D1/D3 (above) is enough; if it is, the
  per-CU stack is superseded.

### Likely still broken

- [ ] **`vfptr-collision` on `CLexStream`** (2 entries in current log) —
  `[vfptr-collision] CLexStream: cannot place {vfptr} at +0 (occupied by _base_unknown_0)`.
  CLexStream's base type is in a header gcc didn't fully resolve, so the
  base-insertion path emitted a `_base_unknown_0` synthetic placeholder.
  `firstPolymorphicBase` then can't recognise the placeholder as
  polymorphic, so `VfptrDecision` falls through to `CollisionAt`. Either
  teach `resolveBaseAstStatic` to follow the synthetic placeholder, or
  detect the case and emit `vfptr-inherited-from-base`.

### Quality / scope

- [ ] **use Ghidra's `GnuDemangler` for `VtableSymbolCandidates`** instead of
  the hand-rolled `itaniumMangleClassName` — currently rebuilds the mangled
  name in Kotlin to look up `_ZTV<class>`. With the ClassBuilder demangler
  refactor in place, the natural next step is iterate existing `_ZTV…`
  symbols, demangle each, and match by class — sidestepping templated-name
  edge cases.

- [ ] **let `DemangledObject.applyTo` create the namespace hierarchy end to
  end on the method path** — `ClassBuilder.namespaceChainFromMangled` now
  walks the demangled namespace chain manually, but `applyTo` could do that
  plus the rename in one call. If we adopt it, `reparentMethod` reduces to
  "call applyTo, then set thiscall + explicit-this param list". Verify
  whether applyTo's symbol-creation semantics conflict with our
  `IMPORTED`-source / primary-label invariants before switching.

- [ ] (partial) **dedup code with `RTTIGccClassRecoverer` / `GccTypeinfo` /
  `RecoverClassesFromRTTIScript`** — `RecoveredClassHelper` lives in
  `ghidra_scripts/classrecovery/` (script source, not on Ghidra's compiled
  classpath), so a compiled extension can't import it. Full delegation
  would require vendoring ~9 kLOC of script source (Apache-2.0, legal but
  heavy). Convention-level compatibility is done; we keep our own vtable
  construction.

- [ ] **define structures in the `.stab` section itself** — turn
  `StabRecord` into a Ghidra Structure overlay so the disassembler view of
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
  cross-CU canonicalisation / `(id, name)` split.
- [ ] README/`docs/` short explainer for the hairy bits: CU canonicalisation,
  placeholders + pre-add to DTM, byHash dedup, the `(TypeId, name)` map,
  and the BINCL collision case.
- [ ] Identify code duplication and vestigial helpers; consolidate
  single-class files into siblings (e.g. small data records that travel
  with `ClassBuilder`).

## Done

### TODO triage (2026-06-10)

- [x] **naive `name.split("::")` breaks on `::` inside template `<…>`** —
  fixed by `ghistabs/util/QualifiedName.split`, a depth-aware splitter
  that tracks `<>`/`()` nesting. Wired into `ClassBuilder` (as the
  fallback for type-only stabs) and `VtableSymbolCandidates`.

- [x] **drop non-standard `_C1`/`_C2`/`_C3`/`_D0`/`_D1`/`_D2` ctor/dtor
  display suffixes** — `ClassBuilder.displayNameFor` now emits the
  demangled source-form name (`Foo` / `~Foo`); multiple Itanium variants
  share that name and Ghidra disambiguates by address.

- [x] **thread mangled names through to ClassBuilder so Ghidra's
  `DemanglerUtil` handles namespace splitting** — `ensureClassNamespace`
  prefers `namespaceChainFromMangled(m.mangled)`, walking
  `DemangledObject.getNamespace()` parent-chain to build the GhidraClass
  hierarchy without string-splitting. Falls back to the depth-aware
  splitter when no mangled method is available. Follow-up "use
  `DemangledObject.applyTo` end-to-end" tracked separately under Quality.

- [x] **global/statics not renamed (PE-loader underscore wins)** — new
  `StabsImporter.ensureStabLabel(addr, name)` creates an `IMPORTED`
  label with the stab's demangled name and promotes it to primary via
  `SetLabelPrimaryCmd`, so the demangled form displays over `_<name>`.
  Called from `applyGlobal` and `applyStatic`.

- [x] **`_Value_type` / `_ValueType` cross-CU dangling-refs** — gone.
  Current `xapasmcsr.after.log` shows `dangling-ref = 0` and zero
  occurrences of either name. Cleanup fell out of the canonicalisation
  work (commits 3f2e566..3a40357).

- [x] **demangle function names from stab records** — stale. The
  end-of-import `demangleMangledLabels()` pass already converts `_Z…`
  labels via Ghidra's demangler; the harvest legitimately stores raw
  stab content. No remaining symptom in current runs.

- [x] **D5: rawByIdSnapshot vestigial documentation** — removed the
  three stale references in `TypeRegistry.kt` (`dataTypeFor` kdoc + two
  inline comments) and the one in `ResolverDecision.kt`. Field already
  gone since commit 7d2bc56; only the descriptive text was stale.

- [x] **D7: `AttributionTraceDump` updated for header model** —
  empty-result message now reads "no attribution trace recorded in this
  run" instead of the misleading "/std/* in this run"; kdoc explains
  that traces cover both `/std/*` and `/headers/*` (D2). Tests updated.

- [x] **[algo-audit] D2: Attribution.categoryFor() routes HeaderSource to /headers/<basename>/** —
  Ref: stabs-canonicalization.md §7.1, deviation D2.
  Added a routing branch (Attribution.kt step 3) that fires when every
  defining source is a `HeaderSource` and they all share the same filename
  basename — single-defining case (the common case for header-attributed
  types) AND multi-defining shared-header case (D1 forward-EXCL placeholders
  produce distinct `HeaderFile` instances for the same physical header;
  attribution still converges). Bumps `attribution-routed-headers` counter
  and records an `AttributionTrace` via the generalised
  `StabsDiagnostics.recordAttributionTrace(..., counter)` helper. Stays
  before the single-CU shortcut so single HeaderSource defs land in
  `/headers/<basename>/` instead of `/<basename>/`. Single-CUSource case
  unchanged. Cross-header multi-defining cases still fall through to the
  multi-CU heuristic (step 5).

- [x] **`_Z11RegToBinary12EnumRegToken` stays mangled** — `demangleMangledLabels()`
  end-of-import pass at `StabsImporter.kt:272–295` walks IMPORTED labels and
  runs `DemanglerCmd` on residual `_Z…`/`__Z…` symbols. Confirmed zero
  `_Z11…` occurrences in `xapasmcsr.after.log`.
- [x] **demangled method names sometimes replaced by mangled** — covered
  by the same end-of-import demangle pass + `StabsAnalyzer` at LOW_PRIORITY.
- [x] **`[class-apply-error]` on templated `_Rb_tree<…>` names (216 entries)**
  — diagnosis was wrong (`<` and `>` are valid in Ghidra symbol names; only
  space is forbidden, and `ghidraName` already strips it via
  `SymbolUtilities.replaceInvalidChars(name, false)`). Current
  `xapasmcsr.after.log` shows 0 `class-apply-error` and 0 `_Rb_tree`
  entries. (Older `xapasmcsr.log` baseline still shows them — it's stale
  by 6 days.)
- [x] **3 remaining `[class-not-struct]` entries downstream of
  class-apply-error** — gone with the above.

### Phase 8 (stabs-algo-audit plan, 2026-06-09)

- [x] **Parsing audit complete** — AC1: Every type expression form (range, array, struct/union, method #-form, XRef,
  InlineDef, pointer, reference, const, volatile, function, complex) has test coverage. Parser edge cases (trailing void
  sentinel, implicit this pointer) tested. Deeply nested InlineDef chains parse correctly (ParserPrimitiveTest,
  ParserClassTest, ParserBugfixTest).

- [x] **Reference document written** — AC2: `docs/notes/stabs-canonicalization.md` complete with all 9 sections (1–8
  spec/algo + 9 architecture audit), 7-item deviation table (D1–D7), and comprehensive spec citations to stabs PDF, BFD
  stabs.c, gdb stabsread.c.

- [x] **KDoc added to key functions** — AC2.4: Harvester, IncludeContext, HeaderRegistry, globalize(), appendAsts()
  annotated with comprehensive KDoc covering the multi-pass pipeline, placeholder handling, byHash dedup, cross-CU
  canonicalisation, and (TypeId, name) mapping.

- [x] **Harvester unit tests added** — AC3: HarvesterGlobalizeTest (identity, recursion, InlineDef, Ref resolution),
  HarvesterAppendAstsTest (XRef replacement, hash collision, first-writer-wins), HarvesterPassATest (
  N_SO/N_FUN/N_GSYM/N_LSYM state machine, N_SOL non-allocation, BINCL/EXCL/EINCL), HarvesterGapTest (untested
  deviations), IncludeContextTest extended (BINCL re-entry).

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
