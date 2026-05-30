# ghidra-stabs Test Requirements

Maps every acceptance criterion in the design to either an automated test or a documented human verification step.

**Test rings:**
- **Ring-1**: pure-Kotlin unit tests, no Ghidra runtime needed (`./gradlew test`).
- **Ring-2**: in-Ghidra-runtime tests using `ProgramBuilder` (`./gradlew test`).
- **Ring-3**: real-binary integration tests, fixture-dependent (`./gradlew integrationTest`, skips if fixture absent).

All test paths are relative to `/home/riton/git/bouse/ghidra-stabs/`.

---

## ghidra-stabs.AC1: Container reading and analyzer lifecycle

| AC | Test | Type | Path | Phase |
|----|------|------|------|-------|
| AC1.1 (read all 12-byte records, `\`-continuation) | `StabReaderTest.singleCu_readsAllRecords` + `…multipleCus_continuationMerges` | Ring-1 unit | `src/test/kotlin/ghistabs/container/StabReaderTest.kt` | P1.T4 |
| AC1.1 (real-binary: 48,341 records on xapasmcsr.exe) | `StabReaderRealBinaryTest.recordCountMatches` | Ring-3 integration | `src/test/kotlin/ghistabs/container/StabReaderRealBinaryTest.kt` | P1.T7 |
| AC1.2 (per-CU stabstr offset trick) | `StabReaderTest.twoCus_perCuOffsetApplied` | Ring-1 unit | same as AC1.1 | P1.T4 |
| AC1.3 (auto-analyzer first run, sets done-flag, second run no-op) | `StabsAnalyzerLifecycleTest.firstRun_setsFlag_secondRunNoOp` | Ring-2 | `src/test/kotlin/ghistabs/StabsAnalyzerLifecycleTest.kt` | P6.T4 |
| AC1.3 + AC1.4 (lifecycle on real binary) | `XapasmcsrIntegrationTest.lifecycleAndIdempotence` | Ring-3 | `src/test/kotlin/ghistabs/XapasmcsrIntegrationTest.kt` | P6.T6 |
| AC1.4 (Re-import action clears flag, idempotent) | `StabsAnalyzerLifecycleTest.reimport_clearsFlag_isIdempotent` + `IdempotenceTest.dtmAndSymbolStateIdentical` | Ring-2 | `StabsAnalyzerLifecycleTest.kt`, `IdempotenceTest.kt` | P6.T4, P6.T5 |
| AC1.5 (no .stab block ⇒ canAnalyze == false, action disabled) | `StabsAnalyzerLifecycleTest.noStabBlock_canAnalyzeFalse` + **HUMAN: Tools menu shows action disabled when stabs absent** | Ring-2 + human | `StabsAnalyzerLifecycleTest.kt` + manual UI check | P6.T4 |

**Human verification — AC1.5 menu disabled state:** open Ghidra, load any binary with no `.stab` block (any stripped PE will do), open `Tools > Stabs`, confirm `Re-import` is greyed out. Justification: `DockingAction.isEnabledForContext` is checked by Ghidra at menu-open time; we can't easily simulate Ghidra's UI traversal in JUnit, so the assertion lives in `isEnabledForContext`'s unit test plus a one-line manual smoke check.

---

## ghidra-stabs.AC2: Parser correctness against Sun + GCC grammar

| AC | Test | Type | Path | Phase |
|----|------|------|------|-------|
| AC2.1 (every descriptor in xapasmcsr.exe golden corpus) | `ParserBugfixTest.goldenCorpusAllParse` | Ring-1 (corpus skipped in CI absent fixture) | `src/test/kotlin/ghistabs/parser/ParserBugfixTest.kt` | P2.T7 |
| AC2.2 (`@s<n>;<inner>` size attributes — `@s8`, `@s16`, `@s64`) | `ParserPrimitiveTest.sizeAttribute_8_16_64` + `BuiltinTableTest.sizeAttrMappingToBuiltin` | Ring-1 | `src/test/kotlin/ghistabs/parser/ParserPrimitiveTest.kt`, `src/test/kotlin/ghistabs/builder/BuiltinTableTest.kt` | P2.T5, P3.T4 |
| AC2.3 (`R<n>;<size>;0;` complex-type — `R3`, `R4`, `R5`) | `ParserPrimitiveTest.complexFloatDoubleLongDouble` + `BuiltinTableTest.complexMappingToGhidra` | Ring-1 | same as AC2.2 | P2.T5, P3.T4 |
| AC2.4 (full C++ class grammar: inheritance, methods, voff, `~%`, statics) | `ParserClassTest.{plainStruct, singleInheritance, vtableMarker, methodWithMangled, virtualMethod, staticField}` | Ring-1 | `src/test/kotlin/ghistabs/parser/ParserClassTest.kt` | P2.T6 |
| AC2.5 (10 issue-#2 bug strings parse) | `ParserBugfixTest.issue2_strings_allParse` | Ring-1 | `ParserBugfixTest.kt` + `src/test/resources/corpus/issue2-strings.txt` | P2.T7 |
| AC2.6 (malformed descriptor throws StabsParseException with cursor info) | `ParserBugfixTest.malformedDescriptor_throwsWithCursor` | Ring-1 | `ParserBugfixTest.kt` | P2.T7 |
| AC2.7 (recursive types parse without infinite recursion) | `ParserBugfixTest.selfPointerStruct_parsesUnder100ms` | Ring-1 | `ParserBugfixTest.kt` | P2.T7 |

---

## ghidra-stabs.AC3: Type resolution, dedup, and attribution

| AC | Test | Type | Path | Phase |
|----|------|------|------|-------|
| AC3.1 (cross-CU same-body dedup) | `TypeRegistryTest.sameBody_acrossCus_collapses` | Ring-2 | `src/test/kotlin/ghistabs/builder/TypeRegistryTest.kt` | P3.T7 |
| AC3.2 (cross-CU different-body conflict naming + log) | `TypeRegistryTest.differentBody_acrossCus_suffixesAndLogs` | Ring-2 | same | P3.T7 |
| AC3.3 (header / std / headers-untracked / instantiations attribution) | `AttributionTest.{stdHeader, stdMingw, projectHeader, singleCpp, multiCuClean, multiCuTemplate, multiCuLeadingUnderscore, multiCuBuiltinShadow}` + `TypeRegistryTest.attributionAtMaterialisation` | Ring-1 + Ring-2 | `AttributionTest.kt`, `TypeRegistryTest.kt` | P3.T2, P3.T7 |
| AC3.4 (recursive types resolve via placeholder) | `TypeRegistryTest.{selfPointerNode, mutuallyRecursiveAB}` | Ring-2 | `TypeRegistryTest.kt` | P3.T7 |
| AC3.5 (≥80 interesting typenames on xapasmcsr.exe) | `XapasmcsrIntegrationTest.atLeast80InterestingTypenames` | Ring-3 | `XapasmcsrIntegrationTest.kt` + `src/test/resources/corpus/xapasmcsr-interesting-typenames.txt` | P6.T6 |

---

## ghidra-stabs.AC4: Symbol application — functions, globals, locals, params

| AC | Test | Type | Path | Phase |
|----|------|------|------|-------|
| AC4.1 (function with prototype + named params) | `SymbolApplyTest.functionWithParams_returnAndArgsApplied` | Ring-2 | `src/test/kotlin/ghistabs/importer/SymbolApplyTest.kt` | P4.T4 |
| AC4.2 (locals — stack and register) | `SymbolApplyTest.{stackLocal_applied, registerLocal_applied}` | Ring-2 | same | P4.T5 |
| AC4.3 (resolved + unresolved globals) | `SymbolApplyTest.{global_resolved_applied, global_unresolved_logsNoBookmark}` | Ring-2 | same | P4.T6 |
| AC4.4 (file-statics from N_STSYM/N_LCSYM at stab-carried addr) | `SymbolApplyTest.fileStatic_appliedAtStabAddress` | Ring-2 | same | P4.T6 |
| AC4.5 (LBRAC/RBRAC scope plate comments) | `SymbolApplyTest.scopePlateComments_listLocals` | Ring-2 | same | P4.T5 |
| AC4.6 (real-binary: ≥470 funcs with named params, ≥92 with locals) | `XapasmcsrIntegrationTest.functionParamLocalCounts` | Ring-3 | `XapasmcsrIntegrationTest.kt` | P6.T6 |

---

## ghidra-stabs.AC5: C++ classes and vtables

| AC | Test | Type | Path | Phase |
|----|------|------|------|-------|
| AC5.1 (class struct + GhidraClass + reparented methods) | `ClassBuilderTest.singleInheritance_structAndNamespaceAndReparent` | Ring-2 | `src/test/kotlin/ghistabs/builder/ClassBuilderTest.kt` | P5.T5 |
| AC5.2 (ctor `_C1`/`_C2`/`_C3`, dtor `_D0`/`_D1`/`_D2` suffixes) | `ClassBuilderTest.{ctorVariants_renamedWithSuffix, dtorVariants_renamedWithTilde}` | Ring-2 | same | P5.T7 |
| AC5.3 (vtable struct, voff order, inherited entries first) | `ClassBuilderTest.{vtable_singleClass_layoutOrdered, vtable_inherited_entriesFirst}` | Ring-2 | same | P5.T6, P5.T8 |
| AC5.4 ({vfptr} as first field of polymorphic struct) | `ClassBuilderTest.polymorphicClass_vfptrFirstField` | Ring-2 | same | P5.T6 |
| AC5.5 (_ZTV applied + plate comments on virtual methods) | `ClassBuilderTest.vtable_appliedAtZtvAddress_plateComments` | Ring-2 | same | P5.T6 |
| AC5.6 (nested + templated namespaces) | `ClassBuilderTest.{nestedNamespaces, templateInstantiationNamespaceName}` | Ring-2 | same | P5.T5 |
| AC5.7 (unresolved-method tolerance — others still apply) | `ClassBuilderTest.unresolvedMethod_skipsButOthersApply` | Ring-2 | same | P5.T7 |
| AC5 (real-binary: ≥50 GhidraClass namespaces) | `XapasmcsrIntegrationTest.atLeast50GhidraClasses` | Ring-3 | `XapasmcsrIntegrationTest.kt` | P6.T6 |

**Descoped to v1.1** (documented in P5.T9): multiple-inheritance and virtual-base layout tests. Justification: `xapasmcsr.exe` corpus uses neither pattern (verified empirically via `parse_image/stabs_stats.py`'s class-marker counts). If a future binary forces re-opening, the work is enumerated in P5.T9.

---

## ghidra-stabs.AC6: Error handling, idempotence, packaging

| AC | Test | Type | Path | Phase |
|----|------|------|------|-------|
| AC6.1 (stripped binary still gets IMPORTED labels at stab addrs) | `AddressResolverTest.recordFromStab_strippedBinary_createsImportedLabel` | Ring-2 | `src/test/kotlin/ghistabs/container/AddressResolverTest.kt` | P1.T6 |
| AC6.2 (malformed record: parse-error log, importer continues) | `SymbolApplyTest.malformedRecord_doesNotAbort_surroundingApply` | Ring-2 | `SymbolApplyTest.kt` | P4.T6 |
| AC6.3 (bookmark vs log split — addressed errors get bookmark, headerless errors don't) | `SymbolApplyTest.bookmarkVsLogSplit` | Ring-2 | same | P4.T6 |
| AC6.4 (idempotent re-run — DTM and symbol state byte-identical) | `IdempotenceTest.{dtmSnapshotEqualAcrossRuns, symbolSnapshotEqualAcrossRuns, vtableBookmarkCountEqual}` | Ring-2 | `src/test/kotlin/ghistabs/IdempotenceTest.kt` | P6.T5 |
| AC6.5 (gradle distributeExtension produces installable .zip) | **HUMAN: install zip in Ghidra 12.0.4 + verify analyzer appears** + `gradle build` succeeds | build verification + human | manual smoke per P6.T7 procedure | P6.T7 |

**Human verification — AC6.5 install smoke:** the procedure in P6.T7 (open Ghidra, `File > Install Extensions > +`, select `dist/ghidra_12.0.4_*_ghidra-stabs.zip`, restart, open any program with stabs, confirm "Stabs Importer" appears in `Auto Analysis` dialog and `Tools > Stabs > Re-import` action exists). Justification: extension loading is a Ghidra UI mechanism we cannot easily exercise from inside JUnit without a headless Ghidra instance; one manual install per release is appropriate.

---

## Test execution

- **Fast loop (every save):** `./gradlew test` — runs all Ring-1 + Ring-2 tests. Sub-minute target on a developer workstation.
- **Pre-commit:** same — `./gradlew test` (Ring-1 + Ring-2). Plus `./gradlew build` to confirm the extension still packages.
- **Nightly / pre-release:** `./gradlew integrationTest` — runs Ring-3 against fixtures. Skipped where fixtures absent.
- **Per-release:** human smoke (AC1.5 menu, AC6.5 install) per the manual checklists above.

## Coverage summary

- **Automated coverage:** 27 of 29 acceptance-criterion cases.
- **Human verification:** 2 cases (AC1.5 menu disabled state, AC6.5 install smoke). Both have automated proxy tests at the API level (`isEnabledForContext` unit test, `gradle distributeExtension` build success); the human step verifies the UI/install layer that Ghidra runs above our code.
- **Descoped:** AC5 multiple-inheritance and virtual-base test variants (corpus does not exercise them; tracked in P5.T9 for v1.1 if needed).
