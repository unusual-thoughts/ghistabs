# Stabs Algorithm Audit Design

## Summary

The `ghidra-stabs` extension imports debug information from stabs-in-COFF debug records embedded in Cygwin GCC 3.4.4 PE binaries into Ghidra. Stabs is a decades-old debug format: each type, variable, and function is described by a record (an `N_*` stab) carrying a name and a type-expression string. The extension parses these records, resolves cross-file type references, deduplicates types shared across compilation units via the BINCL/EXCL/EINCL include-block protocol, and registers the resulting types and symbols in Ghidra's data-type manager and symbol table.

This plan is a correctness audit of the harvesting pipeline — the code that converts raw parsed stabs into Ghidra-ready types. The approach is spec-first and source-grounded: the stabs PDF, gdb's `stabsread.c`, and BFD's `bfd/stabs.c` are read first to establish ground truth, then the existing implementation (specifically the four refactor commits `3f2e566..3a40357`) is compared against that ground truth. Findings are captured in a reference document, backfilled into KDoc, and validated with a test suite whose assertions are derived entirely from the spec — not from what the current code happens to produce.

## Definition of Done

1. **Parsing audit** (against the stabs PDF spec): verify `Parser.kt` and stab record decoding correctly handle all type expression forms — ranges, arrays, structs/unions, methods, XRef forward refs, InlineDef nested inline definitions.
2. **Post-parse logic audit** (against `stabsread.c` + `bfd/stabs.c`): document and compare how gdb (a) identifies source CU vs. header file for a type, (b) deduplicates types across CUs, (c) resolves IDs nested deeply inside stab strings (e.g. a struct field whose type is an InlineDef referring to a type in a different file slot), and (d) handles forward cross-references (XRef / N_EXCL before N_BINCL).
3. **Reference document** at `docs/notes/stabs-canonicalization.md`: captures both audits, spec → implementation mapping, and any deviations or unmodeled edge cases found. KDoc added to `Harvester`, `IncludeContext`, `HeaderRegistry`, `globalize()`, `appendAsts()`.
4. **Tests** added covering: `Parser.kt` type expressions; `IncludeContext`/`HeaderRegistry` (BINCL, EXCL, forward-EXCL, shared-registry dedup); `globalize()` (nested InlineDef, deep Ref chains); `appendAsts()` collision logic; `Harvest.passA` state machine (N_SO/N_FUN/N_GSYM/N_LSYM flow); and any gaps identified by the commit review.
5. **`TODO.md`** retriaged and committed: done items closed, open items re-prioritized based on reference-doc findings.

## Acceptance Criteria

### stabs-algo-audit.AC1: Parsing audit complete
- **AC1.1 Success:** Every type expression form in the stabs PDF (range, array, struct/union, method `#`-form, XRef, InlineDef, pointer, reference, const, volatile, function, complex) has at least one test in the parser test suite.
- **AC1.2 Success:** Method `#`-form edge cases (trailing void sentinel, implicit this pointer) are tested.
- **AC1.3 Success:** Deeply nested InlineDef chains (InlineDef containing InlineDef containing Struct) parse correctly.
- **AC1.4 Failure:** Parser test suite has no assertions derived directly from current log output.

### stabs-algo-audit.AC2: Reference document written
- **AC2.1 Success:** `docs/notes/stabs-canonicalization.md` exists with all 8 sections covering: stab record forms, namespace model (N_SO/BINCL/EXCL/SOL), type-ID identity model, cross-CU deduplication, deep ID resolution, forward XRefs, untouched algorithm parts, commit review and deviation table.
- **AC2.2 Success:** Every factual claim about gdb or BFD behavior cites the specific function or section of `stabsread.c` / `bfd/stabs.c` / the stabs PDF.
- **AC2.3 Success:** Deviation table in section 8 covers all deviations found, each rated (correct / incomplete / needs-fix / vestigial).
- **AC2.4 Success:** KDoc present on `Harvester`, `IncludeContext`, `HeaderRegistry`, `globalize()`, `appendAsts()`.
- **AC2.5 Failure:** Reference doc makes no unsourced claims about gdb behavior.

### stabs-algo-audit.AC3: Harvester unit tests added
- **AC3.1 Success:** `HarvesterGlobalizeTest` covers identity on terminals, recursion through all `TypeDecl` variants, `InlineDef` producing `TypeAst`, and `Ref` resolution through both `CUSource` and `HeaderSource`.
- **AC3.2 Success:** `HarvesterAppendAstsTest` covers XRef replacement, same-hash suppression, hash-differing first-writer-wins, and same-type-twice-from-same-CU.
- **AC3.3 Success:** `HarvesterPassATest` covers N_SO/N_FUN/N_GSYM/N_LSYM state machine, N_SOL non-allocation, and BINCL/EXCL/EINCL in both passes.
- **AC3.4 Success:** `HarvesterGapTest` covers every untested case identified in the deviation table.
- **AC3.5 Success:** `IncludeContextTest` covers BINCL re-entry for the same header within one CU.
- **AC3.6 Failure:** No test assertion matches current log output directly — all are derived from spec behavior.

### stabs-algo-audit.AC4: TODO.md retriaged
- **AC4.1 Success:** Items confirmed done and tested are closed.
- **AC4.2 Success:** Open items referencing the include-stack / nested-Ref problem have concrete spec citations replacing vague descriptions.
- **AC4.3 Success:** Vestigial items (`rawByIdSnapshot`, `collidingAsts` downstream, `preSeedHeaders()` two-pass rationale, stale `Attribution` routing, `AttributionTraceDump` usage) are flagged.
- **AC4.4 Success:** New TODO entries exist for out-of-scope deviations found during the audit.
- **AC4.5 Success:** `./gradlew test` passes after all changes.

## Glossary

- **stabs**: A debug information format originating in Unix assemblers and used by GCC. Each "stab" is a record carrying a symbol type (`N_FUN`, `N_GSYM`, `N_SO`, etc.), a name string, and a numeric value. The type-expression embedded in the name string describes the type of the symbol.
- **COFF**: Common Object File Format; the binary container format used by PE (Windows) executables. Stabs records are stored in a `.stab` COFF section.
- **N_\* record types**: Named constants that classify a stab record's role. Examples: `N_SO` (source file boundary), `N_FUN` (function), `N_GSYM` (global symbol), `N_LSYM` (local/stack symbol), `N_BINCL`/`N_EINCL`/`N_EXCL` (include-block protocol).
- **CU (Compilation Unit)**: One `.c` or `.cpp` source file as compiled. Stabs are logically partitioned into CUs by `N_SO` records. Each CU has its own type-number namespace.
- **BINCL / EINCL / EXCL**: The stabs include-block protocol. `N_BINCL` opens a named block of stabs for a header file (with a checksum); `N_EINCL` closes it. A subsequent CU that includes the same header uses `N_EXCL` instead of re-emitting all the stabs, referencing the block by `(filename, checksum)`. The BFD linker performs this deduplication at link time.
- **XRef (cross-reference)**: A type expression of the form `xs<tag>`, `xu<tag>`, or `xe<tag>` that names a struct, union, or enum by tag without giving its body. Used as a forward reference when the full definition appears elsewhere.
- **InlineDef**: A type expression that defines a new type inline inside another type expression. Represented as a `TypeDecl` variant that produces a `TypeAst` as a side effect during `globalize()`.
- **LocalTypeId / GlobalTypeId**: The two-level type identity model. A `LocalTypeId` is a `(file, n)` pair scoped to one CU's stabs stream. A `GlobalTypeId` pairs the type number with a `SourceFile`, making it globally unique across CUs.
- **SourceFile / CUSource / HeaderSource**: The implementation's representation of where a type is attributed. `CUSource` identifies a compilation unit; `HeaderSource` wraps a `HeaderFile` (a `(filename, checksum)` pair) representing a shared header block.
- **HeaderRegistry**: A shared-across-CUs registry keyed by `(filename, checksum)`. Ensures that two CUs that BINCL/EXCL the same header share a single `HeaderFile` instance and thus the same `GlobalTypeId`s.
- **IncludeContext**: Per-CU state tracking the include stack, file-number-to-header mapping, and `N_BINCL`/`N_EINCL`/`N_EXCL` transitions. The `sourceFor()` method maps a `LocalTypeId` to the correct `SourceFile`.
- **Harvester**: The central pipeline class. Runs two passes (`preSeedHeaders`, `passA`) over the raw stabs stream, building `typeAsts`, `symbolsByCu`, and related output structures.
- **`globalize()`**: Harvester method that converts a parsed `TypeDecl<LocalTypeId>` to `TypeDecl<GlobalTypeId>` by replacing all local type IDs with their globally-unique counterparts. Produces `TypeAst` nodes as a side effect when it encounters `InlineDef` nodes.
- **`appendAsts()`**: Harvester method that inserts a resolved `TypeAst` into the global `typeAsts` map, applying the collision policy: XRef bodies are silently replaced; same-hash duplicates are suppressed; hash-differing duplicates log and let the first writer win.
- **`walkDefinitions()`**: Traversal helper that visits all `TypeDecl` nodes in a type tree and collects inline definitions.
- **`passA()` / `preSeedHeaders()`**: The two Harvester passes. `preSeedHeaders` seeds the `HeaderRegistry` by scanning for `N_BINCL`/`N_EXCL` records before per-CU processing begins. `passA` is the main pass that processes all `N_*` records to harvest symbols and types.
- **`collidingAsts`**: A map in `Harvest` recording type-body collisions (same `GlobalTypeId`, different content). Currently suspected vestigial — auditing whether it has any live downstream consumer is part of this plan.
- **`rawByIdSnapshot`**: A field flagged in `TODO.md` as possibly pointless. Auditing its necessity is in scope for Phase 3.
- **Attribution / `categoryFor()`**: The routing logic that decides which Ghidra namespace or category a harvested type is placed into. `AttributionTraceDump` is its diagnostic companion. Neither is rethought by the four refactor commits; staleness relative to the new `SourceFile` model is a known gap.
- **stabs PDF**: The normative specification at `sourceware.org/gdb/onlinedocs/stabs.pdf`, describing the type-expression grammar, all `N_*` record semantics, and the BINCL/EXCL/EINCL protocol.
- **`stabsread.c` / `bfd/stabs.c`**: GDB and BFD source files implementing stabs consumption and link-time BINCL elimination, located at `/home/riton/git/binutils-gdb/`.
- **`context_stack` / `this_object_header_files[]`**: GDB internal structures in `stabsread.c` tracking per-CU include nesting state and the CU's file-number-to-header mapping. Our `IncludeContext` is the counterpart model.
- **deviation table**: Section 8 of `stabs-canonicalization.md`. Enumerates all places where the implementation diverges from the spec or gdb, with a severity rating: correct / incomplete / needs-fix / vestigial.
- **KDoc**: Kotlin's doc-comment format. Added only where the "why" is non-obvious, per the project's sparse-KDoc convention.
- **ktlint**: The Kotlin linter configured in this project. Required to pass before every commit touching `*.kt` files.
- **TypeDecl**: The AST node type representing a parsed type body, parameterized on the ID type (`LocalTypeId` or `GlobalTypeId`).
- **TypeAst**: A top-level named type entry in the output `Harvest`, combining a `GlobalTypeId`, a name, a `CUSource`, and a `TypeDecl<GlobalTypeId>` body.

## Architecture

Spec-first sequential audit: read all normative sources before writing anything, so reference doc sections can cross-reference each other freely and test cases are derived from the spec rather than from current output.

Three source layers are read in order:

1. **Stabs PDF** (`sourceware.org/gdb/onlinedocs/stabs.pdf`) — normative spec for type expression syntax, N_* record semantics, BINCL/EXCL/EINCL protocol, and XRef forward-reference forms. Covers the *parsing* layer.
2. **`bfd/stabs.c`** and **`gdb/stabsread.c`** (at `/home/riton/git/binutils-gdb/`) — BFD's link-time BINCL/EXCL elimination pass and gdb's consumer model (`this_object_header_files[]`, `context_stack`, per-CU type-number lookup, structural deduplication if any). Covers the *post-parse identity and deduplication* layer.
3. **Refactor commits `3f2e566..3a40357`** — the four-commit body of work reviewed holistically against the above, deviations and gaps catalogued.

Findings feed two outputs: a reference document and a test suite. Integration test logs (`xapasmcsr.after.log`, `appquery.after.log`) are used for case discovery only — test assertions are derived from spec behavior, not from current output.

**Key components:**

- `docs/notes/stabs-canonicalization.md` — reference document (8 sections, see Implementation Phases)
- `src/main/kotlin/ghistabs/parser/IdInterface.kt` — `LocalTypeId`, `GlobalTypeId`, `HeaderFile`, `SourceFile`
- `src/main/kotlin/ghistabs/parser/IncludeContext.kt` — `HeaderRegistry`, `IncludeContext`
- `src/main/kotlin/ghistabs/parser/Harvest.kt` — `Harvester`, `globalize()`, `walkDefinitions()`, `appendAsts()`, `passA()`, `preSeedHeaders()`
- `src/main/kotlin/ghistabs/builder/Attribution.kt` — `Attribution.categoryFor()`, `AttributionTraceDump`

## Existing Patterns

`docs/notes/stabs-grammar-conformance.md` establishes the pattern for reference documents in this project: prose sections with spec citations, implementation notes, and known-deviation callouts. `stabs-canonicalization.md` follows the same structure.

Test files follow the pattern established by `IncludeContextTest`, `ParserPrimitiveTest`, and `ParserBugfixTest`: pure Kotlin unit tests with no Ghidra dependency, no mocks, operating on plain data types. New test files (`HarvesterGlobalizeTest`, `HarvesterAppendAstsTest`, `HarvesterPassATest`, `HarvesterGapTest`) follow this same pattern.

KDoc is currently sparse in this codebase by convention — added only where the *why* is non-obvious. New KDoc follows this: brief doc on class-level purpose and on methods whose invariants or edge-case behavior would surprise a reader.

## Implementation Phases

<!-- START_PHASE_1 -->
### Phase 1: Source reading
**Goal:** Establish ground truth from the stabs PDF, gdb source, and the four refactor commits before writing anything.

**Components:**
- Read stabs PDF: type expression grammar (all forms), N_* record semantics, BINCL/EXCL/EINCL protocol, XRef forms
- Read `bfd/stabs.c`: link-time BINCL block elimination, checksum deduplication
- Read `gdb/stabsread.c`: `add_new_header_file()`, `add_old_header_file()`, `context_stack`, `this_object_header_files[]`, per-CU type-number resolution, deep nested-ID resolution, forward XRef handling
- Read `git diff 3f2e566..3a40357` holistically: model introduced, rationale, coverage gaps

**Dependencies:** None

**Done when:** Reading notes sufficient to write all 8 reference doc sections exist; no open questions about spec behavior remain unresolved from the sources.
<!-- END_PHASE_1 -->

<!-- START_PHASE_2 -->
### Phase 2: Reference doc sections 1–6
**Goal:** Write the core algorithm sections of `docs/notes/stabs-canonicalization.md`.

**Components:**
- Section 1: Stab record forms and type expression grammar — which N_* types carry type strings, `(file,n)=body` grammar, continuation lines, raw value semantics per record type
- Section 2: Namespace model — N_SO establishes CU namespace (file=0), N_BINCL/EXCL establish shared header namespace keyed by `(filename,checksum)`, N_SOL switches line-tracking context only (no namespace allocation). Type attribution: a type's `SourceFile` is determined at parse time by the active namespace. Our `CUSource` / `HeaderSource` model.
- Section 3: Type-ID identity model — gdb's `this_object_header_files[]` and `context_stack` vs our `LocalTypeId → GlobalTypeId` via `sourceFor()`
- Section 4: Cross-CU deduplication — BINCL checksum protocol; `appendAsts()` collision logic (XRef replaced silently, same-hash suppressed, hash-differing first-writer-wins); `collidingAsts` map (vestigial?); unresolved nested-Ref hash-divergence (source of 207 xapasmcsr collisions); whether gdb does structural type-body deduplication (to be determined from stabsread.c, not assumed)
- Section 5: Deep ID resolution — nested type IDs inside struct fields / method signatures; gdb's resolution path vs our `globalize()` / `walkDefinitions()`
- Section 6: Forward cross-references — XRef records, forward EXCL before BINCL, our placeholder model in `HeaderRegistry.recall()`

**Dependencies:** Phase 1

**Done when:** Sections 1–6 written, spec citations present for each claim, deviations called out explicitly.
<!-- END_PHASE_2 -->

<!-- START_PHASE_3 -->
### Phase 3: Reference doc sections 7–8 and deviation table
**Goal:** Complete the reference doc with the untouched-algorithm audit and holistic commit review.

**Components:**
- Section 7: Untouched algorithm parts — `Attribution.categoryFor()` and `AttributionTraceDump` (routing logic not rethought by commits; `PROJECT_OVERRIDE_NAMES` hardcoded hack; commented-out extension routing; interaction with new `SourceFile.HeaderSource` model); `preSeedHeaders()` (two-pass rationale unclear — why not a single pass?); `walkDefinitions()` InlineDef naming (anonymous `TypeAst` with `"${decl.id}"` as name); `rawByIdSnapshot` (TODO flags as possibly pointless)
- Section 8: Commit review and deviation analysis — holistic review of `3f2e566..3a40357` as a body of work: model introduced, rationale, alignment with spec and gdb source, edge cases not covered; summary deviation table indexed to sections 1–7 with severity rating (correct / incomplete / needs-fix / vestigial)

**Dependencies:** Phase 2

**Done when:** Sections 7–8 written; deviation table complete; reference doc committed to `docs/notes/stabs-canonicalization.md`.
<!-- END_PHASE_3 -->

<!-- START_PHASE_4 -->
### Phase 4: KDoc on key classes and functions
**Goal:** Add inline documentation to the hairy algorithm code, following the project's sparse-KDoc convention.

**Components:**
- `Harvester` class — multi-pass pipeline overview (preSeedHeaders → passA → globalize → appendAsts), shared-registry invariant, currentCu/currentInclude state machine
- `IncludeContext` — BINCL/EXCL/EINCL semantics, fileNum allocation, `sourceFor()` contract
- `HeaderRegistry` — shared-across-CUs invariant, `(filename,checksum)` dedup key, forward-EXCL placeholder behavior
- `globalize()` — identity on terminal nodes, recursion contract, InlineDef side-effect (produces TypeAst)
- `appendAsts()` — XRef replacement rule, collision policy (same-hash suppressed, hash-differing first-writer-wins)

**Dependencies:** Phase 3 (reference doc provides the correct descriptions to copy from)

**Done when:** KDoc present on all listed targets; build passes; ktlint clean.
<!-- END_PHASE_4 -->

<!-- START_PHASE_5 -->
### Phase 5: Parser tests (audit-driven)
**Goal:** Fill gaps in Parser-layer test coverage identified by the parsing audit.

**Components:**
- Extensions to `ParserPrimitiveTest` — any type expression forms from the spec not currently exercised
- Extensions to `ParserClassTest` — method `#`-form edge cases (trailing void sentinel, implicit this), XRef forward-ref syntax within struct bodies
- Extensions to `ParserBugfixTest` — deeply nested InlineDef chains (InlineDef containing InlineDef containing Struct)
- Specific cases driven by section 1 of the reference doc and the deviation table from Phase 3

**Dependencies:** Phase 3 (deviation table identifies gaps)

**Done when:** All parsing audit gaps have corresponding test cases; `./gradlew test` passes.
<!-- END_PHASE_5 -->

<!-- START_PHASE_6 -->
### Phase 6: Harvester unit tests — globalize and appendAsts
**Goal:** Direct unit test coverage for `globalize()`, `walkDefinitions()`, and `appendAsts()`.

**Components:**
- `HarvesterGlobalizeTest` — identity on terminals (`Complex`, `Enum`, `XRef`); correct recursion through `Pointer`, `Array`, `FunctionT`, `Method`, `Struct`; `InlineDef` produces `TypeAst` with correct `GlobalTypeId`; deeply nested struct with inline field types; `Ref` resolution through `sourceFor()` for both CUSource and HeaderSource
- `HarvesterAppendAstsTest` — XRef body replaced by real definition; same-hash collision suppressed (no duplicate in `typeAsts`); hash-differing collision logs and first-writer-wins; same type emitted twice from same CU (the appquery same-hash pattern)

**Dependencies:** Phase 3 (reference doc defines correct behavior to assert against)

**Done when:** Both test files green; all assertions derived from spec behavior documented in Phase 3.
<!-- END_PHASE_6 -->

<!-- START_PHASE_7 -->
### Phase 7: Harvester state machine tests and gap tests
**Goal:** Direct unit test coverage for `passA()` / `preSeedHeaders()` and any remaining gaps from the commit review.

**Components:**
- `HarvesterPassATest` — N_SO opens/closes CU context; N_BINCL/EXCL/EINCL processed in both `preSeedHeaders` and `passA`; N_FUN opens/closes function; N_GSYM harvests symbol into `symbolsByCu`; N_LSYM routes to TaggedType/Typedef/local/StaticVar correctly; N_SOL does not affect type namespace (no fileNum allocated)
- Extensions to `IncludeContextTest` — BINCL re-entry for the same header within one CU (appquery same-hash pattern origin); any edge cases from sections 2 and 6 of the reference doc not already covered
- `HarvesterGapTest` — cases specifically identified by the deviation table in section 8 as untested

**Dependencies:** Phase 3 (deviation table), Phase 6

**Done when:** All new test files green; `./gradlew test` passes; no assertions are derived from current log output.
<!-- END_PHASE_7 -->

<!-- START_PHASE_8 -->
### Phase 8: TODO.md retriage and final commit
**Goal:** Retriage `TODO.md` against audit findings and commit all remaining changes.

**Components:**
- Close items the reference doc confirms are now correctly implemented and tested (N_SOL fix, shared HeaderRegistry dedup, N_GSYM/N_PSYM canonicalization)
- Reprioritize open items with concrete spec citations — in particular the include-stack / nested-Ref hash-divergence item (currently vague; now expressible in terms of what gdb's `context_stack` does that we don't)
- Flag vestigial items found in Phase 3: `rawByIdSnapshot`, `collidingAsts` downstream, `preSeedHeaders()` two-pass rationale, `Attribution` routing-logic staleness, `AttributionTraceDump` usage
- Add new TODO entries for deviations found in the audit that are out of scope to fix now
- Trim stale references (outdated binary names, obsolete phase numbers in comments, resolved diagnostic-spam entries)
- Commit everything: reference doc, KDoc, tests, and updated TODO.md

**Dependencies:** Phases 3–7

**Done when:** `TODO.md` committed; `./gradlew test` passes; all design-plan deliverables verified against Definition of Done.
<!-- END_PHASE_8 -->

## Additional Considerations

**Integration log policy:** `xapasmcsr.after.log` and `appquery.after.log` are read during phases 1–3 for case discovery — to understand what the running system produces and where anomalies appear. No test assertion may be written to match current log output directly. All assertions must be derivable from the spec or gdb source behavior established in the reading phase.

**Attribution staleness:** `Attribution.categoryFor()` and `AttributionTraceDump` are in scope for section 7 of the reference doc and the deviation table, but fixing the routing logic is out of scope for this plan. Any issues found become new TODO entries.
