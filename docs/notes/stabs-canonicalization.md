# Stabs Canonicalization Reference

This document covers the algorithm layer above parsing: how raw stab records
are converted into globally-unique typed symbols, how types shared across
compilation units are deduplicated, and how the implementation (as of commits
`3f2e566..3a40357`) aligns with or deviates from gdb's model.

Companion document: `stabs-grammar-conformance.md` covers the parsing layer
(type expression grammar, N_* record syntax, Cygwin GCC 3.4.4 deviations).

---

## Section 1: Stab Record Forms and Type Expression Grammar

This section maps each N_* record type to its semantic role in the stabs namespace model.

### Record Types: Namespace and Type Carriers

| N_* Type  | Carries Type String | Format                    | Semantics                                                                                                                                                                                                  |
| --------- | ------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `N_SO`    | No                  | `name` (pathname)         | Opens compilation unit. Allocates `fileNum=0` context. Addressed to the first `text` address in the CU.                                                                                                    |
| `N_BINCL` | No                  | `name` (header filename)  | Opens header inclusion block. Allocates new `fileNum ≥ 1`. Linker computes checksum; deduplication key is `(filename, checksum)`.                                                                          |
| `N_EINCL` | No                  | (empty)                   | Closes header block. No fileNum change. Marks end of stabs attributed to current header.                                                                                                                   |
| `N_EXCL`  | No                  | `name` (header filename)  | **Linker-transformed BINCL**: remounts previously-seen header (identified by name+checksum). No stabs follow; fileNum re-established locally. Signals to GDB: "types from this header were in a prior CU." |
| `N_SOL`   | No                  | `name` (source file)      | Source-line directive (for debugger's line-to-address map). Does NOT allocate fileNum; does NOT affect type attribution.                                                                                   |
| `N_GSYM`  | Yes                 | `name:SC=type_expr`       | Global symbol (external variable). Type string provides type.                                                                                                                                              |
| `N_LSYM`  | Yes                 | `name:SC(cu,n)=type_expr` | Local symbol (automatic variable, local static, type definition). Inline body defines type.                                                                                                                |
| `N_STSYM` | Yes                 | `name:SC(cu,n)=type_expr` | Static symbol (function-static or file-static variable). Type string provides type.                                                                                                                        |
| `N_PSYM`  | Yes                 | `name:SC(cu,n)=type_expr` | Parameter symbol (function parameter). Type string provides type.                                                                                                                                          |
| `N_RSYM`  | Yes                 | `name:SC(cu,n)=type_expr` | Register symbol (parameter/local in register). Type string provides type.                                                                                                                                  |
| `N_FUN`   | Yes                 | `name:SC(cu,n)=type_expr` | Function symbol. Type string (if non-empty) provides return type and parameter types.                                                                                                                      |

**Source:** stabs PDF §2 ("Symbol Types"); **gdb/stabsread.c** `define_symbol()`.

### Type Expression Nesting

Type expressions are composed from atomic descriptors (e.g., `*` for pointer, `a` for array, `s` for struct) and combine via:

- **Prefix operators:** `*<target>` (pointer), `&<target>` (reference), `k<target>` (const).
- **Composite descriptors:** `s<size>field1:type1,field2:type2;` (struct), `u<size>…` (union), `e<name>:<val>,…;` (enum), `r<base>;<min>;<max>;` (range).
- **Type references (IDs):** `(cu,n)` or `cu,n` (bare) referencing a type defined elsewhere in the stab stream.
- **Inline definitions:** `(cu,n)=body` nests a full type definition within a field or array bounds expression.
- **Cross-references (forward refs):** `x<kind><name>:` where kind ∈ {s, u, c, Y} names an incomplete type by tag.

**Source:** stabs PDF §4 ("Type Definitions"); **gdb/stabsread.c** `read_type()`.

### Continuation Lines

When a stab string in a type-carrying record exceeds the compiler's line-length limit, it is split across multiple physical records. Continuation records reuse the same N_* type code as the original record; they do not use a separate `N_CONT` descriptor.

- **Format:** A type-carrying record whose name-string ends with `\` (backslash) signals that the next physical record(s) continue the same name string.
- **Continuation records:** Subsequent physical records with the same N_* type are treated as continuations. The `\` is stripped, and the continuation record's name-string is concatenated to the original.
- **Concatenation:** The parser reassembles by dropping the trailing `\` and appending the next record's name-string, repeating until a record does not end with `\`.

**Eligible types:** Only certain N_* types support continuation: `N_GSYM`, `N_FUN`, `N_STSYM`, `N_LCSYM`, `N_RSYM`, `N_LSYM`, `N_PSYM` (as defined in `Stabs.kt:TYPES_WITH_CONTINUATION`).

**Implication:** `Parser.kt` must accumulate continuations during stab reading, merging them before parsing the complete type string.

**Source:** **Stabs.kt** lines 294–428 (continuation merging logic and `TYPES_WITH_CONTINUATION` set definition).

---

## Section 2: Namespace Model

The stabs namespace model assigns type IDs (`LocalTypeId(file, n)`) to scopes opened and closed by include-block markers. A `SourceFile` object (either `CUSource` or `HeaderSource`) represents the scope.

### Compilation Unit (CU)

An `N_SO` record opens a compilation unit. All symbols and types at the start of the CU reside in namespace `file=0`.

- **N_SO semantics:** The address value points to the first text segment byte of the CU. The name-string is the source file path (e.g., `xapasmcsr.c`).
- **Our model:** `CUSource` object represents the CU. Types defined with `LocalTypeId(0, n)` reside here.
- **Global scope:** Types in `CUSource` are visible to that CU only; a different CU gets its own `CUSource` instance.

**Source:** stabs PDF §7.1 ("Include Files"); **gdb/stabsread.c** `start_symtab()` / `end_symtab()` (GDB opens/closes a CU).

### Header Inclusion Block

An `N_BINCL` record opens a header inclusion block within a CU, allocating a new `fileNum` (starting from 1, incremented per BINCL).

- **N_BINCL semantics:** The name-string is the header filename (e.g., `stdio.h`). The address value is typically the CU's start address (inherited). The linker computes a **checksum** over the stab strings in this block, accumulating character values and skipping digit sequences following `(`.
- **Deduplication key:** `(filename, checksum)` uniquely identifies the header contents.
- **Our model:** `beginInclude(filename, checksum)` allocates a `HeaderFile(filename, checksum, originatingCu)` (if not seen before) and stores it in the per-CU `fileNumToHeader[fileNum]` map. A `HeaderSource(HeaderFile)` wraps the header and becomes the source for all types at this `fileNum`.
- **Forward visibility:** Types in a header are available to any CU that BINCL or EXCL the same header.

**N_EINCL semantics:** Closes the block. Name-string is empty. Marks the end of stabs from the current header inclusion. Filenum does not change; it merely signals the boundary.

**Source:** stabs PDF §7.1; **bfd/stabs.c** `_bfd_link_section_stabs()` checksum computation (lines 364–384) and deduplication (lines 391–438).

### Header Remounting (EXCL)

An `N_EXCL` record (appearing after linking) remounts a previously-seen header by name+checksum, WITHOUT re-emitting its stabs.

- **Transformation:** The linker converts the second and subsequent BINCL records for the same header into EXCL, keeping only the first BINCL and its stab contents.
- **Our model:** `remount(filename, checksum)` allocates a new `fileNum` and stores the SAME `HeaderFile` instance (retrieved by looking up `(filename, checksum)` in `HeaderRegistry.globalByFilenameChecksum`) in the per-CU map. Types in this CU attributed to this `fileNum` thus share identical `GlobalTypeId`s with types in earlier CUs that BINCL'd the same header.
- **No stabs follow:** The EXCL record carries only the filename. No type definitions appear after EXCL.

**Deviation:** If an `N_EXCL` appears before any CU has processed the corresponding `N_BINCL`, `HeaderRegistry.recall()` creates a **placeholder** `HeaderFile` with `originatingCu = null` (see also `IncludeContext.recall` KDoc — currently disagrees with the implementation; resolved in Phase 4). This placeholder is stored locally in `fileNumToHeader` but NOT in the global registry. When a later CU processes the real BINCL, it allocates a NEW `HeaderFile` instance. This divergence causes `GlobalTypeId` collisions (see Section 4).

**Implication:** The log message "forward-excl" marks this case for audit purposes.

**Source:** **gdb/stabsread.c** `add_old_header_file()`; **ghistabs/parser/IncludeContext.kt** `HeaderRegistry`.

### Source-Line Directive (SOL)

An `N_SOL` record changes the source-line context for the debugger without affecting type namespace.

- **Semantics:** The name-string is a source file path (may differ from N_SO's path, e.g., when inlining or generating code from other files).
- **Effect:** Updates `current_file` for debugger's line-to-address map.
- **No fileNum change:** N_SOL does NOT allocate a fileNum and does NOT affect type attribution.
- **Our model:** `IncludeContext` ignores N_SOL; type IDs are unaffected.

**Source:** stabs PDF §7.1; **gdb/stabsread.c** `start_stabs_symbol()` (N_SOL handling).

### The `IncludeContext.sourceFor(LocalTypeId)` Contract

Given a `LocalTypeId(file, n)`, `sourceFor()` returns the `SourceFile` object:

- **If `file == 0`:** Return `CUSource` (types belong to the current CU).
- **If `file > 0` and a header is registered for this `fileNum`:** Return `HeaderSource(HeaderFile)` where the `HeaderFile` is stored in `fileNumToHeader[file]`.
- **If `file > 0` and no entry exists:** This should not occur in well-formed input; return `CUSource` as a fallback.

**Implication:** Type identity is consistent: two types with the same `LocalTypeId(file, n)` but processed in different CUs receive the same `SourceFile` instance if and only if the header mapping is identical (same `HeaderFile` key).

---

## Section 3: Type-ID Identity Model

This section explains the two-level type identity system used to deduplicate types across compilation units.

### Level 1: LocalTypeId (Stream-Local)

A `LocalTypeId(file, n)` identifies a type within a single CU's stab stream.

- **file component:** The fileNum assigned by the include-block model (Section 2). `file=0` for CU-level types; `file≥1` for types inside BINCL blocks.
- **n component:** The ordinal index of the type definition within that namespace. Multiple definitions with the same `(file, n)` in a CU indicate duplicate type definitions (same type assigned the same ID by the compiler).

**Usage:** Emitted by `Parser.parseSymbol()` when a type-carrying stab is encountered.

### Level 2: GlobalTypeId (Cross-CU)

A `GlobalTypeId(source, n)` globalizes a `LocalTypeId` by replacing the `file` component with a `SourceFile` object.

- **SourceFile variants:**
  - `CUSource`: represents the current compilation unit. Each CU has one instance.
  - `HeaderSource(HeaderFile)`: represents a specific header file. Multiple CUs may share the same `HeaderFile` instance if they include the same header.
  
- **HeaderFile key:** `(filename, checksum, originatingCu)` tuple. The linker guarantees (post-linking) that all BINCL/EXCL pairs for the same header have the same checksum, making `(filename, checksum)` a sufficient dedup key. The `originatingCu` tracks which CU first defined the header (for audit purposes).

- **Globalization contract:** `IncludeContext.sourceFor(LocalTypeId(file, n))` returns the `SourceFile` for `file`, and `GlobalTypeId(source, n)` is formed. Two CUs with the same `(filename, checksum)` pair receive the same `HeaderFile` instance, so their types have identical `GlobalTypeId`s.

**Usage:** Returned by `Harvest.globalize()` when recursively converting `LocalTypeId` refs to `GlobalTypeId` refs inside type expressions.

### Deduplication Semantics

Two types are considered identical (and deduplicated) if:

1. **Same GlobalTypeId:** `GlobalTypeId(source, n)` must match exactly. This includes both the `SourceFile` instance and the type index `n`.
2. **Same content hash:** The `Type` bodies must hash identically, ensuring that types with the same ID are also semantically identical.

If a later type with the same `GlobalTypeId` but a different hash is encountered, it is logged as a collision, and the first-writer-wins policy applies (the existing type is retained).

### Comparison with GDB's Model

GDB uses `this_object_header_files[]`, a per-CU array indexed by `fileNum`:

- **`this_object_header_files[0]`:** Pointer to the entry for the CU's own source file.
- **`this_object_header_files[n]` for n ≥ 1:** Pointers to `struct header_file *` entries for included headers.
- **`add_new_header_file(filename, instance)`:** Creates a new `struct header_file *` and appends it to the array.
- **`add_old_header_file(filename, checksum)`:** Looks up an existing entry by `(filename, checksum)` in a global table. If found, reuses it; if not found, creates a placeholder and patches it when the BINCL arrives.

Our model is structurally equivalent, with `HeaderRegistry.globalByFilenameChecksum` playing the role of GDB's global table, and `fileNumToHeader` playing the role of `this_object_header_files[]`.

**Source:** **gdb/stabsread.c** `this_object_header_files[]`, `add_new_header_file()`, `add_old_header_file()`; **ghistabs/parser/IdInterface.kt**, **ghistabs/parser/IncludeContext.kt**.

---

## Section 4: Cross-CU Deduplication

This section explains how types defined in shared headers are deduplicated and what happens when the implementation deviates from GDB's patching model.

### BFD's BINCL/EXCL Checksum Protocol

Before linking, each object file's stab section contains multiple BINCL/EINCL pairs, one per header inclusion. The linker applies the following transformation:

1. **Checksum computation (BFD):** For each BINCL block, accumulate the character values of all stab strings (excluding digit sequences following `(`) until EINCL. This checksum is written into the BINCL record.
   - **Spec:** bfd/stabs.c lines 364–384.
   - **Outcome:** Two identical header contents in different object files produce the same checksum.

2. **Deduplication (BFD):** After checksumming, iterate through all CUs. For each BINCL with checksum C and filename F:
   - If this is the FIRST occurrence of `(F, C)`, keep the BINCL and its stabs.
   - If a previous BINCL had the SAME `(F, C)`, convert this BINCL to EXCL, suppress its stabs, and write the checksum into the EXCL record.
   - **Spec:** bfd/stabs.c lines 391–438.
   - **Outcome:** In the final linked binary, each unique `(filename, checksum)` pair appears as exactly one BINCL block; subsequent inclusions are marked EXCL.

3. **GDB's interpretation:** When GDB reads EXCL, it invokes `add_old_header_file(filename, checksum)`:
   - Look up `(filename, checksum)` in a global dedup table.
   - If found, reuse the existing `struct header_file *` entry (all types from this header share the same `this_object_header_files[]` entry across CUs).
   - If not found, create a placeholder entry and patch it when the BINCL arrives (if it does).

### Our Model: HeaderRegistry and GlobalTypeId Sharing

Our `HeaderRegistry` mimics GDB's dedup table:

- **`HeaderRegistry.globalByFilenameChecksum`:** Map from `(filename, checksum)` → `HeaderFile` instance (singleton per key).
- **`HeaderRegistry.getOrInsert(filename, checksum, originatingCu)`:** Returns the existing entry if present, or creates and stores a new one.
- **Per-CU `fileNumToHeader[fileNum]`:** Stores the `HeaderFile` assigned to this fileNum in this CU. Multiple CUs may have different filenums but map to the same `HeaderFile` instance.

**Deduplication contract:** When two CUs call `beginInclude(filename, checksum)`, they both receive the SAME `HeaderFile` instance. Therefore, a type `TypeAst(GlobalTypeId(source, n))` where `source = HeaderSource(header)` is identical across the two CUs (same `source` object, same `n`).

**`appendAsts()` collision policy:**

- **Same GlobalTypeId, same content hash:** Logged as `ast-id-collision-same-hash` and deduplicated. The type is already in the collection.
- **Same GlobalTypeId, different content hash:** Log the collision with details (file, type index, both hashes) in `collidingAsts` map. Apply first-writer-wins: retain the existing body, discard the new one.
- **Different GlobalTypeId:** Always add both to the collection.

**XRef resolution:** When a type expression contains `TypeDecl.XRef(kind, tag)` (a forward reference to a struct/union/enum), `appendAsts()` replaces the XRef body with a concrete definition (`TypeDecl.Struct`, etc.) if both are encountered for the same `GlobalTypeId`.

### The 207 xapasmcsr Collisions

The xapasmcsr binary (CSR XAP assembler, circa 2005) exhibits 207 collision log lines involving `GlobalTypeId` pairs with the same ID but different content hashes.

**Root cause (per design audit):** Nested `Ref` types inside struct fields whose resolved hash diverges across CUs. The following example uses illustrative fileNums; actual fileNums depend on the number of prior BINCL records in each CU.

- CU1 includes header H via BINCL.
  - Struct S (in H) has field `f: Ref(file=1, n=42)`.
  - During globalization, `sourceFor((1, 42))` → `HeaderSource(H)`.
  - `Ref(file=1, n=42)` globalizes to `Ref(GlobalTypeId(HeaderSource(H), 42))`.
  
- CU2 encounters an EXCL for H before any BINCL.
  - `HeaderRegistry.recall()` creates a placeholder `HeaderFile(name=H, checksum=…, originatingCu=null)`.
  - `fileNumToHeader[3] = placeholder`.
  - Later, CU3 processes the real BINCL for H.
  - `HeaderRegistry.getOrInsert()` creates a NEW `HeaderFile` instance (different from the placeholder).
  
- When CU2's struct S is processed:
  - `sourceFor((3, 42))` → `HeaderSource(placeholder)` (different instance from the real H).
  - `Ref(file=3, n=42)` globalizes to `Ref(GlobalTypeId(HeaderSource(placeholder), 42))`.
  
- **Hash divergence:** Even though the `Ref` target (type 42 in H) is the same, the `GlobalTypeId` differs because the `HeaderSource` wraps different `HeaderFile` instances.

**Outcome:** When both struct S definitions are added to `appendAsts()`, they have the same `GlobalTypeId` but different content hashes → collision logged, first-writer-wins applied.

**`collidingAsts` map:** Keyed by `GlobalTypeId`, stores the list of hashes that collided. Populated by `appendAsts()` when a conflict is detected. Its downstream consumer status is not yet clear; see Section 7 for the audit.

**Source:** **bfd/stabs.c** `_bfd_link_section_stabs()`; **gdb/stabsread.c** `add_old_header_file()`; **ghistabs/parser/Harvest.kt** `appendAsts()`; integration log `src/test/resources/logs/xapasmcsr.after.log` (collision lines); harvest JSON `src/test/resources/harvests/xapasmcsr-harvest.json` (`collidingAsts` field).

---

## Section 5: Deep ID Resolution

This section explains how type IDs nested inside struct fields, method parameters, and array bounds are resolved during globalization to ensure cross-CU deduplication works correctly.

### Recursive Globalization

The `globalize()` method in `Harvest.kt` performs a recursive descent through a `TypeDecl` tree, converting `LocalTypeId` references to `GlobalTypeId`:

- **Leaf types** (e.g., `TypeDecl.Builtin`, `TypeDecl.Void`): Pass through unchanged.
- **Recursive types** (e.g., `TypeDecl.Pointer`, `TypeDecl.Array`, `TypeDecl.Struct`): Recurse on child `TypeDecl` nodes.
- **Reference nodes** (`TypeDecl.Ref(LocalTypeId)`): Convert to `TypeDecl.Ref(GlobalTypeId)` by invoking `globalIdFor(id)`.

**Resolution contract:** `globalIdFor(LocalTypeId(file, n))` calls `currentInclude.sourceFor(LocalTypeId(file, n))`, which returns:

- `CUSource` if `file == 0`.
- `HeaderSource(header)` if `file ≥ 1` and `header` is registered in `fileNumToHeader[file]`.

The resulting `GlobalTypeId(source, n)` is unique for a given `source` and `n`, enabling deduplication.

### InlineDef Side Effect

When `globalize()` encounters an `TypeDecl.InlineDef(localId, body)` node (a type definition nested inside another type expression), it performs two actions:

1. **Globalize the body:** Recursively apply `globalize()` to the `body` expression.
2. **Emit a TypeAst:** Create a `TypeAst(globalIdFor(localId), globalizedBody)` and append it to a side-effect list.

**Implication:** Inline definitions are "hoisted" into the top-level AST collection during globalization, ensuring that all types (including those defined inline) are indexed by `GlobalTypeId`.

**Example:** A field type `Ref((0, 12), InlineDef((0, 99), Struct(...)))` causes both the Ref and the Struct to be emitted as separate TypeAsts.

### walkDefinitions() Traversal

After globalization, `walkDefinitions()` performs a second pass through the tree, collecting all `Type` nodes emitted by `InlineDef` side effects.

- **Purpose:** Ensure that every type node, no matter how deeply nested, is added to the global `Type` collection via `appendAsts()`.
- **Behavior:** Visits all nodes in depth-first order; when an `InlineDef` is encountered, yields the emitted `Type`.

### Deep Nesting Example

Consider a struct field whose type is `Ref(3, 12)` (reference to type 12 in fileNum 3, a header). Note: fileNums in this example are illustrative and differ from the Section 4 example; actual fileNums depend on the number of prior BINCL records in each CU.

**CU1 (correct BINCL):**
- Processes `N_BINCL header.h` with checksum C, allocating fileNum 3.
- `headerRegistry.getOrInsert("header.h", C, CU1)` returns `HeaderFile(name="header.h", checksum=C, originatingCu=CU1)`.
- `fileNumToHeader[3] = HeaderFile_C`.
- Struct field `Ref(3, 12)` globalizes via `sourceFor((3, 12))` → `HeaderSource(HeaderFile_C)` → `GlobalTypeId(HeaderSource(HeaderFile_C), 12)`.

**CU2 (forward EXCL before BINCL):**
- Processes `N_EXCL header.h` with checksum C before any BINCL has been seen.
- `headerRegistry.recall("header.h", C)` creates placeholder `HeaderFile(name="header.h", checksum=C, originatingCu=null)` (see also `IncludeContext.recall` KDoc — currently disagrees with the implementation; resolved in Phase 4) (NOT in global registry).
- `fileNumToHeader[2] = HeaderFile_placeholder` (note: different fileNum, different instance).
- Struct field `Ref(2, 12)` globalizes via `sourceFor((2, 12))` → `HeaderSource(HeaderFile_placeholder)` → `GlobalTypeId(HeaderSource(HeaderFile_placeholder), 12)`.

**Later CU3 (real BINCL):**
- Processes `N_BINCL header.h` with checksum C.
- `headerRegistry.getOrInsert("header.h", C, CU3)` returns `HeaderFile_C` (already registered in global table by CU1, or creates new if CU1 was never processed).

**Result:** CU1 and CU3 have identical `GlobalTypeId`s for types in header.h; CU2 has a divergent `GlobalTypeId` due to the placeholder → **hash collision** when struct definitions are merged.

### Comparison with GDB's Lazy Resolution

GDB resolves type references lazily using `read_type()`:

- Type refs are stored as `(cu, n)` pairs in the AST (e.g., in a `struct field` record).
- When a type is needed (e.g., during decompilation), `read_type()` looks up `this_object_header_files[file]` to get the target file's type vector, then indexes into it with `n`.
- If the type at `(file, n)` has not been parsed yet, a `TYPE_CODE_UNDEF` placeholder is returned, and a flag is set to resolve it later.

**Our model:** We resolve eagerly (at globalize time), replacing `LocalTypeId` with `GlobalTypeId` upfront. This means forward-EXCL divergence manifests as hash collisions rather than unresolved refs. The trade-off is that all types must be parsed before globalization, but deduplication is deterministic.

**Source:** **gdb/stabsread.c** `read_type()`, `read_struct_fields()`; **ghistabs/parser/Harvest.kt** `globalize()` (recursive descent), `walkDefinitions()` (side-effect collection).

---

## Section 6: Forward Cross-References

This section covers type references that cannot be resolved upfront (forward XRefs) and the deviation from GDB's patching model that causes collisions.

### XRef Forward References

A `TypeDecl.XRef(kind, tag)` is emitted when a type expression is:

- `xs<tag>:` (struct forward ref)
- `xu<tag>:` (union forward ref)
- `xc<tag>:` (class forward ref, GCC-2 style)
- `xY<tag>:` (class forward ref, alternate)

**Semantics:** Names an incomplete struct/union/enum type by its tag name without providing the body. The body appears:

1. Later in the same stab stream (forward declaration followed by full definition in the same CU).
2. In an included header (the header file emits both the forward ref in the referencing CU and the full body in the header).
3. Never (incomplete types that are only forward-referenced, never fully defined).

**Our model:** `TypeDecl.XRef(kind, tag)` is initially emitted as-is. During `appendAsts()`, if a concrete type definition (`TypeDecl.Struct`, `TypeDecl.Union`, `TypeDecl.Enum`) with the same `GlobalTypeId` and matching tag is later encountered, the XRef body is replaced with the concrete definition.

**Implication:** The order of processing matters: if a full definition arrives before an XRef, the XRef will not be created (since there's nothing to place-hold). If an XRef arrives first, it is retained until superseded by a definition.

**Source:** stabs PDF §4.6 ("Cross-References"); **gdb/stabsread.c** `read_type()`.

### Forward EXCL Before BINCL

A forward EXCL occurs when a CU encounters `N_EXCL` for a header `(filename, checksum)` before any prior CU has processed the `N_BINCL` for that header.

**Scenario:**

1. **CU1:** Processes types including struct S defined in header H. No BINCL for H yet (all types are CU-local via XRef placeholders or are inlined).
2. **CU1:** Emits `N_EXCL header H, checksum C` (linker transformation during post-processing).
3. **CU2:** Encounters the EXCL while reading. Calls `headerRegistry.recall("H", C)`.
4. **CU3:** Later encounters the real `N_BINCL header H, checksum C` and calls `headerRegistry.getOrInsert("H", C, CU3)`.

**GDB's approach (patching):**

- `add_old_header_file()` creates a placeholder `struct header_file *` entry.
- The placeholder is stored in a global table by key `(filename, checksum)`.
- When `add_new_header_file()` processes the real BINCL, it checks if a placeholder already exists. If so, the linker has already merged the stabs, and GDB reuses the placeholder (effectively patching it in-place).

**Our approach (no patching):**

- `HeaderRegistry.recall()` creates a placeholder `HeaderFile(filename, checksum, originatingCu=null)` (see also `IncludeContext.recall` KDoc — currently disagrees with the implementation; resolved in Phase 4) and stores it ONLY in the local `fileNumToHeader` map.
- The placeholder is NOT added to `globalByFilenameChecksum`.
- When `HeaderRegistry.getOrInsert()` processes the real BINCL in a later CU, it looks up `(filename, checksum)` in the global table. Since the placeholder was never added, a NEW `HeaderFile` instance is created and stored.
- The earlier CU's types are attributed to the placeholder instance; later CU's types are attributed to the real instance → **divergent GlobalTypeIds** → **hash collisions in `appendAsts()`**.

**Diagnostic:** `HeaderRegistry.recall()` emits a log message `log("forward-excl", ...)` when a forward EXCL is detected. This allows the audit (Phase 3) to identify which collisions stem from this deviation.

**Implication:** The forward-EXCL case is a known source of false collisions. Fixing it would require either:

1. **Patching approach:** Storing the placeholder in the global registry and updating it when the BINCL arrives (GDB's strategy).
2. **Deferred globalization:** Deferring type globalization until all BINCL/EXCL records have been processed, ensuring all fileNum-to-HeaderFile mappings are stable.
3. **Eager patching in memory:** Scanning the CU sequence to detect forward EXCL, pre-allocating all HeaderFile instances upfront, and sharing them from the start.

Option 1 is closest to GDB and easiest to implement.

**Source:** **gdb/stabsread.c** `add_old_header_file()`, `add_new_header_file()`; **ghistabs/parser/IncludeContext.kt** `HeaderRegistry.recall()`; **stabs PDF** §7.1 ("Include Files").

---

## Section 7: Untouched Algorithm Parts

This section documents code paths and logic not modified by commits `3f2e566..3a40357`. The goal is to flag staleness relative to the new `SourceFile` model and note vestigial code.

### 7.1 Attribution.categoryFor() and AttributionTraceDump

The `Attribution.categoryFor()` method (**src/main/kotlin/ghistabs/builder/Attribution.kt**) routes types to Ghidra categories (namespaces) given a type name and the set of source files defining it. The routing decision tree:

1. **PROJECT_OVERRIDE_NAMES**: Hard-coded set of type names → `/proj/` category regardless of source.
2. **STD_MARKERS regex**: Any source matching `STD_MARKERS` pattern → stdlib category.
3. **Single CUSource**: If exactly one source and it's a `CUSource`, derive category from the CU filename.
4. **Clean multi-CU name**: Multiple CU sources but a "clean" name (no special chars) → `/headers-untracked/<name>.h`.
5. **Multi-CU fallback**: Otherwise → `/<canonicalCu>/instantiations`.

**D2 fix (2026-06-10):** A new step 3 routes types whose entire defining-source set is `HeaderSource` (and shares a single filename basename) to `/headers/<basename>/`. The branch sits before the single-CU shortcut (so single `HeaderSource` defs land in `/headers/<basename>/` rather than `/<basename>/`) and converges multi-defining cases caused by D1 forward-EXCL placeholder divergence — distinct `HeaderFile` instances for the same physical header still resolve to the same category. Cross-header multi-defining cases (different basenames) intentionally fall through to step 5. The new route increments `attribution-routed-headers`; the existing stdlib route still increments `attribution-routed-std`; both go through the same `recordAttributionTrace(...counter)` helper.

**Diagnostic companion:** `AttributionTraceDump` (**src/main/kotlin/ghistabs/diag/AttributionTraceDump.kt**) logs the routing decision for each type. Its downstream consumer in `DataTypeRegistry` or elsewhere was not audited by the four commits.

**Deviation rating:** D2 (fixed 2026-06-10) — `categoryFor()` now treats `HeaderSource` as a distinct case.

### 7.2 preSeedHeaders() Two-Pass Rationale

The `preSeedHeaders()` method (**src/main/kotlin/ghistabs/parser/Harvest.kt** lines 104–124) scans the stab stream for `N_SO`, `N_BINCL`, `N_EINCL`, and `N_EXCL` records, building `IncludeContext` for each CU and populating `includesByFile` before `passA()` processes any types.

**Rationale:** `passA()` processes records in order and needs the `IncludeContext` (with its `fileNumToHeader` mapping) to be established for each CU before encountering the first type symbol in that CU. If types were processed before all BINCL/EINCL/EXCL records had been seen, a forward EXCL (N_EXCL appearing before the real N_BINCL) would leave a temporary placeholder that might not match the real header when it arrives later.

Pre-seeding ensures a stable `IncludeContext` per CU upfront, avoiding the need to re-process types when mappings change.

**Known issue:** The pre-seeding approach avoids repeated re-processing but does not fully solve the forward-EXCL divergence (see Section 6). Forward EXCLs still create placeholder `HeaderFile`s that don't get patched when the real BINCL arrives, producing different `GlobalTypeId`s.

**Deviation rating:** D3 (incomplete) — pre-seeding defers the forward-EXCL issue rather than fixing it.

### 7.3 walkDefinitions() InlineDef Naming

The `walkDefinitions()` method (**src/main/kotlin/ghistabs/parser/Harvest.kt** lines 375–400) traverses a `TypeDecl` tree and emits `Type` nodes for any `InlineDef` bodies found. When `walkDefinitions()` encounters an `InlineDef(localId, body)`, it emits a `Type` with name `"${decl.id}"` (the string representation of the `GlobalTypeId`, e.g., `[<HeaderSource>,42]` for an anonymous type).

**Rationale:** Anonymous types in stabs have no textual name in the grammar; the name is synthesized from the type ID itself.

**Note:** This naming convention is not derived from the stabs spec — the spec has no concept of a global name for anonymous types. The choice to use the ID as a name is an implementation convention, not spec-grounded.

**Deviation rating:** D4 (correct / convention) — anonymous `Type` naming from `walkDefinitions()` is a local convention not spec-grounded, but it is correct.

### 7.4 rawByIdSnapshot: Removed Field with Vestigial Documentation

The `rawByIdSnapshot` field existed in the prior TypeRegistry implementation (before commit 7d2bc56, "rip out stupid canonicalization") as a snapshot map of `TypeId` → `Type` used during type resolution. It was removed during the refactoring that introduced the `GlobalTypeId` and `SourceFile` model.

**Current status (post-refactor):** The field no longer exists in the codebase. However, four comments still reference it as a conceptual part of the type-lookup cascade:

- **src/main/kotlin/ghistabs/builder/TypeRegistry.kt:88** — `dataTypeFor()` KDoc describes an idealized lookup order: "byId → placeholders → rawByIdSnapshot"
- **src/main/kotlin/ghistabs/builder/TypeRegistry.kt:457** — Comment in `resolve()`: "Same cascade as dataTypeFor: byId → placeholders → rawByIdSnapshot"
- **src/main/kotlin/ghistabs/builder/TypeRegistry.kt:462** — Comment: "Truly-missing classifier: rawByIdSnapshot already exhausted above"
- **src/main/kotlin/ghistabs/builder/ResolverDecision.kt:40** — KDoc on `classifyRef()`: "@param knownTypeIds All TypeIds that were observed in the harvest (from rawByIdSnapshot)"

**What it was:** The field was a snapshot of the Harvest's `types` map, created at the start of materialization to provide a fallback lookup when a type reference could not be resolved via `byId` or `placeholders`. It represented the complete set of types observed during the harvest phase.

**Why it was removed:** The new `GlobalTypeId`-based model and `HarvestIndex` make the snapshot unnecessary. Types are now resolved via `typeResolver.getTypeFor(GlobalTypeId)`, which queries the `Harvest.typeAsts` map directly, eliminating the need for an intermediate snapshot.

**Current resolution cascade:** `tryGetExisting(gId)` → `byId[gId]` (Ghidra already-materialized) → `placeholders[gId]` (forward-ref placeholder) → `typeResolver.getTypeFor(gId)` (query Harvest.typeAsts). The `rawByIdSnapshot` references are **vestigial documentation artifacts** that describe an old strategy no longer needed.

**Recommendation for cleanup:** Replace all four comments' references to "rawByIdSnapshot" with "harvest.typeAsts" or "typeResolver" to match the current post-refactor implementation.

**Deviation rating:** D5 (vestigial in documentation) — the field is correctly removed, but comments persist as stale documentation. The lookup logic is correctly implemented; only the descriptive text needs updating.

---

## Section 8: Commit Review and Deviation Table

### 8.1 Model Introduced

The refactor commits `3f2e566..3a40357` introduced a new type-ID and deduplication model replacing the prior approach:

**Old approach:** Types were deduplicated by some heuristic (described in commit messages as "stupid canonicalization"); the exact mechanism is not documented in the current codebase.

**New model:**
- **LocalTypeId(file, n)** — Stream-local type identifier within a CU's stab stream; file is the fileNum (0 for CU-level, ≥1 for BINCL blocks).
- **GlobalTypeId(source, n)** — Cross-CU global identifier formed by replacing the file component with a `SourceFile` object (either `CUSource` or `HeaderSource`).
- **SourceFile sealed class** — Two variants:
  - `CUSource(filename)` — Represents a single CU; each CU gets one instance.
  - `HeaderSource(HeaderFile)` — Represents a header file; multiple CUs may share the same `HeaderFile` instance if they include the same header.
- **HeaderFile(filename, checksum, originatingCu)** — The dedup key for headers; `(filename, checksum)` uniquely identifies header contents (post-linking), and `originatingCu` tracks which CU first defined the header.
- **HeaderRegistry** — Global cross-CU registry mapping `(filename, checksum)` → `HeaderFile` instance (singleton per key).
- **IncludeContext** — Per-CU state machine managing the include-block stack and fileNum-to-header mappings.
- **globalize()** — Recursive descent replacing `LocalTypeId` refs with `GlobalTypeId` refs during `passA()`.
- **walkDefinitions()** — Traversal collecting all `Type` nodes emitted by inline-type side effects.
- **appendAsts()** — Collision policy and cross-CU deduplication: same `GlobalTypeId` with identical hash = deduplicated; same ID with different hash = collision logged.

### 8.2 What Was Removed

Commit 7d2bc56 ("rip out stupid canonicalization") removed a name-based deduplication strategy and related infrastructure:

1. **ContentHash class:** A custom hash function that computed content-based hashes of `TypeDecl` trees for deduplication.
2. **rawByIdSnapshot field:** A snapshot map of `TypeId` → `Type` used for fallback type lookup when refs were unresolved.
3. **Type-lookup maps by (TypeId, name):** Fields `byIdName`, `placeholdersByIdName`, and `byHash: Map<(String, ContentHash), DataType>` that keyed types by both identity AND name separately, allowing multiple types per ID.
4. **FileResolver and IncludeContext initialization:** Simplified context setup; the old code maintained per-CU `includeContextsByFile` and `structAstsByName` snapshots.

The new model replaces this with deterministic `GlobalTypeId`-based deduplication, where identity is primary and content-hash is used only for collision detection (not deduplication). The removal of the `ContentHash` class and name-keyed maps reflects a shift from "try all possible dedup keys" to "use a single deterministic ID".

### 8.3 Alignment with Spec and GDB

For each design choice in the new model:

- **BINCL/EXCL dedup by (filename, checksum):** Aligns with gdb's `add_old_header_file()` and BFD's linker checksum protocol (bfd/stabs.c lines 364–384, 391–438).
- **sourceFor() mapping (LocalTypeId → SourceFile):** Aligns with gdb's `this_object_header_files[]` per-CU indexing (**gdb/stabsread.c** `this_object_header_files`, `start_symtab()`, `end_symtab()`).
- **Forward EXCL placeholder:** Partial alignment — gdb patches the placeholder when the real BINCL arrives; our approach creates a non-patched placeholder, causing `GlobalTypeId` divergence. See Section 6 for details.
- **Two-pass pre-seeding:** Not present in gdb; gdb processes single-pass with lazy resolution. Our approach is different but valid (deterministic and early-binding).
- **InlineDef side-effect during globalize():** Not directly analogous to gdb; gdb handles inline types differently via `read_type()`. Our model "hoists" inline definitions into the top-level collection during globalization.

### 8.4 Deviation Table

| ID  | Location                           | Description                                                                                                                                                               | Rating                                                         |
| --- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| D1  | HeaderRegistry.recall()            | Forward EXCL creates placeholder HeaderFile not stored globally; later BINCL CU gets different HeaderFile → GlobalTypeId mismatch → hash collisions                       | needs-fix                                                      |
| D2  | Attribution.categoryFor()          | All-HeaderSource same-basename defs route to `/headers/<basename>/` via new step 3 branch; cross-header multi-defining still falls through to multi-CU heuristic          | fixed (2026-06-10) — see §7.1                                  |
| D3  | preSeedHeaders()                   | Two-pass pre-seeding does not patch forward-EXCL placeholders when the BINCL arrives; placeholder divergence persists                                                     | incomplete                                                     |
| D4  | walkDefinitions() anonymous naming | Anonymous inline TypeAst named "${decl.id}" — convention only, not spec-grounded                                                                                          | correct (convention)                                           |
| D5  | rawByIdSnapshot                    | Field removed in commit 7d2bc56; vestigial comments remain in TypeRegistry.kt lines 88, 457, 462 and ResolverDecision.kt line 40 describing old lookup cascade — see §7.4 | vestigial (in documentation)                                   |
| D6  | collidingAsts map                  | Map of colliding TypeDecls indexed by GlobalTypeId; populated by appendAsts() but no production consumer (diagnostic-only)                                                | vestigial (diagnostic-only, no production consumer — see §9.6) |
| D7  | AttributionTraceDump               | Diagnostic companion to categoryFor(); not updated for HeaderSource model                                                                                                 | incomplete                                                     |

---

## Section 9: Pipeline Architecture and Segmentation Audit

This section evaluates the pipeline layering, data-flow boundaries, and context dataclass shapes across six pipeline stages: Parser, Harvester, TypeRegistry, TypeResolver, ClassBuilder, and StabsImporter.

**Note on code citations:** Kotlin file and line-number references in this section are pinned to commit `07b9791290145ce1a57bcc08d32e1510571e42ee` (current HEAD). Consult that commit if line numbers drift.

### 9.1 Pipeline Layer Map

**Parser (src/main/kotlin/ghistabs/parser/Parser.kt)** — Recursive-descent parser consuming type expression strings and symbol descriptors, producing `TypeDecl<LocalTypeId>` and `SymbolDecl<LocalTypeId>` ASTs. Entry points: `parseSymbol()` (parses `name:descriptor`), `parseTypeBody()` (parses type body for testing). Continuation-line joining is delegated to the caller. No Ghidra types; pure grammar implementation.

**Harvester (src/main/kotlin/ghistabs/parser/Harvest.kt)** — Stateful stream processor consuming stab records; produces `Harvest` (data class containing `typeAsts: Map<GlobalTypeId, TypeAst>`, `symbolsByCu`, `functions`, `collidingAsts`, `headerRegistry`). Two passes: `preSeedHeaders()` pre-allocates include contexts, then `passA()` processes all records, calling `Parser` on each type-carrying record. Responsibility: state management (`currentCu`, `currentFunction`, `includesByFile`), record dispatch (N_* type routing), symbol/type accumulation, `LocalTypeId` → `GlobalTypeId` globalization (lines 333–373), inline-type hoisting via side effects, collision logging.

**TypeResolver (src/main/kotlin/ghistabs/builder/TypeRegistry.kt computed property `index`)** — Computed property on `Harvest` returning `TypeResolver(typeAsts)`. Lightweight helper providing three queries: `getTypeFor(GlobalTypeId)`, `getBodyFor<T>(GlobalTypeId)`, `getStructByName(name)`. Used by `DataTypeRegistry` and `ClassBuilder` to look up type definitions during materialization and class construction.

**TypeRegistry (src/main/kotlin/ghistabs/builder/TypeRegistry.kt)** — Stateful Ghidra DataTypeManager wrapper; transforms `Harvest` output (`Type` map) into Ghidra `DataType` objects. Responsibility: placeholder allocation, byId/byHash dedup (keying on `GlobalTypeId` and content hash), cross-CU collision handling (merge via `StructuralDiff` or rename), attribute computation (`Attribution.categoryFor()` for namespace routing). Materializes types transactionally via `materializeAll()` and `resolve()` methods. Uses `HarvestIndex` to resolve nested type references.

**ClassBuilder (src/main/kotlin/ghistabs/builder/ClassBuilder.kt)** — Stateful Ghidra program updater; constructs GhidraClass namespaces, applies methods, builds vtables. Responsibility: polymorphism detection (`ClassBuilderHelpers.firstPolymorphicBase()`), vfptr placement decision (`VfptrDecision`), inherited virtual method collection, vtable struct building, method reparenting with `__thiscall` calling convention. Uses `HarvestIndex` to resolve base types during inheritance chain traversal.

**StabsImporter (src/main/kotlin/ghistabs/importer/StabsImporter.kt)** — Orchestrator coordinating three passes: Pass A (Harvester), Pass B (TypeRegistry.materializeAll), Pass C (applyAllSymbols). Responsibility: transaction management, diagnostic counter recording, symbol application (functions, globals, class vtables), demangler stub replacement, final Itanium-mangled label demangling. Uses `StabReader` to extract stab section, `AddressResolver` to map stab values to program addresses.

### 9.2 Parser / Harvester Boundary

**Finding:** The boundary is clean. Parser is stateless and produces only grammar-level ASTs. Harvester manages all stream state (CU tracking, include contexts, symbol accumulation). 

However:
- **Continuation-line joining** (backslash-terminated records) is performed by `Stabs.kt` before Parser sees the string (**Stabs.kt** lines 294–428, `TYPES_WITH_CONTINUATION` set). This is correctly located at the record level, not Parser level, since continuation is a physical-record property, not a grammar property.
- **No logic in Parser consumes or produces Harvest-level data structures.** All typing metadata (`LocalTypeId`, type-ID resolution) is Parser's concern; all stream state is Harvester's.
- **LocalTypeId → GlobalTypeId globalization** happens in Harvester (`globalize()` method, lines 333–373), after Parser produces `TypeDecl<LocalTypeId>`. This is correct: the globalization step requires knowledge of the current `IncludeContext`, which Parser has no access to.

**Verdict:** Correct separation. No changes suggested.

### 9.3 Harvester / TypeRegistry Boundary

**Finding:** The boundary is well-defined but has one subtle design choice worth noting.

**Harvest data shape:** The `Harvest` data class (**src/main/kotlin/ghistabs/parser/Harvest.kt** lines 64–74) contains:
- `typeAsts: Map<GlobalTypeId, TypeAst>` — all types indexed by global ID
- `symbolsByCu: Map<String, List<HarvestedSymbol>>` — all non-type symbols (globals, statics, function-params) grouped by CU filename
- `openFunctions: List<OpenFunction>` — all function records with locals, params, scope brackets
- `collidingAsts: Map<GlobalTypeId, MutableMap<String, MutableSet<TypeDecl<GlobalTypeId>>>>` — collision log keyed by ID
- `headerRegistry: HeaderRegistry` — the global header dedup table
- `parseErrors: Int` — error count

**TypeRegistry consumption:**
- `materializeAll(typeAsts.values)` uses only the `Type` list.
- `index` computed property wraps only `types`.
- `collidingAsts` is NOT consumed by TypeRegistry; the deviation table flags this as pending audit (D6).

**Ghidra-specific types:** None in `Harvest`. It is pure data (serializable via `kotlinx.serialization`).

**Subtle design choice — TypeAst.cu field:** Each `Type` (**src/main/kotlin/ghistabs/parser/Harvest.kt** lines 15–23) carries a `cu: SourceFile.CUSource` field AND an `id: GlobalTypeId` field. The `id` contains `id.source` (a `SourceFile` — either `CUSource` or `HeaderSource`). The `cu` field is always a `CUSource` and represents the CU that originally emitted this type record (even if the type is in a header). This duplication allows callers to ask "which CU did this come from originally?" without having to parse the source type.

**Assessment:** The `cu` field is redundant for Harvest-layer consumers but useful for diagnostics and attribution (matching defining CUs to compute categories). It is harmless and intentional. No change suggested.

**TypeResolver interface:** `TypeResolver.getTypeFor(GlobalTypeId)` and `getStructByName(String)` are the right level of abstraction for ClassBuilder and TypeRegistry's resolve phase. No change suggested.

**Verdict:** Correct boundary; subtle but justified design choice.

### 9.4 StructuralDiff

**Current status:** `StructuralDiff` (**src/main/kotlin/ghistabs/builder/StructuralDiff.kt**) is called from `TypeRegistry.tryExecuteMerge()` (**src/main/kotlin/ghistabs/builder/TypeRegistry.kt** lines 527–590).

**Purpose:** When two `DataType` definitions with the same `(category, name)` but different hashes are encountered, `StructuralDiff.diff()` compares their byte layouts to detect whether one can be merged into the other (gap-filling) or whether they conflict (incompatible field definitions).

**Algorithm:** Byte-by-byte coverage analysis with gap-merge validation and bitfield collision detection. Pure algorithm; no Ghidra imports. Result is `StructDiffResult.Identical`, `GapMergeable(mergePlan)`, or `Conflicting(reason)`.

**Call site:** One call in `TypeRegistry.tryExecuteMerge()` when a conflict is detected. The merge plan (if `GapMergeable`) is applied to the existing `Structure` via `replaceAtOffset()` for each operation.

**Assessment:** StructuralDiff is active and correctly scoped. It operates at the right abstraction level (pure struct comparison) and produces results that TypeRegistry applies. No vestigial code found.

**Verdict:** Active and correctly placed. No changes suggested.

### 9.5 Re-grouping by Name

**Scan for name-based dedup:** Grep results show name-based keying in the following places:

| Location                                | Pattern                                             | Purpose                                                                     | Justified?                                                                            |
| --------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| TypeRegistry.materializeAll lines 44–61 | `val byName = asts.groupBy { it.name }`             | Pre-seed placeholders per unique name; later dedup by name within the batch | Yes — ensures forward refs resolve via placeholders                                   |
| TypeRegistry.resolve lines 178, 194     | `byName[ast.name]?.map { it.id.source }?.toSet()`   | Compute union of defining CUs for attribution                               | Yes — needed for correct category computation                                         |
| TypeRegistry.byHash lines 17            | `byHash: Map<Pair<String, Int>, DataType>`          | Cross-CU dedup: same name + same hash                                       | Yes — efficient by-hash lookup keyed on (name, hash) for idempotent reruns            |
| StabsImporter.applyAllSymbols lines 232 | `harvest.typeAsts.values.groupBy { it.ghidraName }` | Dedupe class ASTs by display name                                           | Yes — multiple ASTs from different CUs may have the same name; take the most detailed |

**Specific case — same name, different IDs:** When two `Type`s have the same `ghidraName` but different `GlobalTypeId`s (e.g., a struct defined in two different CUs with the same name but different bodies):
- In `materializeAll`: Both materialize into the DTM as separate `DataType` objects (keyed by `(name, hash)`); the byId map keeps first-writer-wins for ref resolution.
- In `StabsImporter`: Classes are deduplicated by name; the most-detailed one (max methods, then fields) is chosen for vtable construction.
- In `Attribution.categoryFor()`: Both types may get different category paths if the dedup rule disagrees (e.g., one is multi-CU, one is single-CU).

**Assessment:** Name-based grouping is used only for diagnostic/dedup purposes (deciding which AST to build a vtable for, which body to keep in a merge), not for identity. Identity is always keyed by `GlobalTypeId`. No conflation found.

**Verdict:** Name-based grouping is justified and correctly scoped. No changes suggested.

### 9.6 Post-harvester Hashes

**Hash/equality mechanisms in the pipeline:**

| Level        | Mechanism                                  | Used By                 | Purpose                                     |
| ------------ | ------------------------------------------ | ----------------------- | ------------------------------------------- |
| Harvest      | `TypeDecl<GlobalTypeId>.hashCode()`        | `appendAsts()`          | Detect collisions (same ID, different hash) |
| Harvest      | `collidingAsts` map                        | Logged but not consumed | Collision audit trail                       |
| TypeRegistry | `byHash: Map<Pair<String, Int>, DataType>` | `resolve()` idempotency | Reuse type if same (name, hash) seen before |
| TypeRegistry | `StructuralDiff.diff()` comparison         | `tryExecuteMerge()`     | Byte-by-byte layout conflict detection      |
| TypeRegistry | `dataType.name == resolvedDataType.name`   | `applyGlobal()`         | Verify stab-applied type actually stuck     |

**Operation levels:**
- **Harvest-layer hash (TypeDecl.hashCode):** Detects collision during type accumulation; content-based comparison. Correct level.
- **TypeRegistry byHash:** Efficient lookup by (name, hash); prevents re-materializing identical types. Correct level.
- **StructuralDiff:** Ghidra-level structural comparison (offset, length, type path); used when name-matched types have different hashes. Correct level.

**collidingAsts consumer status:** `collidingAsts` is populated in `appendAsts()` (**src/main/kotlin/ghistabs/parser/Harvest.kt** lines 415–419) but not consumed by TypeRegistry, ClassBuilder, or StabsImporter. It is serialized to the harvest JSON for diagnostic analysis. No code reads it downstream.

**Assessment:** Three independent hash/equality levels are appropriate (Harvest content-based, TypeRegistry by-name dedup, Ghidra structural merge). They operate at different layers. `collidingAsts` is a diagnostic artifact, not a functional dedup mechanism.

**Verdict:** Hash mechanisms are correct. `collidingAsts` is diagnostic-only. No changes suggested.

### 9.7 Context Dataclass Shapes

Evaluation of five key data classes:

**TypeAst(cu, id, name, body)** (**src/main/kotlin/ghistabs/parser/Harvest.kt** lines 15–23):
- `cu: SourceFile.CUSource` — originating CU (always CUSource, never HeaderSource).
- `id: GlobalTypeId` — global identity (may be HeaderSource).
- `name: String` — type name.
- `body: TypeDecl<GlobalTypeId>` — type definition.

**Evaluation:** The `cu` field duplicates information from `id.source` when `id.source` is a `CUSource`. However, when `id.source` is a `HeaderSource`, the `cu` field tells which CU first emitted this stab record, which is useful for attribution. Not redundant; intended. Correct.

**HarvestedSymbol(decl, recordType, rawValue)** (**src/main/kotlin/ghistabs/parser/Harvest.kt** lines 39):
- `decl: SymbolDecl<GlobalTypeId>` — the parsed symbol.
- `recordType: StabType` — the N_* code (for filtering in downstream code).
- `rawValue: Long` — the stab record's value field (address or offset).

**Evaluation:** Used in `StabsImporter.applyAllSymbols()` (**src/main/kotlin/ghistabs/importer/StabsImporter.kt** lines 192–208). All three fields are used: decl is applied, recordType helps dispatch (global vs static), rawValue is passed to `applyStatic()`. Correct shape.

**OpenFunction(name, addr, decl, cu, locals, params, scopeBrackets, sizeBytes)** (**src/main/kotlin/ghistabs/parser/Harvest.kt** lines 52–61):
- `locals: MutableList<LocalRecord>` — accumulates locals during harvest.
- `params: MutableList<ParamRecord>` — accumulates params during harvest.
- `scopeBrackets: MutableList<Triple<StabType, Long, Int>>` — LBRAC/RBRAC pairs for scope comments.
- `sizeBytes: Long` — function size from end-of-function N_FUN record.

**Evaluation:** `scopeBrackets` stores `(StabType, Long, Int)` = (LBRAC or RBRAC, address, record index). `ScopePairs.compute()` (**src/main/kotlin/ghistabs/importer/StabsImporter.kt** lines 416) pairs opens/closes by record-index range and filters locals whose `recordIndex` falls within the range. This mechanism is correct. `locals` and `params` are properly typed. Correct shape.

**LocalRecord(decl, rawValue, recordIndex)** (**src/main/kotlin/ghistabs/parser/Harvest.kt** lines 35–36):
- `recordIndex` — stab stream record number (for scope filtering).

**Evaluation:** `recordIndex` enables scope-bracket pairing. Used in `ScopePairs.compute()` to filter locals by scope. Correct usage.

**Attribution context:** The `Attribution.categoryFor()` method (**src/main/kotlin/ghistabs/builder/Attribution.kt**) takes `(typeName: String, defCUs: Set<SourceFile>)` and returns a `CategoryPath`. This signature is sufficient for the dedup strategy (route based on name and defining CUs). Correct.

**Verdict:** All dataclass shapes are correct. No missing or redundant fields identified.

### 9.8 Architecture Summary

The pipeline is well-layered with clear responsibilities:
1. **Parser** — Pure grammar (no state, no Ghidra types).
2. **Harvester** — Stream state + record dispatch + globalization.
3. **TypeResolver** — Lightweight query helper on Harvest output.
4. **TypeRegistry** — Ghidra DataType materialization + dedup.
5. **ClassBuilder** — Class namespace + vtable construction.
6. **StabsImporter** — Orchestration + transaction management.

Boundaries are clean; data flows unidirectionally downstream (Harvest → TypeRegistry → ClassBuilder → StabsImporter). Context dataclasses have the right fields for their consumers. No redundant hashing or dedup layers detected. One architectural note: `collidingAsts` is a diagnostic artifact (D6 in the deviation table) and should be audited for whether downstream analysis consumes it or if it can be documented as a post-hoc collision report only.

---

## References

- **stabs.html** (GNU Binutils documentation): <https://sourceware.org/binutils/docs/stabs/>
  - Section 2: "Symbol Types" and descriptors
  - Section 4: "Type Definitions" (all subsections)
  - Section 7: "Include Files" and include-block mechanics

- **BFD stabs.c** (Binutils source tree, any version 2.15+):
  - `_bfd_link_section_stabs()` - Main linker deduplication routine
  - Checksum computation (lines 364–384)
  - Deduplication and EXCL transformation (lines 391–438)

- **GDB stabsread.c** (GDB source tree, versions 5.x–8.x):
  - `define_symbol()` - Symbol-level dispatch
  - `read_type()` - Type descriptor recursion
  - `add_new_header_file()` - Create new header entry
  - `add_old_header_file()` - Reuse or create placeholder header entry
  - `this_object_header_files[]` - Per-CU header file array (declared near top of file)
  - `start_symtab()` / `end_symtab()` - CU open/close

- **ghistabs codebase:**
  - **Stabs.kt** lines 294–428: `TYPES_WITH_CONTINUATION` set and continuation record merging logic
  - **ghistabs/parser/IdInterface.kt**: `LocalTypeId`, `GlobalTypeId`, `SourceFile` definitions
  - **ghistabs/parser/IncludeContext.kt** line 26: `recall()` method for forward-EXCL placeholder creation
  - **ghistabs/parser/IncludeContext.kt** line 64: `beginInclude()` method for header block allocation
  - **ghistabs/parser/Harvest.kt** line 333: `globalize()` recursive descent through type trees
  - **ghistabs/parser/Harvest.kt** line 375: `walkDefinitions()` traversal collecting emitted TypeAsts
  - **ghistabs/parser/Harvest.kt** line 402: `appendAsts()` collision policy and deduplication
  - **src/test/resources/logs/xapasmcsr.after.log** - 207 collision log lines (xapasmcsr binary)
  - **src/test/resources/harvests/xapasmcsr-harvest.json** - `collidingAsts` map from same binary

- **CSR/Qualcomm ecosystem:**
  - ADK 4.0.1 sink firmware (QC35 II) compiled with GCC 3.4.4 (Cygwin), the primary reference for stabs emission patterns in this project
