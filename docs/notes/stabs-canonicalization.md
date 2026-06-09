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

| N_* Type | Segment | Carries Type String | Format | Semantics |
|----------|---------|---------------------|--------|-----------|
| `N_SO` | STAB_DESC_COMP_UNIT | No | `name` (pathname) | Opens compilation unit. Allocates `fileNum=0` context. Addressed to the first `text` address in the CU. |
| `N_BINCL` | STAB_DESC_INCLUDE_BEGIN | No | `name` (header filename) | Opens header inclusion block. Allocates new `fileNum ≥ 1`. Linker computes checksum; deduplication key is `(filename, checksum)`. |
| `N_EINCL` | STAB_DESC_INCLUDE_END | No | (empty) | Closes header block. No fileNum change. Marks end of stabs attributed to current header. |
| `N_EXCL` | STAB_DESC_INCLUDE_EXCL | No | `name` (header filename) | **Linker-transformed BINCL**: remounts previously-seen header (identified by name+checksum). No stabs follow; fileNum re-established locally. Signals to GDB: "types from this header were in a prior CU." |
| `N_SOL` | STAB_DESC_SOURCE | No | `name` (source file) | Source-line directive (for debugger's line-to-address map). Does NOT allocate fileNum; does NOT affect type attribution. |
| `N_GSYM` | STAB_DESC_GSYM | Yes | `name:SC=type_expr` | Global symbol (external variable). Type string provides type. |
| `N_LSYM` | STAB_DESC_LSYM | Yes | `name:SC(cu,n)=type_expr` | Local symbol (automatic variable, local static, type definition). Inline body defines type. |
| `N_STSYM` | STAB_DESC_STSYM | Yes | `name:SC(cu,n)=type_expr` | Static symbol (function-static or file-static variable). Type string provides type. |
| `N_PSYM` | STAB_DESC_PSYM | Yes | `name:SC(cu,n)=type_expr` | Parameter symbol (function parameter). Type string provides type. |
| `N_RSYM` | STAB_DESC_RSYM | Yes | `name:SC(cu,n)=type_expr` | Register symbol (parameter/local in register). Type string provides type. |
| `N_FUN` | STAB_DESC_FUN | Yes | `name:SC(cu,n)=type_expr` | Function symbol. Type string (if non-empty) provides return type and parameter types. |

**Source:** stabs PDF §2 ("Symbol Types"); **gdb/stabsread.c** `define_symbol()` dispatch on descriptor letter (~line 700 in GCC-3.4.4 era).

### Type Expression Nesting

Type expressions are composed from atomic descriptors (e.g., `*` for pointer, `a` for array, `s` for struct) and combine via:

- **Prefix operators:** `*<target>` (pointer), `&<target>` (reference), `k<target>` (const).
- **Composite descriptors:** `s<size>field1:type1,field2:type2;` (struct), `u<size>…` (union), `e<name>:<val>,…;` (enum), `r<base>;<min>;<max>;` (range).
- **Type references (IDs):** `(cu,n)` or `cu,n` (bare) referencing a type defined elsewhere in the stab stream.
- **Inline definitions:** `(cu,n)=body` nests a full type definition within a field or array bounds expression.
- **Cross-references (forward refs):** `x<kind><name>:` where kind ∈ {s, u, c, Y} names an incomplete type by tag.

**Source:** stabs PDF §4 ("Type Definitions"); **gdb/stabsread.c** `read_type()` dispatch (~line 2000).

### Continuation Lines

Stab strings are truncated at `STAB_LINE_MAX` characters (typically 4096). When a type definition exceeds this limit, the stab string is split across multiple records with a continuation marker.

- **Format:** First record's name-string ends with `\` (backslash).
- **Subsequent records:** N_CONT descriptor (code `0x90`) carries the continuation, with name-string being the next chunk.
- **Concatenation:** The parser reassembles by joining the chunks at the backslash boundary.

**Implication:** `Parser.kt` must handle stab records with descriptor `N_CONT` and accumulate continuations before dispatching to type parsing.

**Source:** stabs PDF §2.1 ("String Table Handling"); **gdb/stabsread.c** continuation handling in `read_type_string()`.

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

**Deviation:** If an `N_EXCL` appears before any CU has processed the corresponding `N_BINCL`, `HeaderRegistry.recall()` creates a **placeholder** `HeaderFile` with `originatingCu = null`. This placeholder is stored locally in `fileNumToHeader` but NOT in the global registry. When a later CU processes the real BINCL, it allocates a NEW `HeaderFile` instance. This divergence causes `GlobalTypeId` collisions (see Section 4).

**Implication:** The log message "forward-excl" marks this case for audit purposes.

**Source:** **gdb/stabsread.c** `add_old_header_file()` (lines 413–438); **ghistabs/parser/IncludeContext.kt** `HeaderRegistry`.

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
2. **Same content hash:** The `TypeAst` bodies must hash identically, ensuring that types with the same ID are also semantically identical.

If a later type with the same `GlobalTypeId` but a different hash is encountered, it is logged as a collision, and the first-writer-wins policy applies (the existing type is retained).

### Comparison with GDB's Model

GDB uses `this_object_header_files[]`, a per-CU array indexed by `fileNum`:

- **`this_object_header_files[0]`:** Pointer to the entry for the CU's own source file.
- **`this_object_header_files[n]` for n ≥ 1:** Pointers to `struct header_file *` entries for included headers.
- **`add_new_header_file(filename, instance)`:** Creates a new `struct header_file *` and appends it to the array.
- **`add_old_header_file(filename, checksum)`:** Looks up an existing entry by `(filename, checksum)` in a global table. If found, reuses it; if not found, creates a placeholder and patches it when the BINCL arrives.

Our model is structurally equivalent, with `HeaderRegistry.globalByFilenameChecksum` playing the role of GDB's global table, and `fileNumToHeader` playing the role of `this_object_header_files[]`.

**Source:** **gdb/stabsread.c** `this_object_header_files[]` declaration, `add_new_header_file()` (lines 390–410), `add_old_header_file()` (lines 413–438); **ghistabs/parser/IdInterface.kt**, **ghistabs/parser/IncludeContext.kt**.

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
   - If a previous BINCL had the SAME `(F, C)`, convert this BINCL to EXCL (marker `0x84`), suppress its stabs, and write the checksum into the EXCL record.
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

- **Same GlobalTypeId, same content hash:** Suppress (silent dedup). The type is already in the collection.
- **Same GlobalTypeId, different content hash:** Log the collision with details (file, type index, both hashes) in `collidingAsts` map. Apply first-writer-wins: retain the existing body, discard the new one.
- **Different GlobalTypeId:** Always add both to the collection.

**XRef resolution:** When a type expression contains `TypeDecl.XRef(kind, tag)` (a forward reference to a struct/union/enum), `appendAsts()` replaces the XRef body with a concrete definition (`TypeDecl.Struct`, etc.) if both are encountered for the same `GlobalTypeId`.

### The 207 xapasmcsr Collisions

The xapasmcsr binary (CSR XAP assembler, circa 2005) exhibits 207 collision log lines involving `GlobalTypeId` pairs with the same ID but different content hashes.

**Root cause (per design audit):** Nested `Ref` types inside struct fields whose resolved hash diverges across CUs. Example:

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

**Source:** **bfd/stabs.c** `_bfd_link_section_stabs()` (entire function); **gdb/stabsread.c** `add_old_header_file()` (lines 413–438); **ghistabs/parser/Harvest.kt** `appendAsts()`; integration log `src/test/resources/logs/xapasmcsr.after.log` (collision lines); harvest JSON `src/test/resources/harvests/xapasmcsr-harvest.json` (`collidingAsts` field).

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

After globalization, `walkDefinitions()` performs a second pass through the tree, collecting all `TypeAst` nodes emitted by `InlineDef` side effects.

- **Purpose:** Ensure that every type node, no matter how deeply nested, is added to the global `TypeAst` collection via `appendAsts()`.
- **Behavior:** Visits all nodes in depth-first order; when an `InlineDef` is encountered, yields the emitted `TypeAst`.

### Deep Nesting Example

Consider a struct field whose type is `Ref(3, 12)` (reference to type 12 in fileNum 3, a header):

**CU1 (correct BINCL):**
- Processes `N_BINCL header.h` with checksum C, allocating fileNum 3.
- `headerRegistry.getOrInsert("header.h", C, CU1)` returns `HeaderFile(name="header.h", checksum=C, originatingCu=CU1)`.
- `fileNumToHeader[3] = HeaderFile_C`.
- Struct field `Ref(3, 12)` globalizes via `sourceFor((3, 12))` → `HeaderSource(HeaderFile_C)` → `GlobalTypeId(HeaderSource(HeaderFile_C), 12)`.

**CU2 (forward EXCL before BINCL):**
- Processes `N_EXCL header.h` with checksum C before any BINCL has been seen.
- `headerRegistry.recall("header.h", C)` creates placeholder `HeaderFile(name="header.h", checksum=C, originatingCu=null)` (NOT in global registry).
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

**Source:** **gdb/stabsread.c** `read_type()` (lines 1900–2200), `read_struct_fields()` (lines 3200–3350); **ghistabs/parser/Harvest.kt** `globalize()` (recursive descent), `walkDefinitions()` (side-effect collection).

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

**Source:** stabs PDF §4.6 ("Cross-References"); **gdb/stabsread.c** `read_cross_ref()` (lines 2950–3000).

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

- `HeaderRegistry.recall()` creates a placeholder `HeaderFile(filename, checksum, originatingCu=null)` and stores it ONLY in the local `fileNumToHeader` map.
- The placeholder is NOT added to `globalByFilenameChecksum`.
- When `HeaderRegistry.getOrInsert()` processes the real BINCL in a later CU, it looks up `(filename, checksum)` in the global table. Since the placeholder was never added, a NEW `HeaderFile` instance is created and stored.
- The earlier CU's types are attributed to the placeholder instance; later CU's types are attributed to the real instance → **divergent GlobalTypeIds** → **hash collisions in `appendAsts()`**.

**Diagnostic:** `HeaderRegistry.recall()` emits a log message `log("forward-excl", ...)` when a forward EXCL is detected. This allows the audit (Phase 3) to identify which collisions stem from this deviation.

**Implication:** The forward-EXCL case is a known source of false collisions. Fixing it would require either:

1. **Patching approach:** Storing the placeholder in the global registry and updating it when the BINCL arrives (GDB's strategy).
2. **Deferred globalization:** Deferring type globalization until all BINCL/EXCL records have been processed, ensuring all fileNum-to-HeaderFile mappings are stable.
3. **Eager patching in memory:** Scanning the CU sequence to detect forward EXCL, pre-allocating all HeaderFile instances upfront, and sharing them from the start.

Option 1 is closest to GDB and easiest to implement.

**Source:** **gdb/stabsread.c** `add_old_header_file()` (lines 413–438), `add_new_header_file()` (lines 390–410); **ghistabs/parser/IncludeContext.kt** `HeaderRegistry.recall()`; **stabs PDF** §7.1 ("Include Files").

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
  - `add_new_header_file()` (lines 390–410) - Create new header entry
  - `add_old_header_file()` (lines 413–438) - Reuse or create placeholder header entry
  - `this_object_header_files[]` - Per-CU header file array (declared near top of file)
  - `start_symtab()` / `end_symtab()` - CU open/close

- **GCC dbxout.c** (GCC source tree, 3.x–4.x era):
  - `dbxout_type()` - Type emission
  - Continuation line handling in type string emission

- **ghistabs codebase:**
  - **ghistabs/parser/IdInterface.kt** - `LocalTypeId`, `GlobalTypeId`, `SourceFile` definitions
  - **ghistabs/parser/IncludeContext.kt** - `HeaderRegistry`, `HeaderFile`, `sourceFor()` contract
  - **ghistabs/parser/Harvest.kt** - `globalize()`, `walkDefinitions()`, `appendAsts()`
  - **src/test/resources/logs/xapasmcsr.after.log** - 207 collision log lines (xapasmcsr binary)
  - **src/test/resources/harvests/xapasmcsr-harvest.json** - `collidingAsts` map from same binary

- **CSR/Qualcomm ecosystem:**
  - ADK 4.0.1 sink firmware (QC35 II) compiled with GCC 3.4.4 (Cygwin), the primary reference for stabs emission patterns in this project
