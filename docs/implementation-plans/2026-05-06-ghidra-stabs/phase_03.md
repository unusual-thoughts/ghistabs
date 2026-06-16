# ghidra-stabs Phase 3: Type building

**Goal:** Materialise Ghidra `DataType`s from the AST: primitives, structs, unions, enums, arrays, pointers, references,
function definitions, recursive types — all deduped across CUs and filed under a sensible `CategoryPath`.

**Architecture:** Pass-2 walker over the parser's `TypeDecl` tree. `TypeRegistry` is the single owner of
`(TypeId, n) → DataType` resolution and `(name, body-hash) → canonical DataType` cross-CU dedup. `Attribution` is a pure
function deciding category placement. Recursive types are handled by registering a placeholder DataType BEFORE recursing
into the body, then patching its members in place.

**Tech Stack:** Kotlin 2.3.21, Ghidra `DataTypeManager` API, `ProgramBuilder` for Ring-2 tests, JUnit 5.

**Scope:** Phase 3 of 6.

**Codebase verified:** 2026-05-07.

**Codebase verification findings:**

- ✓ Phase 2 lands the AST. This phase imports `ghistabs.parse.*`.
- ✓ Ghidra `DataTypeManager` API is at `ghidra.program.model.data.DataTypeManager`. Key methods:
  `addDataType(DataType, DataTypeConflictHandler)`, `getDataType(CategoryPath, String): DataType?`,
  `getCategory(CategoryPath): Category`, `createCategory(CategoryPath): Category`.
- ✓ `CategoryPath` constructor takes a `/`-delimited path: `CategoryPath("/std/string")`. Root is `CategoryPath.ROOT`.
- ✓ Built-ins available via `program.dataTypeManager.getDataType("/byte")` etc., or via
  `BuiltInDataTypeManager.getDataTypeManager()` for cross-program lookups. Concrete classes: `IntegerDataType`,
  `LongLongDataType`, `BooleanDataType`, `FloatDataType`, `DoubleDataType`, `Complex8DataType`, `Complex16DataType`,
  `CharDataType`, `WideCharDataType`, `VoidDataType`, `Undefined1DataType` … Undefined8.
- ✓ `StructureDataType(CategoryPath, String, int length, DataTypeManager dtm)` — length 0 is "auto-grow", positive is "
  fixed". `replaceAtOffset(offset, type, len, name, comment)` is for static-position layout. We use `add(component)` for
  sequential append.
- ✓ Cycle handling: `StructureDataType` allows `add(...)` of a `Pointer` to a not-yet-resolved type via
  `DataTypeManager.getDataType(path)` returning a `DataType` proxy that updates when the real type lands. Confirmed by
  reading `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/StructureDataType.java`.
- ✓ `MSDataTypeUtils.getMatchingDataType(...)` exists and is intended for Microsoft-binary type unification — for our
  purposes we use `dtm.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER)` and let the manager dedup by full path.
  The (name, body-hash) layer is OUR concern, not the DTM's.
- ✓ `ProgramBuilder` lives at `ghidra.test.ProgramBuilder` (
  `Ghidra/Framework/SoftwareModeling/src/test.slow/java/ghidra/test/ProgramBuilder.java`). Constructor
  `ProgramBuilder(name, language)`; method `getProgram()` returns a fully-functional `Program`. Languages we'll use for
  tests: `_LE_` LP32 (closest match to XAP/x86 32-bit) — `ProgramBuilder._X86`. The implementor confirms by trial.

**External dependency findings:**

- 📖 **`DataTypeConflictHandler.REPLACE_HANDLER`** vs `KEEP_HANDLER` vs `DEFAULT_HANDLER`: REPLACE keeps the new one if
  conflict, KEEP keeps the old. We want KEEP (the canonical / first-seen wins) to avoid overwriting a multi-CU
  consolidated type with a later partial. Confirm by reading
  `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/DataTypeConflictHandler.java`.
- 📖 **Itanium ABI 32-bit struct layout:** size is the sum of field sizes plus padding to align each field to its natural
  alignment (alignment = sizeof(field) for primitives, max-alignment-of-fields for nested aggregates). The stabs
  descriptor carries `<size>` explicitly; we trust it and lay out fields at the offsets the stab provides, padding with
  `Undefined` if needed.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### ghidra-stabs.AC3: Type resolution, dedup, and attribution

- **ghidra-stabs.AC3.1 Success:** Two CUs that emit the same `(name, body)` produce a single canonical Ghidra
  `DataType`; the second emission is dropped, no duplicate appears in the DTM.
- **ghidra-stabs.AC3.2 Success:** Two CUs that emit the same `name` with different bodies produce two distinct
  DataTypes (`Foo`, `Foo_2`), and a `[Stabs] type-conflict` log entry references both CUs.
- **ghidra-stabs.AC3.3 Success:** A type defined in a single header is materialised at category `/<header-basename>/`. A
  multi-CU clean-named type that appears only in `.cpp` files lands at `/headers-untracked/<name>.h`. A type whose
  defining file path contains `/mingw/`, `/cygwin/`, `/c++/`, or `/bits/` lands at `/std/<basename>/`. A multi-CU
  template-instantiation name lands at `/<canonical-cu>/instantiations/`.
- **ghidra-stabs.AC3.4 Success:** Recursive types (struct contains pointer to itself; mutually recursive struct A → B →
  A) resolve via the cycle-breaker placeholder mechanism without throwing or producing partially-populated structs.
- **ghidra-stabs.AC3.5 Success:** On `xapasmcsr.exe`, ≥ 80 "interesting" project typenames (per the Phase 1 stats
  output's `INTERESTING project typenames` list) are present in the DTM after import.

(AC3.5 is asserted by Phase 6's integration test against the real binary; this phase's tests use synthetic ASTs.)

---

## Implementation Tasks

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->

### Task 1: `Attribution` — pure CategoryPath chooser

**Files:**

- Create: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/builder/Attribution.kt`

**Implementation:**

Pure function. No Ghidra mutation. Takes the type's name + the set of CUs that defined it + the set of source-file
paths (from N_SOL records) seen alongside those definitions. Returns a `CategoryPath`.

Decision tree (from design):

1. If ANY defining file path matches `Regex("/(mingw|cygwin|c\\+\\+|bits)/")`, the type is std/system: pick the
   most-specific path-segment after the matched marker as the basename, return `CategoryPath("/std/<basename>")`.
   Example: `/usr/include/c++/3.4.4/string` → basename = `string` → `/std/string`.
2. Else if defined in EXACTLY ONE CU and the CU's filename ends with `.h` / `.hpp` / `.hh` / `.H`: it's a project
   header. Return `CategoryPath("/" + basename-no-ext)`.
3. Else if defined in EXACTLY ONE CU with a `.c` / `.cpp` / `.cc` extension: it's a CU-private type. Return
   `CategoryPath("/" + cu-basename-no-ext)`.
4. Else (multi-CU). Check the name:
    - `cleanName(name)`: returns true iff `name` contains none of `<>,:` AND does not start with `_` AND is not in the
      C/C++ builtin set (`int`, `unsigned`, `void`, etc.). The builtin set is a fixed
      `setOf("int", "char", "short", "long", "float", "double", "void", "bool", "_Bool", "signed", "unsigned")` — extend
      as needed.
    - If clean: `CategoryPath("/headers-untracked/" + name.h)` — a synthetic header bucket.
    - If unclean (template instantiation, mangled name, leading-underscore): pick the lexicographically-first defining
      CU as canonical, return `CategoryPath("/<canonical-cu>/instantiations")`.

```kotlin
package ghistabs.materialize

import ghidra.program.model.data.CategoryPath

object Attribution {
    private val STD_MARKERS = Regex("""/(mingw|cygwin|c\+\+|bits)/""")
    private val UNCLEAN_CHARS = Regex("""[<>,:]""")
    private val BUILTIN_NAMES = setOf(
        "int", "char", "short", "long", "long long", "float", "double", "long double",
        "void", "bool", "_Bool", "signed", "unsigned", "size_t", "ptrdiff_t",
    )

    /**
     * @param typeName e.g. "vector", "std::basic_string<char,…>", "Foo".
     * @param definingCUs the .c/.cpp/.h files that emitted a definition. Std-
     *                    header detection runs over this set (the std markers
     *                    appear in defining-CU paths when gcc emitted the
     *                    definition there).
     */
    fun categoryFor(
        typeName: String,
        definingCUs: Set<String>,
    ): CategoryPath { /* ... */
    }

    private fun isClean(name: String): Boolean =
        !UNCLEAN_CHARS.containsMatchIn(name) &&
                !name.startsWith("_") &&
                name !in BUILTIN_NAMES

    private fun stdBasename(path: String): String? { /* find STD_MARKERS, return last non-empty path segment */
    }
    private fun basename(path: String): String { /* drop dir, drop extension */
    }
}
```

**Step: Commit (after writing tests in Task 2)**

**Verifies:** None directly — exercised in Task 2.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->

### Task 2: `AttributionTest` — every row in the decision tree (Ring-1)

**Files:**

- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/builder/AttributionTest.kt`

**Tests must verify (`ghidra-stabs.AC3.3`):**

(All test inputs use the 2-arg signature `categoryFor(name, definingCUs)`.)

- Std header — `definingCUs = {"/usr/include/c++/3.4.4/string"}`, name = `basic_string` ⇒ `/std/string`.
- Std header (mingw) — `definingCUs = {"/usr/include/mingw/stdint.h"}`, name = `int32_t` ⇒ `/std/stdint`.
- Single header (project) — `definingCUs = {"/proj/include/foo.h"}`, name = `Foo` ⇒ `/foo`.
- Single CU (project) — `definingCUs = {"/proj/src/main.cpp"}`, name = `LocalThing` ⇒ `/main`.
- Multi-CU clean name — `definingCUs = {"/proj/a.cpp", "/proj/b.cpp"}`, name = `Shared` ⇒ `/headers-untracked/Shared.h`.
- Multi-CU unclean name (template instantiation) — `definingCUs = {"/proj/b.cpp", "/proj/a.cpp"}`, name =
  `vector<int,allocator<int>>` ⇒ `/a/instantiations` (canonical CU lexicographically first).
- Multi-CU leading-underscore — `definingCUs = {"/proj/a.cpp", "/proj/b.cpp"}`, name = `__internal` ⇒
  `/a/instantiations`.
- Multi-CU builtin-named (impossible-but-defensive) — `definingCUs = {"/proj/a.cpp", "/proj/b.cpp"}`, name = `int` ⇒
  `/a/instantiations` (treated as unclean since it matches a builtin).

**Step: Run, commit (Task 1 + Task 2 together)**

```bash
./gradlew test --tests 'ghistabs.materialize.AttributionTest'
git add src/main/kotlin/ghistabs/builder/Attribution.kt src/test/kotlin/ghistabs/builder/AttributionTest.kt
git commit -m "feat(builder): Attribution category-path picker + tests"
```

**Verifies:** `ghidra-stabs.AC3.3`.
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_SUBCOMPONENT_B (tasks 3-4) -->

<!-- START_TASK_3 -->

### Task 3: `BuiltinTable` — primitive-form → Ghidra builtin DataType

**Files:**

- Create: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/builder/BuiltinTable.kt`

**Implementation:**

Pure mapping from a "primitive shape descriptor" (the parser's `TypeDecl.Range`, `TypeDecl.Complex`,
`TypeDecl.WithSizeAttr`, and the parser's eventual canonical builtin names) to a Ghidra builtin `DataType`.

The rule of thumb from the design:

- `r(0,N);min;max;` with min/max forming a signed [−2^(W−1), 2^(W−1)−1] range → `IntegerDataType` of size W bits.
- `r(0,N);0;<umax>;` with umax = 2^W − 1 → `UnsignedIntegerDataType` of size W bits.
- `@s<n>;<inner>` where inner is an integer range → builtin of `<n>` bits (width override). E.g. `@s64;r(0,6);…` →
  `LongLongDataType`.
- `@s8;-16` (the `_Bool` form) → `BooleanDataType`.
- `R3;8;0;` → `Complex8DataType` (single-precision complex).
- `R4;16;0;` → `Complex16DataType` (double-precision complex).
- `R5;<size>;0;` → mapped to whichever Ghidra type matches the requested size (likely a long-double complex; if no exact
  builtin exists, fall back to `Complex16DataType` and log).

API:

```kotlin
package ghistabs.materialize

import ghidra.program.model.data.*

object BuiltinTable {
    /** Resolve a primitive-shaped TypeDecl to a builtin Ghidra DataType, or null if not a primitive. */
    fun resolve(decl: ghistabs.parse.TypeDecl, dtm: DataTypeManager): DataType?
}
```

The implementation matches on `decl` shape, derives the bit-width, and returns the builtin. For sizes Ghidra has no
exact match for, return `null` and let `TypeRegistry` fall back to a generic `StructureDataType` of the correct size
with `Undefined` filler.

**Step: Commit (after Task 4 tests)**

**Verifies:** None directly — exercised in Task 4 + Task 6.
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->

### Task 4: `BuiltinTableTest` — every primitive form (Ring-1)

**Files:**

- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/builder/BuiltinTableTest.kt`

**Tests must verify (`ghidra-stabs.AC2.2`/`AC2.3` re-verified at the type-mapping layer):**

The DTM in Ring-1 tests is `BuiltInDataTypeManager.getDataTypeManager()` (a static singleton — no Program needed).

- `Range(of=(0,1), min=-2147483648, max=2147483647)` → instance of `IntegerDataType` with `length == 4`.
- `Range(of=(0,1), min=0, max=4294967295)` → `UnsignedIntegerDataType`, length 4.
- `Range(of=(0,1), min=0, max=255)` → `UnsignedCharDataType`, length 1.
- `WithSizeAttr(64, Range((0,6), 0, -1))` → `LongLongDataType` (the `_Bool`-style overflow case for ull max).
- `WithSizeAttr(8, Ref(TypeId(0,-16)))` (the `_Bool` shape) → `BooleanDataType`.
- `Complex(rCode=3, sizeBytes=8)` → `Complex8DataType`.
- `Complex(rCode=4, sizeBytes=16)` → `Complex16DataType`.
- A non-primitive (e.g. `Pointer(Ref((0,1)))`) → `null` (signals "not a builtin").

**Step: Run, commit**

```bash
./gradlew test --tests 'ghistabs.materialize.BuiltinTableTest'
git add src/main/kotlin/ghistabs/builder/BuiltinTable.kt src/test/kotlin/ghistabs/builder/BuiltinTableTest.kt
git commit -m "feat(builder): BuiltinTable primitive mapper + tests"
```

**Verifies:** `ghidra-stabs.AC2.2`, `ghidra-stabs.AC2.3` (mapping side; parser side covered in Phase 2).
<!-- END_TASK_4 -->

<!-- END_SUBCOMPONENT_B -->

<!-- START_SUBCOMPONENT_C (tasks 5-7) -->

<!-- START_TASK_5 -->

### Task 5: `TypeRegistry` core — id resolution, content-hash dedup, conflict naming

**Files:**

- Create: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/builder/TypeRegistry.kt`

**Implementation:**

```kotlin
package ghistabs.materialize

import ghidra.program.model.data.*
import ghistabs.importer.BookmarkSink
import ghistabs.parse.TypeDecl
import ghistabs.parse.TypeId

/** Per-type metadata accumulated during pass A. */
data class TypeAst(
    val id: TypeId,
    val name: String,
    val body: TypeDecl,
    val cuFile: String,
)

class TypeRegistry(
    private val dtm: DataTypeManager,
    private val sink: BookmarkSink,
) {
    private val byId: MutableMap<TypeId, DataType> = mutableMapOf()
    private val byHash: MutableMap<Pair<String, ContentHash>, DataType> = mutableMapOf()
    private val placeholders: MutableMap<TypeId, DataType> = mutableMapOf()
    private val conflictCount: MutableMap<String, Int> = mutableMapOf()

    /**
     * Pass-2 entry point. Walks every TypeAst in dependency-friendly order and
     * materialises a Ghidra DataType for each, deduping cross-CU and breaking
     * cycles via placeholders.
     */
    fun materialiseAll(asts: List<TypeAst>, attribution: (String, Set<String>) -> CategoryPath) {
        // Group by name for dedup and cu-set computation
        val byName = asts.groupBy { it.name }
        for (ast in asts) {
            resolve(ast, byName, attribution)
        }
    }

    /**
     * Lookup-or-build a Ghidra DataType for an arbitrary TypeDecl. Used by
     * Pass C (functions/locals/globals/classes) to convert AST type nodes
     * to Ghidra DataTypes on demand. Returns null if the decl cannot be
     * mapped (rare — e.g. dangling Ref into a non-existent CU).
     *
     * For TypeDecl.Ref(id) — looks up `byId[id]` (placeholder or final).
     * For primitive shapes — delegates to BuiltinTable.resolve.
     * For Pointer/Array/etc — recurses to the underlying form.
     * Caller MUST be inside a DTM transaction since lookups may register
     * transient builtins.
     */
    fun dataTypeFor(decl: TypeDecl): DataType? = when (decl) {
        is TypeDecl.Ref -> byId[decl.id]
        is TypeDecl.Builtin, is TypeDecl.Range, is TypeDecl.Complex,
        is TypeDecl.WithSizeAttr -> BuiltinTable.resolve(decl, dtm)
        is TypeDecl.Pointer -> dataTypeFor(decl.pointee)?.let { PointerDataType.getPointer(it, dtm) }
        is TypeDecl.Reference -> dataTypeFor(decl.referent)?.let { PointerDataType.getPointer(it, dtm) }
        is TypeDecl.Const -> dataTypeFor(decl.inner)
        is TypeDecl.Volatile -> dataTypeFor(decl.inner)
        is TypeDecl.Array -> dataTypeFor(decl.element)?.let {
            ArrayDataType(it, (decl.length ?: 0L).toInt(), it.length)
        }
        is TypeDecl.Enum, is TypeDecl.Struct, is TypeDecl.FunctionT,
        is TypeDecl.Method, is TypeDecl.XRef ->
            // Synthesise on demand via the same path materialiseBody uses
            // for inline types. Reuses the builder helper.
            buildInlineType(decl)
    }

    private fun buildInlineType(decl: TypeDecl): DataType? {
        // Helper that constructs Enum/Struct/etc as anonymous DataTypes when
        // they appear inline (e.g. an unnamed inner struct field). Same logic
        // as materialiseBody but without a name/category hook. The
        // implementor extracts shared code in Task 6 cleanup.
        TODO("share with materialiseBody — extract in Task 6")
    }

    /** Resolve one TypeAst recursively, registering placeholders as needed. */
    private fun resolve(
        ast: TypeAst,
        byName: Map<String, List<TypeAst>>,
        attribution: (String, Set<String>) -> CategoryPath,
    ): DataType {
        byId[ast.id]?.let { return it }
        // Compute content hash of the body BEFORE materialising — used for cross-CU dedup.
        val hash = ContentHash.of(ast.body)
        byHash[ast.name to hash]?.let { existing ->
            byId[ast.id] = existing
            return existing
        }
        // Register a placeholder so recursive references inside the body terminate.
        val cus = byName[ast.name].orEmpty().map { it.cuFile }.toSet()
        val category = attribution(ast.name, cus)
        val placeholder = StructureDataType(category, ast.name, 0, dtm)
        placeholders[ast.id] = placeholder
        byId[ast.id] = placeholder
        // Materialise body. For struct/union: lay out fields, replacing the placeholder in place.
        val materialised = materialiseBody(ast, category, placeholder)
        // If the materialised result IS the placeholder (in-place), commit to dtm.
        // Otherwise (e.g. a typedef that resolves to a builtin), swap byId.
        val canonical = registerWithConflict(materialised, ast.name, hash, ast.id)
        byHash[ast.name to hash] = canonical
        return canonical
    }

    private fun materialiseBody(ast: TypeAst, category: CategoryPath, placeholder: DataType): DataType {
        // Dispatch on TypeDecl variant — Pointer/Reference/Array/Struct/Enum/etc.
        // For Struct: cast `placeholder` to StructureDataType and `add(...)` each field's resolved DataType.
        // For Pointer: return PointerDataType.getPointer(resolved-pointee, dtm).
        // For Array: return ArrayDataType(elementType, length, elementSize).
        // For Enum: return EnumDataType(category, name, sizeBytes, dtm) with `add(name, value)`.
        // For Ref(id): recurse via resolve(byId[id]) — placeholder will be returned if cycle.
        TODO("complete in Task 6 with cycle-handling tests")
    }

    /**
     * Add the materialised DataType to the DTM. If a conflict arises (different body
     * than an existing entry of the same name+category), suffix `_2`, `_3`, … and log.
     */
    private fun registerWithConflict(dt: DataType, name: String, hash: ContentHash, id: TypeId): DataType {
        val existing = dtm.getDataType(dt.categoryPath, name)
        return if (existing == null) {
            dtm.addDataType(dt, DataTypeConflictHandler.KEEP_HANDLER)
        } else {
            // Same canonical hash already registered? Then we're idempotent.
            val existingHash = ContentHash.ofDataType(existing)
            if (existingHash == hash) {
                existing
            } else {
                // Find a free `<name>_N` slot. setName can throw
                // DuplicateNameException if a stale conflict suffix collides
                // (e.g. two re-imports without a flag clear); bump N until free.
                var n = (conflictCount[name] ?: 1) + 1
                var renamed: DataType? = null
                while (renamed == null && n < 1000) {
                    val candidate = "${name}_$n"
                    if (dtm.getDataType(dt.categoryPath, candidate) != null) {
                        n++; continue
                    }
                    val copy = dt.copy(dtm)
                    try {
                        copy.name = candidate
                        renamed = copy
                    } catch (e: ghidra.util.exception.DuplicateNameException) {
                        n++
                    } catch (e: ghidra.util.exception.InvalidNameException) {
                        // Should not happen for `<name>_N` patterns; rethrow.
                        throw e
                    }
                }
                checkNotNull(renamed) { "could not allocate conflict suffix for '$name'" }
                conflictCount[name] = n
                sink.log(
                    "type-conflict",
                    "Two definitions of '$name' with different bodies; renamed second to '${name}_$n'."
                )
                dtm.addDataType(renamed, DataTypeConflictHandler.KEEP_HANDLER)
            }
        }
    }
}

/** Stable hash of a TypeDecl body for cross-CU dedup. */
@JvmInline
value class ContentHash(val v: Long) {
    companion object {
        fun of(decl: TypeDecl): ContentHash { /* stable serialisation, then hash */ TODO()
        }
        fun ofDataType(dt: DataType): ContentHash { /* serialise field layout, then hash */ TODO()
        }
    }
}
```

**`dataTypeFor` is the single Pass C / ClassBuilder entry point.** Phase 4 and Phase 5 consume it; this phase owns its
definition and behavior so Phase 4 doesn't retroactively edit Phase 3 code.

**ContentHash design choice:** structural hashing of the AST. Visit every node, append a tag byte for the variant kind
plus the relevant primitive fields (sizes, names, type-id refs). Use `Long.hashCode()` on the combined byte array (or
`kotlin.collections.contentHashCode`). The hash is approximate (collisions theoretically possible) but for our
purposes — tens of thousands of types per binary — collision probability is negligible.

**Step: Commit (after Task 7 tests)**

**Verifies:** Internal scaffolding for AC3.1, AC3.2.
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->

### Task 6: Implement `materialiseBody` for every `TypeDecl` variant + cycle handling

**Files:**

- Modify: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/builder/TypeRegistry.kt:materialiseBody`

**Implementation:**

Fill in the `TODO` from Task 5. Per-variant handling:

- `TypeDecl.Builtin` / `WithSizeAttr` / `Range` / `Complex` — delegate to `BuiltinTable.resolve(decl, dtm)`. If
  non-null, return that. If null (e.g. exotic size), fall back to `StructureDataType(category, name, sizeBytes, dtm)` of
  the right total size with `Undefined` filler.
- `TypeDecl.Pointer(pointee)` — `PointerDataType.getPointer(resolvePointee(pointee), dtm)`. If `pointee` is a `Ref(id)`
  for which we have a placeholder, the pointer's pointee is the placeholder (Ghidra resolves the indirection
  automatically when the placeholder is replaced with the real type later).
- `TypeDecl.Reference(referent)` — same as Pointer but flagged. Ghidra has no first-class reference type; we use
  `PointerDataType` and add a comment "C++ reference" via `Pointer.setDescription(...)` if the API allows.
- `TypeDecl.Const(inner)` — Ghidra has no const qualifier; resolve `inner` and return it. Drop the const information (or
  stash it in a comment if required by future work; not for v1).
- `TypeDecl.Volatile(inner)` — same as Const.
- `TypeDecl.Array(element, length, _)` — `ArrayDataType(resolveElement(element), length.toInt(), elementSize)`. If
  `length == null` (open-ended), default to `0` (Ghidra interprets as flexible array member).
- `TypeDecl.Enum(members)` — `EnumDataType(category, name, sizeBytes ?: 4, dtm)`, then for each member
  `enum.add(memberName, memberValue)`.
- `TypeDecl.Struct` — already initialised as a `StructureDataType` placeholder. Cast and call
  `add(fieldType, fieldName, comment)` in field-offset order; pad with `DataType.DEFAULT` (Undefined) where needed. Set
  the structure's overall length to `sizeBytes` via `setLength` if API permits, else use `replaceAtOffset` to write
  fields at exact offsets.
    - For union: use `UnionDataType` instead (different class; same `add` API).
- `TypeDecl.FunctionT(ret, params)` — `FunctionDefinitionDataType(category, name, dtm)`, then
  `setReturnType(resolve(ret))`,
  `setArguments(params.mapIndexed { i, p -> ParameterDefinitionImpl("arg$i", resolve(p), null) }.toTypedArray())`.
- `TypeDecl.Method(...)` — same as `FunctionT` but the first parameter is a pointer-to-class (the implicit `this`).
- `TypeDecl.XRef(kind, tagName)` — return a stub `StructureDataType(category, tagName, 1, dtm)`. The real definition
  will land later (or never, if the type is genuinely incomplete in the binary). Mark with a `[Stabs] xref-stub` log on
  creation.
- `TypeDecl.Ref(id)` — recurse to `resolve()` of the referent's `TypeAst` (looked up via a separate `byId` index built
  once at the start of `materialiseAll`). If the referent isn't in the index, return `Undefined4DataType` (4-byte
  placeholder) and log `[Stabs] dangling-ref`.

**Cycle test specifically asserted in Task 7:**

- Self-pointer (`struct A { A* next; }`): `resolve` is called for A, registers the placeholder, recurses into the body.
  The body has one field of type `Pointer(Ref(A.id))`. Resolving that pointer's pointee finds the placeholder via
  `byId`, returns it. The pointer is added to the struct as a 4-byte field. No infinite recursion.
- Mutually recursive (`A → B → A`): `resolve(A)` registers A's placeholder, recurses; A has a field of type
  `Pointer(Ref(B.id))`. We call `resolve(B)`. B registers its placeholder, recurses; B has a field of type
  `Pointer(Ref(A.id))`. `resolve(A)` finds A's placeholder in `byId`, returns it. B's struct is populated, returned.
  Back in A's resolution, the pointer-to-B is added. Done.

**Step: Run tests, commit (with Task 7)**

**Verifies:** AC3.4 (cycle handling).
<!-- END_TASK_6 -->

<!-- START_TASK_7 -->

### Task 7: `TypeRegistryTest` (Ring-2) — dedup, conflict, recursion, multi-CU attribution

**Files:**

- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/builder/TypeRegistryTest.kt`

**Setup helper:**

```kotlin
private fun newProgramAndDtm(): Triple<Program, DataTypeManager, BookmarkSink> {
    val pb = ProgramBuilder("test", ProgramBuilder._X86)
    val program = pb.program
    val log = MessageLog()
    val sink = BookmarkSink(program, log)
    return Triple(program, program.dataTypeManager, sink)
}
```

The sink uses a real `Program` from `ProgramBuilder` rather than a mock —
`BookmarkManager` and `MessageLog` are both available on the real instance
and exercise our diagnostics for free. If a unit test must NOT touch a
program (pure-Kotlin Ring-1), construct `BookmarkSink` with `Mockito.mock(Program::class.java)`
and a real `MessageLog()`; tag the test with `@Tag("ring1")` and skip if
ProgramBuilder isn't on the classpath.

**Tests must verify:**

- **`ghidra-stabs.AC3.1`** (cross-CU dedup): construct two `TypeAst` entries with the same name `Foo` and the same
  body (a 2-field struct of identical fields), but different CUs. Call `materialiseAll`. Assert
  `dtm.getAllDataTypes().count { it.name == "Foo" } == 1`. Assert no `[Stabs] type-conflict` log entries.

- **`ghidra-stabs.AC3.2`** (cross-CU conflict): same name `Foo`, different bodies (one is `{int x; int y;}`, the other
  is `{int x; float y;}`). Assert `dtm.getAllDataTypes().count { it.name == "Foo" } == 1` AND
  `dtm.getAllDataTypes().count { it.name == "Foo_2" } == 1`. Assert exactly one `[Stabs] type-conflict` log entry that
  mentions both CU paths.

- **`ghidra-stabs.AC3.4`** (self-cycle): single AST `Node` with body
  `Struct(STRUCT, 8, [], [FieldDecl("next", Pointer(Ref(Node.id)), 0, 32, false), FieldDecl("val", Range((0,1), -2^31, 2^31-1), 32, 32, false)], [], false, null)`.
  `materialiseAll` completes without StackOverflow. The materialised `Node` has length 8, two fields, and the first
  field's data type is `Node *`.

- **`ghidra-stabs.AC3.4`** (mutual cycle): two ASTs `A` and `B` where A has a `B*` field and B has an `A*` field.
  `materialiseAll` completes; both structs have length matching the stab payload; both are present in DTM; both pointer
  fields point at the correct opposing struct.

- **`ghidra-stabs.AC3.3`** (attribution at materialisation time): `Foo` defined once in `/proj/foo.h`. After
  `materialiseAll`, `dtm.getDataType(CategoryPath("/foo"), "Foo") != null`.

**Step: Run, commit**

```bash
./gradlew test --tests 'ghistabs.materialize.TypeRegistryTest'
git add src/main/kotlin/ghistabs/builder/TypeRegistry.kt \
        src/test/kotlin/ghistabs/builder/TypeRegistryTest.kt
git commit -m "feat(builder): TypeRegistry (dedup, conflict naming, cycles) + tests"
```

**Verifies:** `ghidra-stabs.AC3.1`, `ghidra-stabs.AC3.2`, `ghidra-stabs.AC3.3` (materialisation half),
`ghidra-stabs.AC3.4`.
<!-- END_TASK_7 -->

<!-- END_SUBCOMPONENT_C -->

---

## Phase Done When

- [ ] `builder/Attribution.kt` exports `Attribution.categoryFor(...)`.
- [ ] `builder/BuiltinTable.kt` exports `BuiltinTable.resolve(...)`.
- [ ] `builder/TypeRegistry.kt` exports `TypeRegistry`, `TypeAst`, `ContentHash`.
- [ ] `AttributionTest`, `BuiltinTableTest`, `TypeRegistryTest` all green.
- [ ] No infinite recursion on self-pointer or A↔B mutual cycle (tests time-out if they regress).
- [ ] AC3.5 (≥80 typenames on real binary) deferred to Phase 6 integration test.

## Open Questions for User

- **Should we preserve `const`/`volatile` qualifiers somewhere?** Ghidra has no first-class const datatype; v1 drops
  them. Acceptable?
- **Reference types as `Pointer` with comment "C++ reference"** — OK or should we use a different convention?
