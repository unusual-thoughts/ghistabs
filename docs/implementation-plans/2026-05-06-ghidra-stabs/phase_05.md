# ghidra-stabs Phase 5: Classes & vtables

**Goal:** Recover full C++ class layout — struct fields, nested namespaces, member functions re-parented under their
class with ctor/dtor variant disambiguation, vtable structs synthesised and applied at `_ZTV<class>` addresses,
polymorphic class `{vfptr}` first-field annotation.

**Architecture:** `builder/Classes.kt` provides `ClassBuilder` — a stateful object created per import that materialises
classes after `TypeRegistry` has run and after Pass C has created the function entries. It derives namespaces from class
names (handling templated names), re-parents member functions, builds vtable `Structure`s, and applies them at the
resolved `_ZTV` address. FCIS-bending is unavoidable here since we mutate `Program`; this layer is part of the
imperative shell.

**Tech Stack:** Kotlin 2.3.21, Ghidra `GhidraClass` / `Namespace` / `SymbolTable` / `ClassUtils.VFPTR` / `GnuDemangler`
APIs.

**Scope:** Phase 5 of 6.

**Codebase verified:** 2026-05-07.

**Codebase verification findings:**

- ✓ `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/symbol/SymbolTable.java`:
  `createClass(parent: Namespace?, name: String, source: SourceType): GhidraClass`. Parent `null` ⇒ global namespace.
- ✓ `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/app/util/NamespaceUtils.java`:
  `convertNamespaceToClass(Namespace): GhidraClass` for upgrading existing namespaces.
  `getNamespaceByPath(program, parent, "Foo::Bar"): Namespace` resolves a `::`-separated path.
- ✓ `ClassUtils.VFPTR` (
  `/home/riton/git/ghidra/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/gclass/ClassUtils.java`)
  is the canonical name string `"{vfptr}"` we use for the vtable-pointer field.
- ✓ `ghidra.app.util.demangler.gnu.GnuDemangler` — its `demangle(MangledContext)` returns `DemangledFunction` with
  `getNamespace()` (a `DemangledType` chain) and `getName()` (the bare member name). Reference:
  `Ghidra/Features/GnuDemangler/src/main/java/ghidra/app/util/demangler/gnu/GnuDemangler.java`.
- ✓ `Function.setParentNamespace(Namespace)` exists at
  `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/Function.java`.
- ✓ Ctor/dtor mangled forms per Itanium ABI: `_ZN<…>C1E…` / `C2E…` / `C3E…` (in-charge / not-in-charge / allocating
  ctor); `_ZN<…>D0E…` / `D1E…` / `D2E…` (deleting / in-charge / not-in-charge dtor). The variant letter is right before
  the parameter encoding `E`.
- ✓ Vtable mangled form: `_ZTV<encoded-class-name>`. Itanium gcc-3 always emits this; gcc-2 uses `_vt$<class>` (legacy
  form).

**External dependency findings:**

- 📖 **Itanium C++ ABI 32-bit vtable layout:** vtable contents are: (1) RTTI pointer (often null on Cygwin 3.4.4 because
  `-fno-rtti` is common), (2) offset-to-top (0 for primary class), (3) function pointers in declaration order, with
  inherited base entries copied first. We model the function-pointer slots only; RTTI/offset-to-top are at negative
  offsets and we skip them in v1 (acceptable per design's 32-bit-only scope).
- 📖 **{vfptr} convention:** Ghidra's class-recovery code (
  `Ghidra/Features/Decompiler/ghidra_scripts/classrecovery/RecoveredClass.java`) uses `ClassUtils.VFPTR` ("{vfptr}") and
  a pointer-to-vtable type as the first struct field. Decompiler resolves virtual calls via pointer dataflow on this
  field.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### ghidra-stabs.AC5: C++ classes and vtables

- **ghidra-stabs.AC5.1 Success:** Each parsed class produces a `Structure` with the correct field layout (fields at
  correct byte offsets, sizes match), a `GhidraClass` namespace (created via `SymbolTable.createClass`), and member
  functions re-parented under that namespace.
- **ghidra-stabs.AC5.2 Success:** Ctor variants (`__base_ctor` / `__comp_ctor`) are renamed to `<ClassName>` with `_C1`/
  `_C2`/`_C3` suffixes when multiple linker symbols exist for the same demangled name; dtor variants (`__base_dtor` /
  `__comp_dtor` / `__deleting_dtor`) renamed to `~<ClassName>` with `_D0`/`_D1`/`_D2` suffixes.
- **ghidra-stabs.AC5.3 Success:** A class with at least one virtual method has a sibling `<Class>_vtable` `Structure`
  containing one named `PointerDataType` field per virtual method, ordered by `*<voff>;` (inherited base-class entries
  first, per Itanium ABI 32-bit).
- **ghidra-stabs.AC5.4 Success:** Polymorphic class structs have `{vfptr}` as their first field, of type
  `<Class>_vtable*`.
- **ghidra-stabs.AC5.5 Success:** The vtable global (Itanium-mangled `_ZTV<class>` or gcc-2 `_vt$<class>`) is resolved
  via `AddressResolver`, has `<Class>_vtable` applied as data, and each virtual method's function symbol carries a plate
  comment naming the class and vtable offset.
- **ghidra-stabs.AC5.6 Success:** Nested namespaces mirror C++: `Foo::Bar::method` results in namespace tree `Foo` ⊃
  `Bar` ⊃ `method`; template-arg names like `std::basic_string<char,…>` are valid namespace names.
- **ghidra-stabs.AC5.7 Failure:** When a class method's mangled symbol isn't found in `program.symbolTable`, the method
  is skipped with a `[Stabs] unresolved-symbol` log entry; other methods of the same class still apply.

---

## Implementation Tasks

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->

### Task 1: `ClassBuilder` skeleton — class struct + namespace

**Files:**

- Create: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/builder/Classes.kt`

**Implementation:**

```kotlin
package ghistabs.materialize

import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.GhidraClass
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghistabs.container.AddressResolver
import ghistabs.importer.BookmarkSink
import ghistabs.parse.MethodDecl
import ghistabs.parse.TypeDecl

class ClassBuilder(
    private val program: Program,
    private val typeRegistry: TypeRegistry,
    private val resolver: AddressResolver,
    private val sink: BookmarkSink,
) {
    private val source = SourceType.IMPORTED
    private val symtab = program.symbolTable
    private val dtm = program.dataTypeManager

    /** Materialise a class struct + namespace + (optional) vtable struct + apply at _ZTV. */
    fun build(name: String, body: TypeDecl.Struct, category: CategoryPath) {
        // 1. Resolve fields recursively.
        val structDt = (typeRegistry.dataTypeFor(body) as? Structure)
            ?: run { sink.log("class-not-struct", "skipping non-struct class '$name'"); return }

        // 2. Insert {vfptr} first if class is polymorphic.
        val isPoly = body.hasVTablePointerMarker || body.methods.any { it.virt == ghistabs.parse.VirtKind.VIRTUAL }
        if (isPoly) ensureVfptrFirstField(structDt, name)

        // 3. Create or upgrade the GhidraClass namespace.
        val ns = ensureClassNamespace(name)

        // 4. Re-parent member functions.
        for (m in body.methods) reparentMethod(m, name, ns)

        // 5. If polymorphic: build <Class>_vtable struct + apply at _ZTV<class> address.
        if (isPoly) buildAndApplyVtable(name, body, ns, category, structDt)
    }

    private fun ensureClassNamespace(name: String): GhidraClass {
        // Split `Foo::Bar::Baz` and walk/create each segment.
        val parts = name.split("::")
        var parent: Namespace? = null
        for ((i, part) in parts.withIndex()) {
            val isLast = i == parts.lastIndex
            val existing = symtab.getNamespace(part, parent)
            parent = if (existing != null) {
                if (isLast && existing !is GhidraClass) {
                    ghidra.app.util.NamespaceUtils.convertNamespaceToClass(existing)
                } else existing
            } else {
                if (isLast) symtab.createClass(parent, part, source)
                else symtab.createNameSpace(parent, part, source)
            }
        }
        return parent as GhidraClass
    }

    private fun ensureVfptrFirstField(structDt: Structure, className: String) {
        val vfptrName = ClassUtils.VFPTR  // "{vfptr}"
        if (structDt.numComponents > 0 && structDt.getComponent(0).fieldName == vfptrName) return
        val vtableType = dtm.getDataType(CategoryPath.ROOT, "${className}_vtable")
            ?: StructureDataType(CategoryPath.ROOT, "${className}_vtable", 0, dtm).let {
                dtm.addDataType(
                    it,
                    DataTypeConflictHandler.KEEP_HANDLER
                )
            }
        val ptrToVtable = PointerDataType.getPointer(vtableType, dtm)
        structDt.insertAtOffset(0, ptrToVtable, ptrToVtable.length, vfptrName, "vtable pointer")
    }

    private fun reparentMethod(m: MethodDecl, className: String, ns: GhidraClass) { /* Task 2 */
    }
    private fun buildAndApplyVtable(
        className: String,
        body: TypeDecl.Struct,
        ns: GhidraClass,
        category: CategoryPath,
        structDt: Structure,
    ) { /* Task 3 */
    }
}
```

**Step: Compile only**

```bash
./gradlew compileKotlin
```

Expected: compiles. Bodies are stubbed.

**Step: Commit (with Task 2)**

**Verifies:** Scaffolding for `ghidra-stabs.AC5.1`, `ghidra-stabs.AC5.4`, `ghidra-stabs.AC5.6`.
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->

### Task 2: `reparentMethod` — ctor/dtor variant disambiguation + namespace move

**Files:**

- Modify: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/builder/Classes.kt:reparentMethod`

**Implementation:**

```kotlin
private fun reparentMethod(m: MethodDecl, className: String, ns: GhidraClass) {
    val mangled = m.mangled ?: run {
        sink.log("method-no-mangled", "$className::${m.name}: stab has no mangled symbol")
        return
    }
    val addr = resolver.resolve(mangled) ?: run {
        sink.log("unresolved-symbol", "method $mangled (in $className)")
        return
    }
    val func = program.functionManager.getFunctionAt(addr) ?: run {
        sink.log("unresolved-symbol", "no Function at $addr for $mangled")
        return
    }

    // 1. Re-parent.
    func.setParentNamespace(ns)

    // 2. Choose the in-class display name:
    val displayName = displayNameFor(mangled, className) ?: m.name
    if (func.name != displayName) func.setName(displayName, source)

    // 3. Apply prototype from MethodDecl.signature.
    val ret = typeRegistry.dataTypeFor(m.signature.ret)
    if (ret != null) func.setReturnType(ret, source)
    val params = m.signature.params.mapIndexed { i, p ->
        ghidra.program.model.listing.ParameterImpl(
            "arg$i",
            typeRegistry.dataTypeFor(p) ?: ghidra.program.model.data.Undefined4DataType.dataType,
            program,
            source,
        )
    }
    if (params.isNotEmpty()) {
        func.replaceParameters(
            params,
            ghidra.program.model.listing.Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            true,
            source,
        )
    }
}

/**
 * Map a ctor/dtor mangled name to its in-class display form. Returns null
 * for non-ctor/dtor methods (caller falls back to MethodDecl.name).
 *
 *   _ZN3FooC1Ev → "Foo_C1"   (in-charge ctor)
 *   _ZN3FooC2Ev → "Foo_C2"   (not-in-charge ctor)
 *   _ZN3FooC3Ev → "Foo_C3"   (allocating ctor)
 *   _ZN3FooD0Ev → "~Foo_D0"  (deleting dtor)
 *   _ZN3FooD1Ev → "~Foo_D1"  (in-charge dtor)
 *   _ZN3FooD2Ev → "~Foo_D2"  (not-in-charge dtor)
 *
 * If only one variant exists in the binary we still suffix; the design says
 * "_C1/_C2/_C3 suffixes to disambiguate when multiple linker symbols exist".
 * We always suffix because we don't yet know how many variants exist; pruning
 * happens later (or never — the suffixes are harmless).
 */
private fun displayNameFor(mangled: String, className: String): String? {
    val ctorRe = Regex("""C([123])E[a-zA-Z_0-9$]*$""")
    val dtorRe = Regex("""D([012])E[a-zA-Z_0-9$]*$""")
    ctorRe.find(mangled)?.let { return "${className}_C${it.groupValues[1]}" }
    dtorRe.find(mangled)?.let { return "~${className}_D${it.groupValues[1]}" }
    return null
}
```

**Note on AC5.2 wording:** the design says "with `_C1`/`_C2`/`_C3` suffixes to disambiguate when the same demangled form
has multiple linker symbols". The simplest implementation is to suffix unconditionally — the suffixes are harmless when
only one variant exists, and we don't have the population count at the per-method level (we'd need a second pass over
all class methods). If the user prefers strict disambiguation-only, that's an optimisation for v1.1; surface to the user
before Task 5 tests.

**Step: Commit Tasks 1+2**

```bash
git add src/main/kotlin/ghistabs/builder/Classes.kt
git commit -m "feat(builder): ClassBuilder skeleton + reparentMethod with ctor/dtor variants"
```

**Verifies:** Implementation-side of `ghidra-stabs.AC5.1`, `ghidra-stabs.AC5.2`, `ghidra-stabs.AC5.6`,
`ghidra-stabs.AC5.7`.
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_TASK_3 -->

### Task 3: `buildAndApplyVtable` — synthesise `<Class>_vtable` Structure, apply at `_ZTV<class>`

**Files:**

- Modify: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/builder/Classes.kt:buildAndApplyVtable`

**Implementation:**

```kotlin
private fun buildAndApplyVtable(
    className: String,
    body: TypeDecl.Struct,
    ns: GhidraClass,
    category: CategoryPath,
    structDt: Structure,
) {
    // 1. Walk inheritance chain to gather inherited virtuals first (Itanium ABI 32-bit:
    //    derived class's vtable starts with base-class entries, in declaration order
    //    of the base list, with overridden slots replaced by the derived method).
    val inherited = collectInheritedVirtuals(body)
    val ownVirtuals = body.methods
        .filter { it.virt == ghistabs.parse.VirtKind.VIRTUAL }
        .sortedBy { it.vtableOffsetBits ?: Long.MAX_VALUE }
    // Merge: inherited slots first (in inheritance order), then any new ones
    // declared in this class. Overrides replace the inherited slot (matched by
    // signature name; cheap heuristic — sufficient for Cygwin gcc 3.4.4 single
    // inheritance, surfaces as a question for MI in Open Questions).
    val virtuals = mergeVtableSlots(inherited, ownVirtuals)
    if (virtuals.isEmpty()) return

    // 2. Build / look up <Class>_vtable struct.
    val vtableName = "${className}_vtable"
    val ptrSize = program.defaultPointerSize  // typically 4 on 32-bit
    val existing = dtm.getDataType(category, vtableName) as? Structure
    val vtable = existing ?: StructureDataType(category, vtableName, 0, dtm).also {
        dtm.addDataType(it, DataTypeConflictHandler.KEEP_HANDLER)
    }
    // Clear any old contents (idempotent re-import).
    while (vtable.numComponents > 0) vtable.delete(0)
    for (m in virtuals) {
        val fnDt = ghidra.program.model.data.PointerDataType.getPointer(
            ghidra.program.model.data.Undefined4DataType.dataType,  // generic FN ptr
            dtm,
        )
        vtable.add(fnDt, ptrSize, m.name, "virtual ${m.name}")
    }

    // 3. Resolve _ZTV<class> address.
    val mangledItanium = "_ZTV" + itaniumMangleClassName(className)
    val mangledGcc2 = "_vt\$$className"
    val addr = resolver.resolve(mangledItanium) ?: resolver.resolve(mangledGcc2) ?: run {
        sink.log("vtable-unresolved", "no _ZTV symbol for $className")
        return
    }

    // 4. Apply data at the address.
    program.listing.clearCodeUnits(addr, addr.add(vtable.length.toLong() - 1), false)
    program.listing.createData(addr, vtable)
    sink.bookmark("vtable", addr, "applied $vtableName")

    // 5. Plate-comment each virtual method.
    var off = 0L
    for (m in virtuals) {
        val mAddr = m.mangled?.let(resolver::resolve) ?: run { off += ptrSize; return@buildAndApplyVtable }
        val func = program.functionManager.getFunctionAt(mAddr) ?: run { off += ptrSize; return@buildAndApplyVtable }
        program.listing.setComment(
            func.entryPoint,
            ghidra.program.model.listing.CodeUnit.PLATE_COMMENT,
            "virtual ${m.name}; ${className}_vtable offset $off",
        )
        off += ptrSize
    }
}

/**
 * Encode a class name in Itanium-ABI form for the _ZTV prefix.
 * Plain class:  Foo  → 3Foo
 * Nested:       Foo::Bar → N3Foo3BarE
 * Templated names (`std::basic_string<char, …>`) are NOT correctly handled
 * by this naïve encoder — for those we fall back to AddressResolver lookup
 * by the name as it appears in the symbol table (gcc emits a separate symbol).
 */
private fun itaniumMangleClassName(name: String): String {
    val parts = name.split("::").filter { it.isNotEmpty() }
    return if (parts.size == 1 && '<' !in name) {
        "${parts[0].length}${parts[0]}"
    } else if (parts.size > 1 && parts.none { '<' in it }) {
        "N" + parts.joinToString("") { "${it.length}$it" } + "E"
    } else {
        // Templated — punt; caller will try whole-symbol lookup separately.
        name
    }
}
```

**Helpers** (declare alongside `buildAndApplyVtable`):

```kotlin
/**
 * Resolve each base's class struct via TypeRegistry, then collect its
 * virtual methods (we look up the original AST via a `byName: Map<String, TypeDecl.Struct>`
 * registry passed into ClassBuilder). Returns inherited methods in declaration
 * order of `body.bases`.
 */
private fun collectInheritedVirtuals(body: TypeDecl.Struct): List<MethodDecl> {
    val out = mutableListOf<MethodDecl>()
    for (base in body.bases) {
        val baseStruct = resolveBaseAst(base.type) ?: continue
        out += baseStruct.methods.filter { it.virt == ghistabs.parse.VirtKind.VIRTUAL }
    }
    return out.sortedBy { it.vtableOffsetBits ?: Long.MAX_VALUE }
}

/**
 * Match overrides by simple name (sufficient for non-overloaded virtual
 * methods, which is the Cygwin gcc 3.4.4 / xapasmcsr.exe corpus). For full
 * Itanium override matching we'd need parameter-type comparison after
 * type resolution — surfaced as v1.1 work.
 */
private fun mergeVtableSlots(inherited: List<MethodDecl>, own: List<MethodDecl>): List<MethodDecl> {
    val result = inherited.toMutableList()
    for (m in own) {
        val idx = result.indexOfFirst { it.name == m.name }
        if (idx >= 0) result[idx] = m else result += m
    }
    return result
}

private fun resolveBaseAst(typeDecl: TypeDecl): TypeDecl.Struct? {
    // Pass-A populated `byNameStruct: Map<String, TypeDecl.Struct>` — the
    // implementor wires a registry. For TypeDecl.Ref(id), use byId-to-name lookup.
    TODO("inject struct-AST registry into ClassBuilder constructor")
}
```

**Update `ClassBuilder` constructor** (Task 1) to accept the struct-AST registry:

```kotlin
class ClassBuilder(
    private val program: Program,
    private val typeRegistry: TypeRegistry,
    private val resolver: AddressResolver,
    private val sink: BookmarkSink,
    /** All struct ASTs harvested in Pass A, indexed by name. */
    private val structAstsByName: Map<String, TypeDecl.Struct>,
) { ... }
```

Phase 4 Task 4 (wiring) builds this map from `typeAsts` when constructing `ClassBuilder`.

**For templated class names** (`std::basic_string<char,…>`), `itaniumMangleClassName` returns the name as-is and
`resolver.resolve("_ZTVstd::basic_string<char,…>")` will fail. The fallback: scan `program.symbolTable` for any symbol
whose demangled-name matches `vtable for ${className}`. This is slow but correct. Surface to user if performance is an
issue.

**Step: Commit**

```bash
git add src/main/kotlin/ghistabs/builder/Classes.kt
git commit -m "feat(builder): synthesise <Class>_vtable + apply at _ZTV"
```

**Verifies:** Implementation-side of `ghidra-stabs.AC5.3`, `ghidra-stabs.AC5.4`, `ghidra-stabs.AC5.5`.
<!-- END_TASK_3 -->

<!-- START_TASK_4 -->

### Task 4: Wire `ClassBuilder` into Pass C

**Files:**

- Modify: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/importer/Importer.kt:applyAllSymbols`

**Implementation:**

**Pass C ordering (explicit, important).** Within the single `txC` transaction:

1. **Functions, params, locals, scope plate comments** (Phase 4 logic).
2. **Globals + file-statics** (Phase 4 logic). This step records `_ZTV<class>` addresses into `AddressResolver` (because
   they appear as `N_GSYM` / `N_STSYM` records and are processed here).
3. **Class application** (this phase). `ClassBuilder.build(...)` queries `AddressResolver.resolve("_ZTV<class>")` which
   now succeeds because step 2 populated it.

Reordering — e.g. running ClassBuilder before globals — would cause `vtable-unresolved` log entries even when the symbol
exists.

After applying non-class globals/file-statics in Phase 4's `applyAllSymbols`, add a final loop over the `TypeAst`s whose
body is a `Struct` with at least one method or the vtable-pointer marker, calling
`ClassBuilder.build(name, body, category)` for each.

```kotlin
// Inside applyAllSymbols, after the globals/statics loop:
val classBuilder = ghistabs.materialize.ClassBuilder(ctx.program, typeRegistry, ctx.resolver, ctx.sink)
for (ast in /* the typeAsts list passed in here — refactor signature */) {
    val body = ast.body as? TypeDecl.Struct ?: continue
    if (body.methods.isEmpty() && !body.hasVTablePointerMarker) continue
    try {
        val category = ghistabs.materialize.Attribution.categoryFor(ast.name, setOf(ast.cuFile))
        classBuilder.build(ast.name, body, category)
    } catch (t: Throwable) {
        ctx.sink.log("class-apply-error", "${ast.name}: ${t.message}")
    }
}
```

**Refactor:** `applyAllSymbols` needs access to `typeAsts`. Update its signature to accept `typeAsts: List<TypeAst>` and
pass from `run()`.

**Step: Commit**

```bash
git add src/main/kotlin/ghistabs/importer/Importer.kt
git commit -m "feat(importer): wire ClassBuilder into Pass C"
```

**Verifies:** Wires up `ghidra-stabs.AC5.*` for end-to-end execution.
<!-- END_TASK_4 -->

<!-- START_SUBCOMPONENT_B (tasks 5-7) -->

<!-- START_TASK_5 -->

### Task 5: `ClassBuilderTest` — single-inheritance, struct + namespace + method reparent (Ring-2)

**Files:**

- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/builder/ClassBuilderTest.kt`

**Setup:** Use `ProgramBuilder` to construct an in-memory program containing:

- A code section with a function entry at `0x10000` (mangled `_ZN3Foo3barEv`).
- A data section reservation at `0x20000` for the future vtable.

Synthetic AST input: `Foo:T(0,5)=s4...bar::(...)=#(0,5),(0,1);;;:_ZN3Foo3barEv;0A.;;`

**Tests must verify:**

- **`ghidra-stabs.AC5.1`**: After `ClassBuilder.build("Foo", body, …)`:
    - `program.dataTypeManager.getDataType("/Foo", "Foo")` is a `Structure` with the right fields.
    - `program.symbolTable.getNamespace("Foo", null)` returns a `GhidraClass`.
    - `program.functionManager.getFunctionAt(0x10000)` has `parentNamespace.name == "Foo"` and `name == "bar"`.

- **`ghidra-stabs.AC5.6`** (nested namespaces): Provide `Foo::Bar` AST, assert namespace tree `Foo` ⊃ `Bar` ⊃ method.

- **`ghidra-stabs.AC5.6`** (template name): Provide `std::vector<int>` AST. Assert
  `program.symbolTable.getNamespace("vector<int>", stdNs)` is non-null and is a `GhidraClass`. Test passes even though
  Itanium mangling of templated names is approximate.

**Step: Run, commit**

```bash
./gradlew test --tests 'ghistabs.materialize.ClassBuilderTest'
git add src/test/kotlin/ghistabs/builder/ClassBuilderTest.kt
git commit -m "test(builder): single-inheritance class struct + namespace + method reparent"
```

**Verifies:** `ghidra-stabs.AC5.1`, `ghidra-stabs.AC5.6`.
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->

### Task 6: `ClassBuilderTest` — vtable struct, {vfptr}, `_ZTV` application, plate comments

**Files:**

- Modify: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/builder/ClassBuilderTest.kt` (add tests)

**Setup additions:**

- Add a function entry for `_ZN3Foo4drawEv` (virtual method) at `0x10100`.
- Add a `_ZTV3Foo` symbol at `0x20000` in the data section.

Synthetic AST input: `Foo:T(0,5)=s8~%(0,8);draw::(...)=#(0,5),...;:_ZN3Foo4drawEv;1A.*0;(0,5);;;`

**Tests must verify:**

- **`ghidra-stabs.AC5.3`**: `dtm.getDataType("/Foo", "Foo_vtable")` is a `Structure` with one component named `draw` of
  type `Pointer`.
- **`ghidra-stabs.AC5.4`**: `dtm.getDataType("/Foo", "Foo")` has `getComponent(0).fieldName == "{vfptr}"` and
  `getComponent(0).dataType` is a `Pointer` whose pointee is `Foo_vtable`.
- **`ghidra-stabs.AC5.5`**: `program.listing.getDataAt(0x20000).dataType.name == "Foo_vtable"`. The function at
  `0x10100` has a plate comment containing `"virtual draw"` and `"Foo_vtable offset 0"`.
- **`ghidra-stabs.AC5.5`** (bookmark): Exactly one `Stabs:vtable` bookmark exists at `0x20000`.

**Step: Run, commit**

```bash
./gradlew test --tests 'ghistabs.materialize.ClassBuilderTest'
git add src/test/kotlin/ghistabs/builder/ClassBuilderTest.kt
git commit -m "test(builder): vtable struct, vfptr, _ZTV application, plate comments"
```

**Verifies:** `ghidra-stabs.AC5.3`, `ghidra-stabs.AC5.4`, `ghidra-stabs.AC5.5`.
<!-- END_TASK_6 -->

<!-- START_TASK_8 -->

### Task 8: `ClassBuilderTest` — single inheritance vtable layout (inherited entries first)

**Files:**

- Modify: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/builder/ClassBuilderTest.kt` (add tests)

**Setup:** Construct two ASTs:

- `Base:T(0,5)=s4~%(0,8);foo::(...)=#…;:_ZN4Base3fooEv;1A.*0;(0,5);;;` (one virtual method `foo`).
- `Derived:T(0,6)=s4!1,0011,(0,5);bar::(...)=#…;:_ZN7Derived3barEv;1A.*4;(0,5);;;` (inherits Base, adds virtual `bar` at
  vtable offset 4).

Add function entries `_ZN4Base3fooEv` at `0x10000`, `_ZN7Derived3barEv` at `0x10100`. Add `_ZTV7Derived` at `0x20000`.

**Tests must verify (`ghidra-stabs.AC5.3` inheritance):**

- `dtm.getDataType("/Derived", "Derived_vtable")` is a `Structure` with TWO components: index 0 is `foo` (inherited from
  Base), index 1 is `bar`.
- The `Derived_vtable` global at `0x20000` has data of type `Derived_vtable` applied.
- The plate comment on `_ZN4Base3fooEv` mentions `Base_vtable` (it's inherited but the originating-class attribution
  sticks). The plate comment on `_ZN7Derived3barEv` mentions `Derived_vtable offset 4`.

**Step: Run, commit**

```bash
./gradlew test --tests 'ghistabs.materialize.ClassBuilderTest'
git add src/test/kotlin/ghistabs/builder/ClassBuilderTest.kt
git commit -m "test(builder): inherited vtable entries (Base::foo before Derived::bar)"
```

**Verifies:** `ghidra-stabs.AC5.3` (inheritance ordering).
<!-- END_TASK_8 -->

<!-- START_TASK_9 -->

### Task 9 (DESCOPED): Multiple-inheritance and virtual-base layouts

The design's Phase 5 "Done when" lists "single-inheritance, multiple-inheritance, virtual-base, and ctor-variant cases."
This implementation plan covers single-inheritance (Tasks 5, 8), ctor/dtor variants (Task 7), and inherited vtable
ordering (Task 8). **Multiple-inheritance and virtual-base are explicitly descoped to v1.1** — the `xapasmcsr.exe`
corpus uses neither pattern (verified via `parse_image/stabs_stats.py` class detector — no `~%` markers with multiple
`!` base entries), so the rejection is empirically safe for the integration target.

If a future binary forces re-opening this: the work is (a) extend `mergeVtableSlots` to track per-base offset-to-top
values (Itanium MI ABI), (b) add `BaseDecl.isVirtual` handling in `ensureVfptrFirstField` (virtual bases use a separate
vbtable), (c) add tests with hand-built MI/VB ASTs.

**Surface to user before Task 5:** confirm the descope. If user wants MI/VB in v1, this becomes Tasks 9–11 with full
ASTs and assertions.

**Step: No code change. Document and commit.**

```bash
git commit --allow-empty -m "docs(plan): MI/virtual-base descoped to v1.1 (xapasmcsr.exe corpus uses neither)"
```

**Verifies:** Documentation deliverable; explicit deviation from design's Phase 5 "Done when" with rationale.
<!-- END_TASK_9 -->

<!-- START_TASK_7 -->

### Task 7: `ClassBuilderTest` — ctor/dtor variants, unresolved-method tolerance

**Files:**

- Modify: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/builder/ClassBuilderTest.kt` (add tests)

**Setup:** Add three function entries:

- `0x10200` named `_ZN3FooC1Ev` (in-charge ctor)
- `0x10300` named `_ZN3FooD0Ev` (deleting dtor)
- `0x10400` named `_ZN3Foo7missingEv` (a method that the AST claims exists but with a typo — let's say the AST mangled
  value is `_ZN3Foo7missingEi` so the lookup fails)

**Tests must verify:**

- **`ghidra-stabs.AC5.2`** (ctor variant): After build, `functionManager.getFunctionAt(0x10200).name == "Foo_C1"`.
  Parent namespace is `Foo`.
- **`ghidra-stabs.AC5.2`** (dtor variant): `functionManager.getFunctionAt(0x10300).name == "~Foo_D0"`.
- **`ghidra-stabs.AC5.7`** (unresolved): The `missing` method is skipped. Log contains
  `[Stabs] unresolved-symbol: method _ZN3Foo7missingEi`. The other methods (`Foo_C1`, `~Foo_D0`) are still applied —
  assert their names.

**Step: Run, commit**

```bash
./gradlew test --tests 'ghistabs.materialize.ClassBuilderTest'
git add src/test/kotlin/ghistabs/builder/ClassBuilderTest.kt
git commit -m "test(builder): ctor/dtor variants + unresolved-method tolerance"
```

**Verifies:** `ghidra-stabs.AC5.2`, `ghidra-stabs.AC5.7`.
<!-- END_TASK_7 -->

<!-- END_SUBCOMPONENT_B -->

---

## Phase Done When

- [ ] `builder/Classes.kt` exports `ClassBuilder.build(name, body, category)`.
- [ ] `Importer.applyAllSymbols` invokes `ClassBuilder.build` for every struct AST that has methods or a vtable-pointer
  marker.
- [ ] `ClassBuilderTest` covers single-inheritance, vtable+vfptr, ctor/dtor variants, unresolved-method tolerance,
  nested namespaces, template names. All green.
- [ ] AC5 phase-6 integration assertions (≥ 50 GhidraClass namespaces in `xapasmcsr.exe`) deferred to Phase 6.

## Open Questions for User

- **Always suffix ctor/dtor variants `_C1`/`_C2`/`_C3`/`_D0`/`_D1`/`_D2`, or only when multiple variants exist?**
  Current plan: always (cheaper, harmless). Confirm before Task 5 tests freeze the assertion.
- **Itanium mangling of templated class names is approximate.** The fallback (scanning `program.symbolTable` for "vtable
  for X" demangled match) is correct but slow. Acceptable for v1, or do we need a real mangler?
- **Multiple-inheritance and virtual-base layouts** — the design's "Done when" mentions tests for these, but they're
  complex. v1 plan focuses on single-inheritance and one example with `~%` virtual marker. Multiple-inheritance is a
  stretch goal in Phase 5 unless the user declares it required. Confirm.
