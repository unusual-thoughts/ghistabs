# ghidra-stabs Phase 4: Symbol application (functions, globals, locals, params)

**Goal:** Apply non-class symbols to the program — function signatures with return + parameter types and names,
register/stack locals, globals at resolved addresses, file-statics at stab-carried addresses, plate comments at lexical
scopes.

**Architecture:** `StabsImporter.run()` is the orchestrator implementing the three-pass walk (read → parse + harvest →
materialise types → apply symbols). This phase wires Pass A's harvesting and Pass C's non-class symbol application;
class-method re-parenting is left to Phase 5.

**Tech Stack:** Kotlin 2.3.21, Ghidra `Function` / `Variable` / `Listing` / `SymbolTable` APIs, JUnit 5 +
`ProgramBuilder`.

**Scope:** Phase 4 of 6.

**Codebase verified:** 2026-05-07.

**Codebase verification findings:**

- ✓ Phases 1–3 deliver: `StabReader`, `Parser`, `TypeRegistry`, `AddressResolver`, `BookmarkSink`. This phase imports
  all of them.
- ✓ Ghidra Function API: `program.functionManager.getFunctionAt(addr): Function?`;
  `createFunction(name, addr, body, source): Function`; `function.setReturnType(dt, source)`;
  `function.replaceParameters(params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, source)`. Confirmed in
  `Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/listing/Function.java`.
- ✓ `Parameter` / `LocalVariable` / `ReturnParameterImpl` / `ParameterImpl` available under
  `ghidra.program.model.listing.*`.
- ✓ Plate comments: `program.listing.setComment(addr, CodeUnit.PLATE_COMMENT, text)`. `CodeUnit.PLATE_COMMENT` is the
  integer constant `3`.
- ✓ For locals: `function.addLocalVariable(LocalVariableImpl, source)`. Stack offsets are signed (negative = below frame
  pointer).
- ✓ Register locals: `LocalVariableImpl(name, dt, register, function, source)`. Need to map stab register numbers to
  Ghidra `Register` objects via `program.programContext.getRegister(int)` — though for x86, the gcc register-number
  convention is `0=eax, 1=ecx, …`. **The implementor must verify the mapping against the target architecture.**
  xapasmcsr.exe is a PE32 x86 binary (Cygwin gcc 3.4.4 produces standard SysV-style register numbers there).
- ✓ Transactions: every `Program` mutation must be inside `program.startTransaction("name") … endTransaction(id, true)`.
  We wrap each pass in its own transaction.

**External dependency findings:**

- 📖 **`N_FUN.n_value` semantics on PE32 / Cygwin gcc 3.4.4:** the function-start `N_FUN` carries `n_value` as the
  *absolute virtual address* (image base + section offset), matching Ghidra's `Address` interpretation. The function-end
  `N_FUN` (empty name) carries `n_value` as the function size *relative to function start*. This is the Cygwin/MinGW gcc
  dialect; it differs from a.out where N_FUN can be section-relative. Reference: gcc 3.4.4 source
  `gcc/dbxout.c:dbxout_function_decl` emits `assemble_name (file, name); fprintf (file, ":%c", '%s'); …` which the
  assembler resolves to the absolute symbol value. **The implementor must verify against the first 5 functions
  of `xapasmcsr.exe`** (compare stab `n_value` to the function entry as Ghidra's PE loader places it). If
  absolute-address assumption is wrong, document and add image-base offset adjustment in passAHarvest.
- 📖 **Stabs scope semantics:** `N_FUN` opens a function record, then a sequence of `N_PSYM` (stack params), `N_RSYM` (
  register params/locals), `N_LSYM` (locals — `n_value` is the stack offset), `N_LBRAC` / `N_RBRAC` (lexical scope
  brackets — `n_value` is an offset from function start), `N_SLINE` (line numbers, out of scope for v1). Order matters
  for scope.
- 📖 **`N_FUN` end-of-function record:** GCC emits a `N_FUN` with empty name and `n_value = function size` (relative to
  function start) to mark the end of a function. We use this to compute function bodies.
- 📖 **Ghidra `AddressSet` for function body:** if we don't have an end marker, fall back to `function.getBody()` after
  `createFunction(addr, null, source)` — Ghidra computes body via flow analysis. The stab-derived size is more reliable;
  use it when present.

---

## Acceptance Criteria Coverage

This phase implements and tests:

### ghidra-stabs.AC4: Symbol application — functions, globals, locals, params

- **ghidra-stabs.AC4.1 Success:** For each `N_FUN` record, a `Function` exists at the stab's address (created or already
  present), with prototype set from the stab's return-type AST plus parameter types/names from following `N_PSYM`/
  `N_RSYM` records.
- **ghidra-stabs.AC4.2 Success:** For each `N_LSYM` non-type record (a local variable), a stack/register local is added
  to the enclosing function with the correct name and type.
- **ghidra-stabs.AC4.3 Success:** For each `N_GSYM`, the corresponding global variable's address is resolved via
  `AddressResolver` and a data type is applied; unresolved cases produce `[Stabs] unresolved-symbol` log entries (no
  bookmark).
- **ghidra-stabs.AC4.4 Success:** For each `N_STSYM` / `N_LCSYM`, a data type is applied at the stab-carried address (no
  symbol-table lookup needed).
- **ghidra-stabs.AC4.5 Success:** Where stabs has `N_LBRAC`/`N_RBRAC` scope info, plate comments are added at the
  scope-start address listing locals visible in that scope.
- **ghidra-stabs.AC4.6 Success:** On `xapasmcsr.exe`, ≥ 470 of the 990 `N_FUN` records have named parameters; ≥ 92 have
  locals; the remainder are bookmark-free (compiler stubs without param info). (Asserted in Phase 6 integration test.)

### ghidra-stabs.AC6: Error handling

- **ghidra-stabs.AC6.2 Failure:** A single malformed stab record never aborts the run; it produces a
  `[Stabs] parse-error` log entry with the raw descriptor and the cursor position, and the importer continues. (
  Importer-catches-and-continues half — parser-throws-with-cursor half landed in Phase 2.)
- **ghidra-stabs.AC6.3 Success:** Bookmarks attach only at intrinsically-meaningful addresses (function entry, data
  location, vtable); diagnostics with no useful address (header-record parse errors, unresolved externs, type conflicts)
  go to `MessageLog` only.

---

## Implementation Tasks

<!-- START_SUBCOMPONENT_A (tasks 1-2) -->

<!-- START_TASK_1 -->

### Task 1: `ImportContext`, `StabsOptions`, `PassResult` value types

**Files:**

- Create: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/importer/ImportContext.kt`

**Implementation:**

```kotlin
package ghistabs.importer

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SymbolTable
import ghidra.util.task.TaskMonitor
import ghistabs.container.AddressResolver

data class StabsOptions(
    val createImportedLabels: Boolean = true,
    val applyPlateComments: Boolean = true,
    val applyVtables: Boolean = true,
)

data class PassResult(
    val recordsRead: Int = 0,
    val recordsParsed: Int = 0,
    val parseErrors: Int = 0,
    val typesMaterialised: Int = 0,
    val functionsApplied: Int = 0,
    val globalsApplied: Int = 0,
    val classesApplied: Int = 0,
)

class ImportContext(
    val program: Program,
    val log: MessageLog,
    val monitor: TaskMonitor,
    val options: StabsOptions = StabsOptions(),
) {
    val dtm: DataTypeManager = program.dataTypeManager
    val symtab: SymbolTable = program.symbolTable
    val sink: BookmarkSink = BookmarkSink(program, log)
    val resolver: AddressResolver = AddressResolver(program)
}
```

**Step: Commit (with Task 2)**

**Verifies:** None (data types).
<!-- END_TASK_1 -->

<!-- START_TASK_2 -->

### Task 2: `StabsImporter` skeleton — three-pass orchestrator + Pass A wiring

**Files:**

- Create: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/importer/Importer.kt`

**Implementation:**

```kotlin
package ghistabs.importer

import ghistabs.container.StabReader
import ghistabs.container.StabType
import ghistabs.parse.Parser
import ghistabs.parse.StabsParseException
import ghistabs.parse.SymbolDecl

class StabsImporter(private val ctx: ImportContext) {
    fun run(): PassResult {
        val readerResult = StabReader.fromProgram(ctx.program) ?: run {
            ctx.sink.log("no-stabs", "No .stab/.stabstr block found; skipping import.")
            return PassResult()
        }

        val records = readerResult.records
        ctx.monitor.initialize(records.size.toLong())
        ctx.monitor.message = "Stabs: parsing"

        // Pass A — parse + harvest
        val typeAsts = mutableListOf<ghistabs.materialize.TypeAst>()
        val symbolsByCu = mutableMapOf<String, MutableList<HarvestedSymbol>>()
        val openFunctions = mutableListOf<OpenFunction>()
        val parseErrors = passAHarvest(records, typeAsts, symbolsByCu, openFunctions)

        // Pass B — materialise types (defer to Phase 3 components)
        val typeRegistry = ghistabs.materialize.TypeRegistry(ctx.dtm, ctx.sink)
        val txB = ctx.program.startTransaction("Stabs: materialise types")
        try {
            typeRegistry.materialiseAll(typeAsts) { name, cus ->
                ghistabs.materialize.Attribution.categoryFor(name, cus)
            }
        } finally {
            ctx.program.endTransaction(txB, true)
        }

        // Pass C — apply symbols
        val txC = ctx.program.startTransaction("Stabs: apply symbols")
        val applyResult = try {
            applyAllSymbols(symbolsByCu, openFunctions, typeRegistry)
        } finally {
            ctx.program.endTransaction(txC, true)
        }

        return PassResult(
            recordsRead = readerResult.recordCount,
            recordsParsed = records.size - parseErrors,
            parseErrors = parseErrors,
            typesMaterialised = typeAsts.size,
            functionsApplied = applyResult.functions,
            globalsApplied = applyResult.globals,
        )
    }

    private fun passAHarvest(
        records: List<ghistabs.container.StabRecord>,
        typeAsts: MutableList<ghistabs.materialize.TypeAst>,
        symbolsByCu: MutableMap<String, MutableList<HarvestedSymbol>>,
        openFunctions: MutableList<OpenFunction>,
    ): Int {
        var parseErrors = 0
        var currentCu: String = "<unknown>"
        var currentFunction: OpenFunction? = null

        for ((i, rec) in records.withIndex()) {
            ctx.monitor.checkCancelled()
            ctx.monitor.incrementProgress(1)

            when (rec.type) {
                StabType.N_SO, StabType.N_SOL -> {
                    if (rec.name.isNotEmpty()) currentCu = rec.name
                }
                StabType.N_FUN -> {
                    val addrSpace = ctx.program.addressFactory.defaultAddressSpace
                    if (rec.name.isEmpty()) {
                        // End-of-function marker: rec.value = function size relative to start.
                        currentFunction?.let { it.sizeBytes = rec.value }
                        currentFunction = null
                    } else {
                        val addr = addrSpace.getAddress(rec.value)
                        // Pull mangled name from before the colon.
                        val mangled = rec.name.substringBefore(':')
                        ctx.resolver.recordFromStab(mangled, addr)
                        try {
                            val decl = Parser(rec.name).parseSymbol() as? SymbolDecl.Function
                            if (decl != null) {
                                val open = OpenFunction(
                                    name = mangled,
                                    addr = addr,
                                    decl = decl,
                                    cu = currentCu,
                                    locals = mutableListOf(),
                                    params = mutableListOf(),
                                    scopeBrackets = mutableListOf()
                                )
                                openFunctions += open
                                currentFunction = open
                            }
                        } catch (e: StabsParseException) {
                            parseErrors++
                            ctx.sink.log("parse-error", "@${i} '${rec.name.take(80)}': ${e.message}")
                        }
                    }
                }
                StabType.N_GSYM -> harvestSymbol(rec, currentCu, symbolsByCu) { parseErrors++ }
                StabType.N_STSYM, StabType.N_LCSYM -> {
                    val addrSpace = ctx.program.addressFactory.defaultAddressSpace
                    val addr = addrSpace.getAddress(rec.value)
                    val mangled = rec.name.substringBefore(':')
                    ctx.resolver.recordFromStab(mangled, addr)
                    harvestSymbol(rec, currentCu, symbolsByCu) { parseErrors++ }
                }
                StabType.N_PSYM, StabType.N_RSYM -> {
                    val open = currentFunction ?: continue
                    try {
                        val decl = Parser(rec.name).parseSymbol()
                        when (decl) {
                            is SymbolDecl.StackParam, is SymbolDecl.RegParam -> open.params += ParamRecord(
                                decl,
                                rec.value
                            )
                            else -> Unit
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        ctx.sink.log("parse-error", "param @${i}: ${e.message}")
                    }
                }
                StabType.N_LSYM -> {
                    val open = currentFunction
                    try {
                        val decl = Parser(rec.name).parseSymbol()
                        when (decl) {
                            is SymbolDecl.TaggedType -> typeAsts += ghistabs.builder.TypeAst(
                                decl.id,
                                decl.name,
                                decl.body,
                                currentCu
                            )
                            is SymbolDecl.Typedef -> typeAsts += ghistabs.builder.TypeAst(
                                decl.id,
                                decl.name,
                                decl.body,
                                currentCu
                            )
                            is SymbolDecl.StackLocal, is SymbolDecl.RegLocal, is SymbolDecl.StaticVar -> open?.locals?.add(
                                LocalRecord(decl, rec.value)
                            )
                            else -> Unit
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        ctx.sink.log("parse-error", "lsym @${i}: ${e.message}")
                    }
                }
                StabType.N_LBRAC, StabType.N_RBRAC -> {
                    currentFunction?.scopeBrackets?.add(rec.type to rec.value)
                }
                else -> Unit  // ignore N_SLINE, N_OPT, etc.
            }
        }
        return parseErrors
    }

    private fun harvestSymbol(
        rec: ghistabs.container.StabRecord,
        currentCu: String,
        symbolsByCu: MutableMap<String, MutableList<HarvestedSymbol>>,
        onError: () -> Unit,
    ) {
        try {
            val decl = Parser(rec.name).parseSymbol()
            symbolsByCu.getOrPut(currentCu) { mutableListOf() } += HarvestedSymbol(decl, rec.type, rec.value)
        } catch (e: StabsParseException) {
            onError()
            ctx.sink.log("parse-error", "@${rec.recordIndex} '${rec.name.take(80)}': ${e.message}")
        }
    }

    private fun applyAllSymbols(
        symbolsByCu: Map<String, List<HarvestedSymbol>>,
        openFunctions: List<OpenFunction>,
        typeRegistry: ghistabs.materialize.TypeRegistry,
    ): ApplyResult { /* implemented in Task 3 */ TODO()
    }

    private data class HarvestedSymbol(val decl: SymbolDecl, val recordType: StabType, val rawValue: Long)
    private data class OpenFunction(
        val name: String,
        val addr: ghidra.program.model.address.Address,
        val decl: SymbolDecl.Function,
        val cu: String,
        val locals: MutableList<LocalRecord>,
        val params: MutableList<ParamRecord>,
        val scopeBrackets: MutableList<Pair<StabType, Long>>,
        var sizeBytes: Long = 0L,
    )
    private data class ParamRecord(val decl: SymbolDecl, val rawValue: Long)
    private data class LocalRecord(val decl: SymbolDecl, val rawValue: Long)
    private data class ApplyResult(val functions: Int, val globals: Int)
}
```

**Step: Compile only**

```bash
./gradlew compileKotlin
```

Expected: compiles cleanly (the body of `applyAllSymbols` is `TODO`; tests in Task 5 won't pass until Task 3 lands).

**Step: Commit (with Task 3)**

**Verifies:** None directly.
<!-- END_TASK_2 -->

<!-- END_SUBCOMPONENT_A -->

<!-- START_TASK_3 -->

### Task 3: `applyAllSymbols` — function prototype + params + locals + globals + statics

**Files:**

- Modify: `/home/riton/git/bouse/ghidra-stabs/src/main/kotlin/ghistabs/importer/Importer.kt:applyAllSymbols`

**Implementation:**

Replace the `TODO()` with the full apply logic. Per-function and per-symbol exceptions are caught at this level and
routed to `sink.log("apply-error", …)`. The transaction wrapping is in `run()`.

```kotlin
private fun applyAllSymbols(
    symbolsByCu: Map<String, List<HarvestedSymbol>>,
    openFunctions: List<OpenFunction>,
    typeRegistry: ghistabs.materialize.TypeRegistry,
): ApplyResult {
    val source = ghidra.program.model.symbol.SourceType.IMPORTED
    val funcMgr = ctx.program.functionManager
    val listing = ctx.program.listing
    var functions = 0
    var globals = 0

    for (open in openFunctions) {
        try {
            val existing = funcMgr.getFunctionAt(open.addr)
            val func = existing
                ?: funcMgr.createFunction(open.name, open.addr, /* body */ null, source)
                ?: continue

            // Apply return type from the parsed signature.
            val retDt = typeRegistry.dataTypeFor(open.decl.signature)
            if (retDt != null) func.setReturnType(retDt, source)

            // Build parameters from the recorded N_PSYM / N_RSYM records.
            val params = open.params.mapIndexed { i, p ->
                val pdecl = p.decl
                val (pname, pdt) = when (pdecl) {
                    is SymbolDecl.StackParam -> pdecl.name to typeRegistry.dataTypeFor(pdecl.type)
                    is SymbolDecl.RegParam -> pdecl.name to typeRegistry.dataTypeFor(pdecl.type)
                    else -> "arg$i" to null
                }
                ghidra.program.model.listing.ParameterImpl(
                    pname,
                    pdt ?: ghidra.program.model.data.Undefined4DataType.dataType,
                    ctx.program,
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

            // Apply locals.
            for (loc in open.locals) {
                applyLocal(func, loc, typeRegistry, source)
            }

            // Apply scope plate comments.
            if (ctx.options.applyPlateComments) applyScopeComments(func, open)

            functions++
        } catch (t: Throwable) {
            ctx.sink.log("apply-error", "function ${open.name} @ ${open.addr}: ${t.message}")
        }
    }

    // Globals + file-statics.
    for ((cu, syms) in symbolsByCu) {
        for (h in syms) {
            try {
                when (val d = h.decl) {
                    is SymbolDecl.Global -> applyGlobal(d, typeRegistry, source).let { if (it) globals++ }
                    is SymbolDecl.StaticVar -> applyStatic(
                        d,
                        h.rawValue,
                        typeRegistry,
                        source
                    ).let { if (it) globals++ }
                    else -> Unit
                }
            } catch (t: Throwable) {
                ctx.sink.log("apply-error", "symbol ${h.decl.name} in $cu: ${t.message}")
            }
        }
    }

    return ApplyResult(functions, globals)
}

private fun applyLocal(
    func: ghidra.program.model.listing.Function,
    loc: LocalRecord,
    typeRegistry: ghistabs.materialize.TypeRegistry,
    source: ghidra.program.model.symbol.SourceType,
) { /* StackLocal: stack offset; RegLocal: map regNum to Register */
}

private fun applyScopeComments(
    func: ghidra.program.model.listing.Function,
    open: OpenFunction,
) {
    // Pair LBRAC (open) with matching RBRAC (close). For each pair, list
    // the locals whose record-index falls inside the bracket range and
    // attach a plate comment at the LBRAC address.
    val funcBase = func.entryPoint.offset
    val pairs = computePairs(open.scopeBrackets)
    for ((openOff, closeOff, localsInScope) in pairs) {
        val addr = func.entryPoint.add(openOff)
        val text = "Stabs scope locals: " + localsInScope.joinToString(", ") { it.decl.name }
        ctx.program.listing.setComment(addr, ghidra.program.model.listing.CodeUnit.PLATE_COMMENT, text)
    }
}

private fun applyGlobal(
    decl: SymbolDecl.Global,
    typeRegistry: ghistabs.materialize.TypeRegistry,
    source: ghidra.program.model.symbol.SourceType,
): Boolean {
    val addr = ctx.resolver.resolve(decl.name) ?: run {
        ctx.sink.log("unresolved-symbol", "global ${decl.name}")
        return false
    }
    val dt = typeRegistry.dataTypeFor(decl.type) ?: return false
    ctx.program.listing.createData(addr, dt)
    return true
}

private fun applyStatic(
    decl: SymbolDecl.StaticVar,
    rawAddr: Long,
    typeRegistry: ghistabs.materialize.TypeRegistry,
    source: ghidra.program.model.symbol.SourceType,
): Boolean {
    val addr = ctx.program.addressFactory.defaultAddressSpace.getAddress(rawAddr)
    val dt = typeRegistry.dataTypeFor(decl.type) ?: return false
    ctx.program.listing.createData(addr, dt)
    return true
}
```

**Required addition to `TypeRegistry`** (Phase 3 amendment carried here):

- Add `fun dataTypeFor(decl: TypeDecl): DataType?` that performs lookup or builds-if-missing. Single entry point used by
  Pass C.

**Step: Commit Tasks 1–3 together**

```bash
git add src/main/kotlin/ghistabs/importer/{ImportContext,Importer}.kt \
        src/main/kotlin/ghistabs/builder/TypeRegistry.kt
git commit -m "feat(importer): three-pass orchestrator + non-class symbol application"
```

**Verifies:** Implementation-side of `ghidra-stabs.AC4.1`–`AC4.5`.
<!-- END_TASK_3 -->

<!-- START_SUBCOMPONENT_B (tasks 4-6) -->

<!-- START_TASK_4 -->

### Task 4: `SymbolApplyTest` — function with params (Ring-2)

**Files:**

- Create: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/importer/SymbolApplyTest.kt`

**Setup:** use `ProgramBuilder("test", ProgramBuilder._X86)` to build an in-memory program with a single text section.
Manually populate `.stab`/`.stabstr` blocks with synthetic byte fixtures that encode a small program: one function
`add(int a, int b)` returning `int`, plus a global `g_count: int`, plus a file-static `s_buf: char[16]`.

The fixture builder is shared across Tasks 4–6 — extract into
`private object Fixture { fun buildProgramWith(stabBytes: ByteArray, stabstrBytes: ByteArray): Program }`.

**Tests must verify (`ghidra-stabs.AC4.1`):**

- After `StabsImporter.run()`, `program.functionManager.getFunctionAt(addr)` is non-null at the encoded function entry.
- `func.returnType` is an `IntegerDataType` (4 bytes).
- `func.parameterCount == 2`.
- `func.getParameter(0).name == "a"`; `func.getParameter(0).dataType is IntegerDataType`.
- `func.getParameter(1).name == "b"`.

Also assert `result.functionsApplied >= 1` and `result.parseErrors == 0`.

**Step: Run, commit**

```bash
./gradlew test --tests 'ghistabs.importer.SymbolApplyTest'
git add src/test/kotlin/ghistabs/importer/SymbolApplyTest.kt
git commit -m "test(importer): function prototype + params"
```

**Verifies:** `ghidra-stabs.AC4.1`.
<!-- END_TASK_4 -->

<!-- START_TASK_5 -->

### Task 5: `SymbolApplyTest` — locals + register vars + scope plate comments

**Files:**

- Modify: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/importer/SymbolApplyTest.kt` (add tests)

**Tests must verify:**

- **`ghidra-stabs.AC4.2`** — Function `f()` has one stack local `int x` at frame offset −8. After import,
  `func.getLocalVariables()` has one entry with `name == "x"`, `dataType is IntegerDataType`, `stackOffset == -8`.
- **`ghidra-stabs.AC4.2`** — Function `g()` has one register local `r0` of type `int` (stab `r:(0,1);0`). After import,
  the function has a register-storage local with the right name and type. (If register mapping is uncertain on x86, use
  a stack local instead and surface the register-mapping question to the user.)
- **`ghidra-stabs.AC4.5`** — Function `h()` has two locals inside an `LBRAC`/`RBRAC` block at offset +12. After import,
  `program.listing.getComment(addr=funcStart+12, CodeUnit.PLATE_COMMENT)` contains the substring `"Stabs scope locals:"`
  and lists both local names.

**Step: Run, commit**

```bash
./gradlew test --tests 'ghistabs.importer.SymbolApplyTest'
git add src/test/kotlin/ghistabs/importer/SymbolApplyTest.kt
git commit -m "test(importer): locals + scope plate comments"
```

**Verifies:** `ghidra-stabs.AC4.2`, `ghidra-stabs.AC4.5`.
<!-- END_TASK_5 -->

<!-- START_TASK_6 -->

### Task 6: `SymbolApplyTest` — globals (resolved + unresolved), file-statics, error policy

**Files:**

- Modify: `/home/riton/git/bouse/ghidra-stabs/src/test/kotlin/ghistabs/importer/SymbolApplyTest.kt` (add tests)

**Tests must verify:**

- **`ghidra-stabs.AC4.3`** (resolved global): A program where `g_count` exists in `program.symbolTable` (added via the
  Ghidra COFF/ELF loader path simulation) and is referenced by an `N_GSYM` record. After import,
  `program.listing.getDataAt(g_count_addr).dataType` is `IntegerDataType`.
- **`ghidra-stabs.AC4.3`** (unresolved global): An `N_GSYM` for `g_unknown` with no matching symbol. After import,
  `[Stabs] unresolved-symbol` appears in the message log; NO bookmark is created at any address (assert
  `program.bookmarkManager.getBookmarks(...)` is empty for the `Stabs:unresolved-symbol` category).
- **`ghidra-stabs.AC4.4`** (file-static): A program with an `N_STSYM` for `s_buf` carrying address `0x4000`. After
  import, `program.listing.getDataAt(0x4000).dataType` is the right `ArrayDataType` of char × 16. AddressResolver has a
  stab-derived label `s_buf` at `0x4000` with `SourceType.IMPORTED`.
- **`ghidra-stabs.AC6.3`** (bookmark vs log split): A combined fixture with one parse-error in a header record (no
  useful address) and one apply-error at a function entry. Assert: 0 bookmarks for the parse-error, 1 bookmark for the
  apply-error (at the function entry address). Both produce log entries.

- **`ghidra-stabs.AC6.2`** (importer continues past malformed record): Build a fixture with three records — a valid
  `N_GSYM` for `g_one`, a malformed `N_GSYM` whose descriptor is `garbage:G@@@?`, and a valid `N_GSYM` for `g_three`.
  Run `StabsImporter.run()`. Assert:
    - `result.parseErrors == 1`
    - `g_one` and `g_three` both have datatypes applied at their addresses (i.e. surrounding records are NOT lost).
    - The MessageLog contains a `[Stabs] parse-error` entry that mentions `garbage` (the leading name token) AND a
      cursor position.
    - No `Stabs:parse-error` bookmark is created (header-record errors have no useful address per AC6.3).

**Step: Run, commit**

```bash
./gradlew test --tests 'ghistabs.importer.SymbolApplyTest'
git add src/test/kotlin/ghistabs/importer/SymbolApplyTest.kt
git commit -m "test(importer): globals, file-statics, bookmark/log split"
```

**Verifies:** `ghidra-stabs.AC4.3`, `ghidra-stabs.AC4.4`, `ghidra-stabs.AC6.2`, `ghidra-stabs.AC6.3`.
<!-- END_TASK_6 -->

<!-- END_SUBCOMPONENT_B -->

---

## Phase Done When

- [ ] `importer/ImportContext.kt` exports `ImportContext`, `StabsOptions`, `PassResult`.
- [ ] `importer/Importer.kt` exports `StabsImporter` with a fully wired `run()`.
- [ ] `TypeRegistry.dataTypeFor(decl)` exists.
- [ ] `SymbolApplyTest` covers: function-with-params, locals, scope comments, resolved + unresolved globals,
  file-static, bookmark/log split. All tests green.
- [ ] AC4.6 (real-binary count) deferred to Phase 6 integration test.

## Open Questions for User

- **Register-number → Ghidra `Register` mapping for `N_RSYM` on x86 PE32:** is the gcc convention
  `0=eax, 1=ecx, 2=edx, 3=ebx, …` correct here, or are we targeting XAP2 in this run (in which case different)?
  Implementor: surface before Task 5.
- **Is `g_count` and `g_unknown` synthetic-fixture style OK** for the resolved/unresolved global tests, or should we use
  real names from `xapasmcsr.exe`?
