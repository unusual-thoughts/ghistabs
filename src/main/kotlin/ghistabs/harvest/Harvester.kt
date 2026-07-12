package ghistabs.harvest

import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.importer.AddressResolver
import ghistabs.importer.ImportContext
import ghistabs.importer.stabAddress
import ghistabs.parse.*

/**
 * Harvest typed symbols and ASTs from a flat stab record stream. [preSeedHeaders] populates
 * per-CU [IncludeContext]s from N_SO/N_BINCL/N_EINCL/N_EXCL; [harvest] dispatches the main
 * record stream into [typeAsts], [symbolsByCu], [openFunctions].
 *
 * The [HeaderRegistry] is shared across all CUs so two CUs that BINCL the same
 * (filename, checksum) get identical GlobalTypeIds for header-attributed types
 * (stabs-canonicalization.md §3).
 */

class Harvester(private val monitor: TaskMonitor, sink: DiagnosticSink, private val resolver: AddressResolver) :
    DiagnosticSink by sink,
    Globalizer {
    constructor(ctx: ImportContext<*>) : this(ctx.monitor, ctx, ctx.resolver)

    private val typeAsts = mutableMapOf<GlobalTypeId, TypeAst>()
    private val collidingAsts = mutableMapOf<GlobalTypeId, MutableMap<String, MutableSet<TypeDecl<GlobalTypeId>>>>()
    private val symbolsByCu = mutableMapOf<String, MutableList<SymbolRecord>>()
    private val openFunctions = mutableListOf<OpenFunction>()
    private val includesByFile = mutableMapOf<String, IncludeContext>()
    private var parseErrors = 0

    private var currentCu: SourceFile.CUSource? = null
    private var currentFunction: OpenFunction? = null

    /**
     * Pending compilation directory from a trailing-slash N_SO (stabs.texinfo §"Source
     * Files": gcc emits dir-N_SO then filename-N_SO back-to-back; we pair them).
     */
    private var pendingDirectory: String? = null

    /**
     * Active filename for N_SLINE attribution. N_SOL switches it; N_SO end-of-CU clears.
     * Without this, lines inside #include'd headers would file under the enclosing CU.
     */
    private var currentSourceForLines: String? = null
    private val lineSource get() = currentSourceForLines ?: currentCu?.filename
    private val lineEntriesByFile = mutableMapOf<String, MutableList<LineEntry>>()

    /**
     * gcc 12 (and modern ELF emitters) omit the empty-name N_FUN end marker, delimiting
     * with the outermost N_RBRAC instead. Compute size from brackets before swapping
     * function context. N_RBRAC value is absolute-or-relative like N_SLINE.
     */
    private fun finaliseGcc12FunctionSize() {
        val f = currentFunction ?: return
        if (f.sizeBytes != null) return
        val rbracs = f.scopeBrackets.filter { it.first == StabType.N_RBRAC }
        if (rbracs.isEmpty()) return
        val funcStart = f.addr.address.offset
        val maxRbrac = rbracs.maxOf { it.second }
        f.sizeBytes = (if (maxRbrac > funcStart) maxRbrac - funcStart else maxRbrac).toULong()
    }

    // ONE shared registry across all per-CU IncludeContexts — same (filename, checksum)
    // BINCL across CUs gets the same HeaderFile instance.
    val sharedHeaderRegistry = HeaderRegistry(this)

    val currentInclude get() = includesByFile[currentCu?.filename]
    override fun globalIdFor(id: LocalTypeId) = GlobalTypeId(currentInclude?.sourceFor(id) ?: currentCu!!, id.n)

    internal fun preSeedHeaders(records: List<StabRecord>) {
        for (rec in records) {
            when (rec.type) {
                StabType.N_SO if (rec.name.endsWith('/')) -> {
                    pendingDirectory = rec.name
                }

                StabType.N_SO if (rec.name.isNotEmpty()) -> {
                    val cu = SourceFile.CUSource(rec.name, pendingDirectory)
                    currentCu = cu
                    includesByFile[rec.name] = IncludeContext(cu, this, sharedHeaderRegistry)
                    pendingDirectory = null
                }

                StabType.N_SO -> {
                    currentCu = null
                    pendingDirectory = null
                }

                StabType.N_BINCL -> currentInclude?.beginInclude(rec.name, rec.value)

                StabType.N_EINCL -> currentInclude?.endInclude()

                StabType.N_EXCL -> currentInclude?.remount(rec.name, rec.value)

                else -> {}
            }
        }
    }

    internal fun harvest(records: List<StabRecord>): Harvest {
        monitor.initialize(records.size.toLong(), "Stabs: harvesting")

        preSeedHeaders(records)
        for ((i, rec) in records.withIndex()) {
            monitor.increment()
            if (rec.desc != 0) {
                when (rec.type) {
                    StabType.N_FUN, StabType.N_SLINE, StabType.N_LSYM,
                    StabType.N_PSYM, StabType.N_RSYM,
                    StabType.N_GSYM, StabType.N_LCSYM, StabType.N_STSYM, StabType.N_ROSYM,
                    -> {
                    }

                    // Other record types with non-zero desc are silently dropping a line number.
                    else -> debug(
                        "desc-dropped-${rec.type.name.removePrefix("N_").lowercase()}",
                        "desc=${rec.desc} name=${rec.name.take(40)}",
                    )
                }
            }

            when (rec.type) {
                StabType.N_SO if (rec.name.endsWith('/')) -> {
                    pendingDirectory = rec.name
                }

                StabType.N_SO if (rec.name.isNotEmpty()) -> {
                    finaliseGcc12FunctionSize()
                    currentCu = SourceFile.CUSource(rec.name, pendingDirectory)
                    pendingDirectory = null
                    if (rec.value != 0L) {
                        debug(
                            "file-start",
                            "${currentCu?.directory.orEmpty()}${rec.name} starts here",
                            address = resolver.buildAddress(rec.value),
                        )
                    }
                }

                StabType.N_SO -> {
                    if (rec.value != 0L) {
                        debug(
                            "file-start",
                            "${currentCu?.filename} ends here",
                            address = resolver.buildAddress(rec.value),
                        )
                    }
                    finaliseGcc12FunctionSize()
                    currentCu = null
                    pendingDirectory = null
                    currentSourceForLines = null
                }

                StabType.N_BINCL, StabType.N_EINCL, StabType.N_EXCL -> {}

                StabType.N_SOL if rec.name.isNotEmpty() -> {
                    currentSourceForLines = rec.name
                }

                // N_SLINE: desc=line, value is function-relative (gcc/COFF on PE) or
                // already-absolute (gcc/ELF). Disambiguate by comparing to func start.
                StabType.N_SLINE -> {
                    val source = lineSource ?: continue
                    val abs = resolver.stabAddress(rec.value, currentFunction?.addr?.address)
                    val entry = LineEntry(rec.desc, SerializableAddress(abs), source)
                    lineEntriesByFile.getOrPut(source) { mutableListOf() } += entry
                    currentFunction?.lineEntries?.add(entry)
                }

                StabType.N_FUN -> if (rec.name.isEmpty()) {
                    // End-of-function marker: rec.value = size relative to start.
                    currentFunction?.let { it.sizeBytes = rec.value.toULong() }
                    currentFunction = null
                } else {
                    finaliseGcc12FunctionSize()
                    val addr = resolver.buildAddress(rec.value)
                    val mangled = rec.name.substringBefore(':')
                    resolver.recordFromStab(mangled, addr)
                    try {
                        val sym = parseSymbol(rec)
                        when (sym.body) {
                            is SymbolDecl.Function -> currentFunction = OpenFunction(
                                name = mangled,
                                addr = SerializableAddress(addr),
                                decl = sym.body,
                                cu = currentCu!!,
                            ).also { openFunctions += it }

                            is SymbolDecl.StaticVar -> harvestSymbol(rec)

                            else -> warn("unexpected-nfun", "$sym")
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        warn("parse-error", "@$i '${rec.name.take(80)}': ${e.message}")
                    }
                }

                StabType.N_GSYM -> harvestSymbol(rec)

                StabType.N_STSYM, StabType.N_LCSYM -> {
                    val addr = resolver.buildAddress(rec.value)
                    val mangled = rec.name.substringBefore(':')
                    resolver.recordFromStab(mangled, addr)
                    harvestSymbol(rec)
                }

                StabType.N_PSYM, StabType.N_RSYM -> {
                    val open = currentFunction ?: continue
                    try {
                        val sym = parseSymbol(rec)
                        when (sym.body) {
                            is SymbolDecl.StackParam, is SymbolDecl.RegParam -> open.params += sym
                            is SymbolDecl.RegLocal -> open.locals += sym
                            else -> warn("unexpected-psym-rsym", "$sym")
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        warn("parse-error", "param @$i: ${e.message}")
                    }
                }

                StabType.N_LSYM -> try {
                    val sym = parseSymbol(rec)
                    when (val decl = sym.body) {
                        is SymbolDecl.TaggedType -> {
                            // Outer ast + every InlineDef bound inside the struct body. gcc
                            // uses inline ids heavily for field types (anon pointers, arrays,
                            // function pointers); without walkDefinitions those become
                            // dangling Refs and undefined field types downstream.
                            val outer = TypeAst(
                                currentCu!!,
                                decl.id,
                                decl.name,
                                decl.type,
                                declLine = sym.declLine,
                                declSourceFile = sym.sourceFile,
                            )
                            appendAsts(
                                outer,
                                *walkDefinitions(decl.type, sym.declLine, sym.sourceFile).toTypedArray(),
                            )
                        }

                        is SymbolDecl.Typedef -> {
                            // `name:t(cu,n)` with no `=body` parses as a self-Ref Typedef:
                            // adds a name but no new body. Skip it — emitting an ast would
                            // collide with the real definition at the same id in another CU
                            // (every box2d typedef hit this).
                            if (decl.type !is TypeDecl.Ref || decl.type.id != decl.id) {
                                val outer = TypeAst(
                                    currentCu!!,
                                    decl.id,
                                    decl.name,
                                    decl.type,
                                    declLine = sym.declLine,
                                    declSourceFile = sym.sourceFile,
                                )
                                appendAsts(
                                    outer,
                                    *walkDefinitions(decl.type, sym.declLine, sym.sourceFile).toTypedArray(),
                                )
                            }
                        }

                        is SymbolDecl.StackLocal, is SymbolDecl.RegLocal -> {
                            currentFunction?.locals?.add(sym)
                        }

                        is SymbolDecl.StaticVar -> {
                            // Function-scope statics get their address from rec.value.
                            symbolsByCu.getOrPut(currentCu!!.filename) { mutableListOf() } += sym
                        }

                        is SymbolDecl.Function, is SymbolDecl.Global, is SymbolDecl.RegParam, is SymbolDecl.StackParam,
                        -> warn("unexpected-lsym", "$sym")
                    }
                } catch (e: StabsParseException) {
                    parseErrors++
                    warn("parse-error", "lsym @$i: ${e.message}")
                }

                StabType.N_LBRAC, StabType.N_RBRAC -> currentFunction?.scopeBrackets?.add(
                    Triple(rec.type, rec.value, i),
                )

                // Known-irrelevant for type/symbol harvesting.
                StabType.N_DSLINE, StabType.N_BSLINE, StabType.N_FLINE,
                StabType.N_OPT, StabType.N_OLEVEL, StabType.N_PARAMS, StabType.N_VERSION,
                StabType.N_MAIN, StabType.N_PC, StabType.N_M2C, StabType.N_DEFD,
                StabType.N_SSYM, StabType.N_ENDM, StabType.N_OSO, StabType.N_FNAME,
                StabType.N_EHDECL, StabType.N_CATCH, StabType.N_LENG,
                StabType.N_SCOPE, StabType.N_BCOMM, StabType.N_ECOMM, StabType.N_ECOML,
                StabType.N_ENTRY, StabType.N_MAC_DEFINE, StabType.N_MAC_UNDEF,
                // Apple/Sun cross-toolchain codes; benign on x86 PE/ELF.
                StabType.N_ROSYM, StabType.N_BNSYM, StabType.N_ENSYM, StabType.N_OBJ,
                StabType.N_ALIAS, StabType.N_NSYMS, StabType.N_NOMAP, StabType.N_PATCH,
                StabType.N_WITH,
                StabType.N_NBTEXT, StabType.N_NBDATA, StabType.N_NBBSS,
                StabType.N_NBSTS, StabType.N_NBLCS,
                -> debug("drop-record-${rec.type.name.removePrefix("N_").lowercase()}")

                // N_UNDF: cuOff/cuSize already advanced in StabReader. Empty N_SOL: nothing to switch to.
                StabType.N_UNDF, StabType.N_SOL ->
                    debug("drop-record-${rec.type.name.removePrefix("N_").lowercase()}-empty")

                // Hard signal: byte-decoder recognised but no harvesting rule. Log once per type.
                StabType.UNKNOWN -> warn(
                    "stab-unknown",
                    "rawType=0x${"%02X".format(rec.rawType)} @${rec.index} '${rec.name.take(60)}'",
                )
            }
        }

        synthesizeXRefStubsForDanglingInheritanceRefs()
        nameAnonymousTypedefTargets()

        return Harvest(
            typeAsts = typeAsts,
            parseErrors = parseErrors,
            rawCollisions = collidingAsts,
            symbolsByCu = symbolsByCu,
            openFunctions = openFunctions,
            lineEntries = lineEntriesByFile.mapValues { (_, v) ->
                v.sortedWith(compareBy({ it.line }, { it.addr.offset }))
            },
        )
    }

    /**
     * Recover gcc 12's malformed C++ inheritance emission. Instead of the documented
     * `!N,<bases>;` form, gcc 12 emits inheritance as a leading pseudo-field whose bitsize
     * is bytes×64 (a double byte→bit conversion bug; gdb itself crashes on these). Example:
     * `XMLText:T(0,81)=s112XMLNode:(0,25),0,6656;…` — XMLNode is 104B (832b) but stab says 6656.
     *
     * Detect via `field.sizeBits > struct.sizeBytes * 8` (real fields can't exceed their
     * enclosing struct), then move the field into `bases[]` and — if the Ref id is
     * dangling — synthesise an XRef-stub named after the field for cross-CU resolution.
     */
    private fun synthesizeXRefStubsForDanglingInheritanceRefs() {
        val synthetic = mutableListOf<TypeAst>()
        // Outer struct id → its inheritance-pseudo-fields. Rewriting moves them to `bases`
        // so the materialiser's BaseInsertionPlanner / firstPolymorphicBase / vtable wiring
        // sees the inheritance.
        val outerRewrites =
            mutableMapOf<GlobalTypeId, MutableList<FieldDecl<GlobalTypeId>>>()
        for (ast in typeAsts.values) {
            val struct = ast.body as? TypeDecl.Struct ?: continue
            val structBits = struct.sizeBytes * 8
            for (field in struct.fields) {
                val ref = field.type as? TypeDecl.Ref ?: continue
                if (field.name.isEmpty()) continue
                if (field.sizeBits <= structBits) continue
                // Rewrite fires regardless of whether the Ref is bound — the bogus-bitsize
                // signal is independent of cross-CU resolution.
                outerRewrites.getOrPut(ast.id) { mutableListOf() }.add(field)
                // Stub only needed when the Ref has no binding (materialiser resolves
                // bound Refs directly).
                if (ref.id in typeAsts) continue
                synthetic.add(
                    TypeAst(
                        cu = ast.cu,
                        id = ref.id,
                        name = field.name,
                        body = TypeDecl.XRef(AggrKind.STRUCT, field.name),
                        declLine = ast.declLine,
                        declSourceFile = ast.declSourceFile,
                    ),
                )
            }
        }
        if (synthetic.isNotEmpty()) {
            log(
                "xref-stubs-synthesized",
                "${synthetic.size} inheritance-pseudo-field Refs → synthetic XRef stubs",
            )
            appendAsts(*synthetic.toTypedArray())
        }
        for ((outerId, pseudoFields) in outerRewrites) {
            val outer = typeAsts[outerId] ?: continue
            val struct = outer.body as? TypeDecl.Struct ?: continue
            val pseudoSet = pseudoFields.toSet()
            val newBases = struct.bases + pseudoFields.map { f ->
                BaseDecl(
                    type = f.type,
                    isVirtual = false,
                    access = Access.PUBLIC,
                    offsetBits = f.offsetBits,
                )
            }
            val newFields = struct.fields.filter { it !in pseudoSet }
            typeAsts[outerId] = outer.copy(
                body = struct.copy(bases = newBases, fields = newFields),
            )
        }
        if (outerRewrites.isNotEmpty()) {
            log(
                "inheritance-pseudo-fields-promoted",
                "${outerRewrites.size} outer struct(s) rewritten to populate bases[]",
            )
        }
    }

    /**
     * `typedef struct {…} Name;` reaches us as an anonymous aggregate + a same-named typedef that
     * inline-defines it. C-semantically the aggregate's name *is* the typedef's, so adopt it, so the
     * anonymous struct/enum carries the real name and [TypeResolver.byCanonicalKey] can merge it with
     * the named copy from another header spelling (render-backlog §20).
     */
    private fun nameAnonymousTypedefTargets() {
        val renames = anonymousTypedefTargetNames(typeAsts)
        for ((id, name) in renames) typeAsts[id] = typeAsts.getValue(id).copy(name = name)
        if (renames.isNotEmpty()) debug("typedef-named-anon-aggregate", count = renames.size.toLong())
    }

    private fun harvestSymbol(rec: StabRecord) {
        try {
            symbolsByCu.getOrPut(currentCu!!.filename) { mutableListOf() } += parseSymbol(rec)
        } catch (e: StabsParseException) {
            parseErrors++
            warn("parse-error", "@${rec.index} '${rec.name.take(80)}': ${e.message}")
        }
    }

    /**
     * Gather TypeAsts for every InlineDef in [decl]. The nested asts inherit the
     * enclosing declaration's source location.
     */
    fun walkDefinitions(
        decl: TypeDecl<GlobalTypeId>,
        declLine: Int = 0,
        declSourceFile: String? = null,
    ): List<TypeAst> {
        fun walk(d: TypeDecl<GlobalTypeId>): List<TypeAst> = when (d) {
            is TypeDecl.Builtin, is TypeDecl.Complex, is TypeDecl.Float, is TypeDecl.Enum, is TypeDecl.Range,
            is TypeDecl.Ref, is TypeDecl.XRef,
            -> listOf()

            is TypeDecl.Const -> walk(d.inner)

            is TypeDecl.Volatile -> walk(d.inner)

            is TypeDecl.WithSizeAttr -> walk(d.inner)

            is TypeDecl.Pointer -> walk(d.pointee)

            is TypeDecl.Reference -> walk(d.referent)

            is TypeDecl.Array -> walk(d.element) + (d.indexType?.let { walk(it) } ?: listOf())

            is TypeDecl.FunctionT -> d.params.flatMap { walk(it) } + walk(d.ret)

            is TypeDecl.Method -> d.params.flatMap { walk(it) } + walk(d.ret) + walk(d.cls)

            is TypeDecl.Struct -> d.bases.flatMap { walk(it.type) } +
                d.fields.flatMap { walk(it.type) } +
                d.methods.flatMap { walk(it.signature) }

            // Emit the InlineDef ast AND recurse — gcc nests them (e.g. Method whose
            // return is an inline-defined Pointer-to-X). Without recursion the inner
            // ids are referenced but never registered → dangling Refs + false collisions.
            is TypeDecl.InlineDef -> listOf(
                TypeAst(
                    currentCu!!,
                    d.id,
                    null,
                    d.body,
                    declLine = declLine,
                    declSourceFile = declSourceFile,
                ),
            ) + walk(d.body)
        }
        return walk(decl)
    }

    /**
     * Accumulate asts with first-writer-wins on GlobalTypeId. XRef placeholders are replaced
     * by any concrete body. Collisions go into [collidingAsts] for post-harvest classification —
     * no per-collision Ref-walking here (slow on template-heavy binaries);
     * `Harvest.classifyCollisions` runs once at the end against a memoized hashCache.
     */
    fun appendAsts(vararg asts: TypeAst) {
        val new = asts.groupBy { it.id }
        val collisions = new.keys.intersect(typeAsts.keys).filter { typeAsts[it]?.body !is TypeDecl.XRef }
        for (id in collisions) {
            val ex = typeAsts[id]!!
            val incoming = new[id]!!

            // Name-promotion: an anonymous InlineDef ast can be superseded by an explicit
            // named Typedef at the same id. Range's `of` self-ref differs between forms so
            // we don't require body equality — both non-XRefTarget + existing unnamed.
            val namedIncoming = incoming.firstOrNull { it.name != null && !it.body.isXRefTarget }
            if (namedIncoming != null && ex.name == null && !ex.body.isXRefTarget) {
                typeAsts[id] = namedIncoming
                continue
            }

            // Structural-equality skip (no Ref-walk): literal re-emissions aren't worth
            // recording. classifyCollisions does the deeper check for survivors.
            val alternates = incoming.filter { it.body != ex.body }.map { it.body }
            if (alternates.isEmpty()) continue
            val bucket = collidingAsts
                .getOrPut(id) { mutableMapOf() }
                .getOrPut(ex.nameOrUnique) { mutableSetOf() }
            bucket.add(ex.body)
            bucket.addAll(alternates)
        }

        for (ast in asts.filter { !collisions.contains(it.id) }) {
            typeAsts[ast.id] = ast
        }
    }

    fun parseSymbol(rec: StabRecord) = SymbolRecord(
        rec,
        Parser(rec.name).parseSymbol().globalize(this).also {
            appendAsts(*walkDefinitions(it.type, rec.desc, lineSource).toTypedArray())
        },
        lineSource,
    )
}

/**
 * Pure core of the `typedef struct {…} Name;` naming (see [Harvester.nameAnonymousTypedefTargets]).
 * Returns `anonymous-aggregate-id → name` for every anonymous Struct/Enum that a typedef targets,
 * when **exactly one** typedef name claims it (ambiguous multi-name targets are left anonymous).
 * Two stab encodings qualify: the inline form `t3=4=s…` (`InlineDef`, gcc's usual for `typedef
 * struct {…} Name`) and the separate-then-reference form `t2=1` with `1=e…` (`Ref`, gcc's usual for
 * `typedef enum {…} Name`). Only genuinely anonymous targets (no tag) — a bare alias to an
 * already-named type is skipped by the target-name guard, and a builtin/pointer target by the kind
 * guard.
 */
fun anonymousTypedefTargetNames(typeAsts: Map<GlobalTypeId, TypeAst>): Map<GlobalTypeId, String> {
    val namesByTarget = mutableMapOf<GlobalTypeId, MutableSet<String>>()
    for (td in typeAsts.values) {
        val name = td.name?.ifEmpty { null } ?: continue
        val targetId = when (val body = td.body) {
            is TypeDecl.InlineDef -> body.id
            is TypeDecl.Ref -> body.id
            else -> continue
        }
        val target = typeAsts[targetId] ?: continue
        if (!target.name.isNullOrEmpty()) continue
        if (target.body !is TypeDecl.Struct && target.body !is TypeDecl.Enum) continue
        namesByTarget.getOrPut(targetId) { mutableSetOf() }.add(name)
    }
    return namesByTarget.filterValues { it.size == 1 }.mapValues { it.value.single() }
}
