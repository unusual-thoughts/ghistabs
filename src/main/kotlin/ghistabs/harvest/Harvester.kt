package ghistabs.harvest

import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.importer.AddressResolver
import ghistabs.parse.*

/**
 * Harvest typed symbols and type ASTs from a flat stab record stream.
 *
 * Two-pass: [preSeedHeaders] scans N_SO/N_BINCL/N_EINCL/N_EXCL to populate per-CU
 * [IncludeContext]s, then [passA] dispatches on record type to fill [typeAsts] / [symbolsByCu] /
 * [openFunctions].
 *
 * All [IncludeContext]s share one [HeaderRegistry] so identical `(filename, checksum)` BINCLs
 * across CUs yield the same [HeaderFile] — the cross-CU dedup invariant for [GlobalTypeId]s
 * (see stabs-canonicalization.md §3).
 */
class Harvester(
    private val monitor: TaskMonitor,
    private val sink: DiagnosticSink,
    private val resolver: AddressResolver,
) : DiagnosticSink by sink,
    Globalizer {
    private val typeAsts = mutableMapOf<GlobalTypeId, TypeAst>()
    private val collidingAsts = mutableMapOf<GlobalTypeId, MutableMap<String, MutableSet<TypeDecl<GlobalTypeId>>>>()
    private val symbolsByCu = mutableMapOf<String, MutableList<SymbolRecord>>()
    private val openFunctions = mutableListOf<OpenFunction>()
    private val includesByFile = mutableMapOf<String, IncludeContext>()
    private var parseErrors = 0

    private var currentCu: SourceFile.CUSource? = null
    private var currentFunction: OpenFunction? = null

    /**
     * Trailing-slash N_SO that we'll pair with the next named N_SO as that CU's directory
     * (stabs.texinfo §"Source Files": gcc emits dir + filename N_SOs back-to-back).
     */
    private var pendingDirectory: String? = null

    /** Source filename for N_SLINE attribution; set by N_SOL, cleared at end-of-CU. */
    private var currentSourceForLines: String? = null
    private val lineSource get() = currentSourceForLines ?: currentCu?.filename
    private val lineEntriesByFile = mutableMapOf<String, MutableList<LineEntry>>()

    /**
     * Recover function size for gcc-12 emitters that omit the empty-name end-of-fn N_FUN —
     * use the outermost N_RBRAC. N_RBRAC values follow the same absolute-vs-function-relative
     * heuristic as N_SLINE (large = absolute text addr, small = fn-relative offset).
     */
    private fun finaliseGcc12FunctionSize() {
        val f = currentFunction ?: return
        if (f.sizeBytes != 0L) return
        val rbracs = f.scopeBrackets.filter { it.first == StabType.N_RBRAC }
        if (rbracs.isEmpty()) return
        val funcStart = f.addr.address.offset
        val maxRbrac = rbracs.maxOf { it.second }
        f.sizeBytes = if (maxRbrac > funcStart) maxRbrac - funcStart else maxRbrac
    }

    /** Shared across every IncludeContext — cross-CU `(filename, checksum)` dedup invariant. */
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

    internal fun passA(records: List<StabRecord>): Harvest {
        preSeedHeaders(records)
        for ((i, rec) in records.withIndex()) {
            monitor.checkCancelled()
            monitor.incrementProgress(1)
            if (rec.desc != 0) {
                when (rec.type) {
                    StabType.N_FUN, StabType.N_SLINE, StabType.N_LSYM,
                    StabType.N_PSYM, StabType.N_RSYM,
                    StabType.N_GSYM, StabType.N_LCSYM, StabType.N_STSYM, StabType.N_ROSYM,
                    -> {
                    }

                    // Any other record with a non-zero desc is silently dropping a line number;
                    // tally it so we can see the surface we're missing.
                    else -> log(
                        "desc-dropped-${rec.type.name.removePrefix("N_").lowercase()}",
                        "desc=${rec.desc} name=${rec.name.take(40)}",
                        Level.DEBUG,
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
                        log(
                            "file-start",
                            "${currentCu?.directory.orEmpty()}${rec.name} starts here",
                            Level.DEBUG,
                            address = resolver.buildAddress(rec.value),
                        )
                    }
                }

                StabType.N_SO -> {
                    if (rec.value != 0L) {
                        log(
                            "file-start",
                            "${currentCu?.filename} ends here",
                            Level.DEBUG,
                            address = resolver.buildAddress(rec.value),
                        )
                    }
                    finaliseGcc12FunctionSize()
                    currentCu = null
                    pendingDirectory = null
                    currentSourceForLines = null
                }

                StabType.N_BINCL, StabType.N_EINCL, StabType.N_EXCL -> {}

                // N_SOL switches source filename for subsequent N_SLINE.
                StabType.N_SOL if rec.name.isNotEmpty() -> {
                    currentSourceForLines = rec.name
                }

                // N_SLINE value is either fn-relative (gcc/COFF, dbx-historical) or absolute
                // (gcc/ELF); disambiguate by comparing to the current function's start address.
                StabType.N_SLINE -> {
                    val source = lineSource ?: continue
                    val funcStart = currentFunction?.addr?.address
                    val abs = when {
                        funcStart != null && rec.value < funcStart.offset -> funcStart.add(rec.value)
                        else -> resolver.buildAddress(rec.value)
                    }
                    lineEntriesByFile.getOrPut(source) { mutableListOf() } +=
                        LineEntry(rec.desc, SerializableAddress(abs))
                }

                StabType.N_FUN -> if (rec.name.isEmpty()) {
                    // End-of-function: value = size relative to start.
                    currentFunction?.let { it.sizeBytes = rec.value }
                    currentFunction = null
                } else {
                    // gcc 12 ELF omits the end-of-fn marker — finalise the previous via N_RBRAC.
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

                            else -> log("unexpected-nfun", "$sym")
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        log("parse-error", "@$i '${rec.name.take(80)}': ${e.message}")
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
                            else -> log("unexpected-psym-rsym", "$sym")
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        log("parse-error", "param @$i: ${e.message}")
                    }
                }

                StabType.N_LSYM -> try {
                    val sym = parseSymbol(rec)
                    when (val decl = sym.body) {
                        is SymbolDecl.TaggedType -> {
                            // Recurse via walkDefinitions so InlineDef-bound nested ids (anon ptrs,
                            // arrays, fn-ptrs) get their own TypeAsts — otherwise downstream
                            // `Ref(id)`s dangle.
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
                            // Skip self-Ref typedefs (`name:t(cu,n)` with no `=body`) — emitting
                            // a body-less alias would collide with the real definition in another CU.
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
                            // Function-scope static variables get their actual address from rec.value
                            symbolsByCu.getOrPut(currentCu!!.filename) { mutableListOf() } += sym
                        }

                        is SymbolDecl.Function, is SymbolDecl.Global, is SymbolDecl.RegParam, is SymbolDecl.StackParam,
                        -> log("unexpected-lsym", "$sym")
                    }
                } catch (e: StabsParseException) {
                    parseErrors++
                    log("parse-error", "lsym @$i: ${e.message}")
                }

                StabType.N_LBRAC, StabType.N_RBRAC -> currentFunction?.scopeBrackets?.add(
                    Triple(rec.type, rec.value, i),
                )

                // Known-irrelevant for harvesting — silently bucketed (would otherwise drown the log).
                StabType.N_DSLINE, StabType.N_BSLINE, StabType.N_FLINE,
                StabType.N_OPT, StabType.N_OLEVEL, StabType.N_PARAMS, StabType.N_VERSION,
                StabType.N_MAIN, StabType.N_PC, StabType.N_M2C, StabType.N_DEFD,
                StabType.N_SSYM, StabType.N_ENDM, StabType.N_OSO, StabType.N_FNAME,
                StabType.N_EHDECL, StabType.N_CATCH, StabType.N_LENG,
                StabType.N_SCOPE, StabType.N_BCOMM, StabType.N_ECOMM, StabType.N_ECOML,
                StabType.N_ENTRY, StabType.N_MAC_DEFINE, StabType.N_MAC_UNDEF,
                // Apple/Sun cross-toolchain codes; benign for x86 PE / ELF.
                StabType.N_ROSYM, StabType.N_BNSYM, StabType.N_ENSYM, StabType.N_OBJ,
                StabType.N_ALIAS, StabType.N_NSYMS, StabType.N_NOMAP, StabType.N_PATCH,
                StabType.N_WITH,
                StabType.N_NBTEXT, StabType.N_NBDATA, StabType.N_NBBSS,
                StabType.N_NBSTS, StabType.N_NBLCS,
                -> log("drop-record-${rec.type.name.removePrefix("N_").lowercase()}")

                // N_UNDF: StabReader already advanced cuOff/cuSize. Empty N_SOL: no filename to switch.
                StabType.N_UNDF, StabType.N_SOL ->
                    log("drop-record-${rec.type.name.removePrefix("N_").lowercase()}-empty")

                // Decoder recognised the type but we have no harvesting rule — log loudly with rawType.
                StabType.UNKNOWN -> log(
                    "stab-unknown",
                    "rawType=0x${"%02X".format(rec.rawType)} @${rec.recordIndex} '${rec.name.take(60)}'",
                )
            }
        }

        synthesizeXRefStubsForDanglingInheritanceRefs()

        return Harvest(
            typeAsts = typeAsts,
            parseErrors = parseErrors,
            rawCollisions = collidingAsts,
            symbolsByCu = symbolsByCu,
            openFunctions = openFunctions,
            lineEntries = lineEntriesByFile.mapValues { (_, v) -> v.sortedBy { it.line } },
        )
    }

    /**
     * Detect gcc-12's C++ inheritance-as-pseudo-field bug and recover it as a proper base.
     *
     * gcc 12 emits inheritance as a leading field whose `sizeBits` is 64× the base's bytes
     * (double byte→bit conversion) instead of the documented `!N,<bases>;` form. Verified vs
     * objdump and gdb (which crashes on the same data, so the stab is genuinely malformed).
     * Detection: `field.sizeBits > struct.sizeBytes * 8` — a real field can't exceed its
     * struct. We rewrite the field into `bases` and synthesise an XRef stub at the dangling id
     * (named after the field) so [TypeResolver.lookupByXRef] can resolve it cross-CU.
     */
    private fun synthesizeXRefStubsForDanglingInheritanceRefs() {
        val synthetic = mutableListOf<TypeAst>()
        val outerRewrites =
            mutableMapOf<GlobalTypeId, MutableList<FieldDecl<GlobalTypeId>>>()
        for (ast in typeAsts.values) {
            val struct = ast.body as? TypeDecl.Struct ?: continue
            val structBits = struct.sizeBytes * 8
            for (field in struct.fields) {
                val ref = field.type as? TypeDecl.Ref ?: continue
                if (field.name.isEmpty()) continue
                if (field.sizeBits <= structBits) continue
                // Always rewrite into bases — gcc-12's bogus bitsize is independent of resolution.
                outerRewrites.getOrPut(ast.id) { mutableListOf() }.add(field)
                // Only synthesise an XRef stub if no resolution exists anywhere.
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

    private fun harvestSymbol(rec: StabRecord) {
        try {
            symbolsByCu.getOrPut(currentCu!!.filename) { mutableListOf() } += parseSymbol(rec)
        } catch (e: StabsParseException) {
            parseErrors++
            log("parse-error", "@${rec.recordIndex} '${rec.name.take(80)}': ${e.message}")
        }
    }

    /**
     * Walk a TypeDecl emitting a [TypeAst] for every nested [TypeDecl.InlineDef]. Anonymous nested
     * TypeAsts inherit the outer's `declLine` / `declSourceFile` (they're declared at the same site).
     * Without the recursion gcc's nested InlineDefs (e.g. Method → InlineDef Pointer-to-X) leave
     * inner ids referenced but never registered.
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
     * Accumulate TypeAsts into [typeAsts] with first-writer-wins on GlobalTypeId collisions:
     *  - non-colliding → insert
     *  - existing XRef placeholder → replaced by any later concrete body for the same id
     *  - real collision → record all alternates into [collidingAsts] for post-harvest classification.
     *
     * No per-collision contentHash walk here — that turned harvest into 10-min on template-heavy
     * binaries. `StabsImporter` runs `Harvest.classifyCollisions` once after harvest instead.
     */
    fun appendAsts(vararg asts: TypeAst) {
        val new = asts.groupBy { it.id }
        val collisions = new.keys.intersect(typeAsts.keys).filter { typeAsts[it]?.body !is TypeDecl.XRef }
        for (id in collisions) {
            val ex = typeAsts[id]!!
            val incoming = new[id]!!

            // Name-promotion: anonymous InlineDef-extracted ast superseded by a named Typedef
            // for the same id. Range bodies' `of` self-ref differs between forms, so don't require
            // body equality — both non-XRefTarget + existing unnamed is enough.
            val namedIncoming = incoming.firstOrNull { it.name != null && !it.body.isXRefTarget }
            if (namedIncoming != null && ex.name == null && !ex.body.isXRefTarget) {
                typeAsts[id] = namedIncoming
                continue
            }

            // Skip literal re-emissions via structural equality; classifyCollisions does the
            // deeper Ref-aware check on what survives.
            val alternates = incoming.filter { it.body != ex.body }.map { it.body }
            if (alternates.isEmpty()) continue
            val bucket = collidingAsts
                .getOrPut(id) { mutableMapOf() }
                .getOrPut(ex.nameOrId) { mutableSetOf() }
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
