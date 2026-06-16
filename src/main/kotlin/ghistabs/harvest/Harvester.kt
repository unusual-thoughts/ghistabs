package ghistabs.harvest

import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.importer.AddressResolver
import ghistabs.parse.*

/**
 * Harvests typed symbols and type ASTs from a flat stab record stream.
 *
 * Two-pass pipeline:
 *  1. [preSeedHeaders] — scans for N_SO / N_BINCL / N_EINCL / N_EXCL to populate
 *     per-CU [IncludeContext] instances before any type symbols are processed.
 *  2. [passA] — main pass; dispatches on record type to populate [typeAsts],
 *     [symbolsByCu], and [openFunctions], calling [globalize] and [appendAsts]
 *     for each parsed symbol.
 *
 * Shared-registry invariant: the [HeaderRegistry] passed to each [IncludeContext]
 * is shared across all CUs. Two CUs that BINCL/EXCL the same (filename, checksum)
 * therefore receive the same [ghistabs.parse.HeaderFile] instance, making their [ghistabs.parse.GlobalTypeId]s
 * identical for header-attributed types (see stabs-canonicalization.md §3).
 */
class Harvester(
    private val monitor: TaskMonitor,
    private val sink: DiagnosticSink,
    private val resolver: AddressResolver,
) : DiagnosticSink by sink,
    Globalizer {
    private val typeAsts = mutableMapOf<GlobalTypeId, TypeAst>()
    private val collidingAsts = mutableMapOf<GlobalTypeId, MutableMap<String, MutableSet<TypeDecl<GlobalTypeId>>>>()
    private val symbolsByCu = mutableMapOf<String, MutableList<HarvestedSymbol>>()
    private val openFunctions = mutableListOf<OpenFunction>()
    private val includesByFile = mutableMapOf<String, IncludeContext>()
    private var parseErrors = 0

    private var currentCu: SourceFile.CUSource? = null
    private var currentFunction: OpenFunction? = null

    // Allocate ONE shared HeaderRegistry for all per-CU IncludeContext instances.
    // This ensures cross-CU dedup: two CUs with the same (filename, checksum) BINCL
    // get the SAME HeaderFile instance via the shared registry.
    val sharedHeaderRegistry = HeaderRegistry(this)

    val currentInclude get() = includesByFile[currentCu?.filename]
    override fun globalIdFor(id: LocalTypeId) = GlobalTypeId(currentInclude?.sourceFor(id) ?: currentCu!!, id.n)

    internal fun preSeedHeaders(records: List<StabRecord>) {
        for (rec in records) {
            when (rec.type) {
                StabType.N_SO if (rec.name.isNotEmpty()) -> {
                    currentCu = SourceFile.CUSource(rec.name)
                    includesByFile[rec.name] = IncludeContext(SourceFile.CUSource(rec.name), this, sharedHeaderRegistry)
                }

                StabType.N_SO -> {
                    currentCu = null
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

            when (rec.type) {
                StabType.N_SO if (rec.name.isNotEmpty()) -> {
                    currentCu = SourceFile.CUSource(rec.name)
                    if (rec.value != 0L) {
                        log(
                            "file-start",
                            "${rec.name} starts here",
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
                    currentCu = null
                }

                // line context
                StabType.N_BINCL, StabType.N_EINCL, StabType.N_EXCL -> {}

                StabType.N_FUN -> if (rec.name.isEmpty()) {
                    // End-of-function marker: rec.value = function size relative to start.
                    currentFunction?.let { it.sizeBytes = rec.value }
                    currentFunction = null
                } else {
                    val addr = resolver.buildAddress(rec.value)
                    // Pull mangled name from before the colon.
                    val mangled = rec.name.substringBefore(':')
                    resolver.recordFromStab(mangled, addr)
                    try {
                        when (val decl = parseSymbol(rec)) {
                            is SymbolDecl.Function -> {
                                val open = OpenFunction(
                                    name = mangled,
                                    addr = SerializableAddress(addr),
                                    decl = SymbolDecl.Function(decl.name, decl.isFileStatic, decl.type),
                                    cu = currentCu!!,
                                    locals = mutableListOf(),
                                    params = mutableListOf(),
                                    scopeBrackets = mutableListOf(),
                                )
                                openFunctions += open
                                currentFunction = open
                            }

                            is SymbolDecl.StaticVar -> harvestSymbol(rec) { parseErrors++ }

                            else -> log("unexpected-nfun", "@$i: $decl")
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        log("parse-error", "@$i '${rec.name.take(80)}': ${e.message}")
                    }
                }

                StabType.N_GSYM -> harvestSymbol(rec) { parseErrors++ }

                StabType.N_STSYM, StabType.N_LCSYM -> {
                    val addr = resolver.buildAddress(rec.value)
                    val mangled = rec.name.substringBefore(':')
                    resolver.recordFromStab(mangled, addr)
                    harvestSymbol(rec) { parseErrors++ }
                }

                StabType.N_PSYM, StabType.N_RSYM -> {
                    val open = currentFunction ?: continue
                    try {
                        when (val decl = parseSymbol(rec)) {
                            is SymbolDecl.StackParam, is SymbolDecl.RegParam ->
                                open.params += ParamRecord(decl, rec.value)

                            is SymbolDecl.RegLocal ->
                                open.locals.add(LocalRecord(decl, rec.value, i))

                            else -> log("unexpected-psym-rsym", "@$i: $decl")
                        }
                    } catch (e: StabsParseException) {
                        parseErrors++
                        log("parse-error", "param @$i: ${e.message}")
                    }
                }

                StabType.N_LSYM -> try {
                    when (val decl = parseSymbol(rec)) {
                        is SymbolDecl.TaggedType -> appendAsts(
                            TypeAst(currentCu!!, decl.id, decl.name, decl.type),
                        )

                        is SymbolDecl.Typedef -> {
                            // `name:t(cu,n)` with no `=body` parses as
                            // `Typedef(name, id, Ref(id))` — a self-Ref. The
                            // typedef adds a name but no new type definition,
                            // so emitting it as a TypeAst would create a
                            // body-less alias that collides with the real
                            // definition at the same id in another CU
                            // (every box2d typedef went this way).
                            if (decl.type !is TypeDecl.Ref || decl.type.id != decl.id) {
                                appendAsts(TypeAst(currentCu!!, decl.id, decl.name, decl.type))
                            }
                        }

                        is SymbolDecl.StackLocal, is SymbolDecl.RegLocal -> {
                            currentFunction?.locals?.add(LocalRecord(decl, rec.value, i))
                        }

                        is SymbolDecl.StaticVar -> {
                            // Function-scope static variables get their actual address from rec.value
                            symbolsByCu.getOrPut(currentCu!!.filename) { mutableListOf() } +=
                                HarvestedSymbol(decl, rec.type, rec.value)
                        }

                        is SymbolDecl.Function, is SymbolDecl.Global, is SymbolDecl.RegParam, is SymbolDecl.StackParam,
                        -> log("unexpected-lsym", "@$i: $decl")
                    }
                } catch (e: StabsParseException) {
                    parseErrors++
                    log("parse-error", "lsym @$i: ${e.message}")
                }

                StabType.N_LBRAC, StabType.N_RBRAC -> currentFunction?.scopeBrackets?.add(
                    Triple(rec.type, rec.value, i),
                )

                // Known-irrelevant for type/symbol harvesting — bumped silently into
                // diagnostics counters by the caller (no per-record log lines, which
                // otherwise drown the log under N_SLINE @ 23k records/binary).
                StabType.N_SLINE, StabType.N_DSLINE, StabType.N_BSLINE, StabType.N_FLINE,
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

                // Empty-name forms that already played their role inside StabReader:
                //   - N_UNDF: cuOff/cuSize were advanced as the record streamed by.
                //   - empty N_SOL: ignored (no source filename to switch to).
                StabType.N_UNDF, StabType.N_SOL ->
                    log("drop-record-${rec.type.name.removePrefix("N_").lowercase()}-empty")

                // Hard signal — a stab type the byte-decoder recognises but we have
                // no harvesting rule for. Log loudly, once per type, with rawType so
                // the binary's source (compiler/linker) can be identified.
                StabType.UNKNOWN -> log(
                    "stab-unknown",
                    "rawType=0x${"%02X".format(rec.rawType)} @${rec.recordIndex} '${rec.name.take(60)}'",
                )
            }
        }

        return Harvest(
            typeAsts,
            parseErrors,
            collidingAsts,
            symbolsByCu,
            openFunctions,
            sink,
        ).apply {
            classifyCollisions()
            byCanonicalKey // force lazy build so canonical-key diagnostics surface during harvest
        }
    }

    private fun harvestSymbol(rec: StabRecord, onError: () -> Unit) {
        try {
            val decl = parseSymbol(rec)
            symbolsByCu.getOrPut(currentCu!!.filename) { mutableListOf() } += HarvestedSymbol(
                decl,
                rec.type,
                rec.value,
            )
        } catch (e: StabsParseException) {
            onError()
            log("parse-error", "@${rec.recordIndex} '${rec.name.take(80)}': ${e.message}")
        }
    }

    fun walkDefinitions(decl: TypeDecl<GlobalTypeId>): List<TypeAst> = when (decl) {
        is TypeDecl.Builtin, is TypeDecl.Complex, is TypeDecl.Enum, is TypeDecl.Range,
        is TypeDecl.Ref, is TypeDecl.XRef,
        -> listOf()

        is TypeDecl.Const -> walkDefinitions(decl.inner)

        is TypeDecl.Volatile -> walkDefinitions(decl.inner)

        is TypeDecl.WithSizeAttr -> walkDefinitions(decl.inner)

        is TypeDecl.Pointer -> walkDefinitions(decl.pointee)

        is TypeDecl.Reference -> walkDefinitions(decl.referent)

        is TypeDecl.Array -> walkDefinitions(decl.element) + (decl.indexType?.let { walkDefinitions(it) } ?: listOf())

        is TypeDecl.FunctionT -> decl.params.flatMap { walkDefinitions(it) } + walkDefinitions(decl.ret)

        is TypeDecl.Method -> decl.params.flatMap { walkDefinitions(it) } + walkDefinitions(decl.ret) + walkDefinitions(
            decl.cls,
        )

        is TypeDecl.Struct -> decl.bases.flatMap { walkDefinitions(it.type) } +
            decl.fields.flatMap { walkDefinitions(it.type) } +
            decl.methods.flatMap { walkDefinitions(it.signature) }

        // Emit the outer InlineDef's TypeAst AND recurse into its body —
        // gcc nests InlineDefs (e.g. an outer Method whose return type is
        // itself an inline-defined Pointer-to-X), and without the
        // recursion the inner ids are referenced by other types but
        // never registered. Result: the contentHash oracle can't resolve
        // the Refs, per-CU clones diverge, and the appendAsts collision
        // log surfaces hundreds of false "different hash" entries.
        is TypeDecl.InlineDef -> listOf(TypeAst(currentCu!!, decl.id, "${decl.id}", decl.body)) +
            walkDefinitions(decl.body)
    }

    /**
     * Accumulate [TypeAst]s into [typeAsts] with first-writer-wins on
     * GlobalTypeId collisions.
     *
     * 1. **Non-colliding:** insert as-is.
     * 2. **Existing XRef placeholder:** replaced by any concrete body that
     *    arrives later for the same id (see filter on the collision set).
     * 3. **GlobalTypeId already taken:** record every alternate body into
     *    [collidingAsts] for post-harvest classification, then drop the
     *    new entries. No per-collision logging or `contentHash` walk
     *    here — that turned the harvest into a 10-minute affair on
     *    template-heavy binaries. `Harvest.classifyCollisions` runs once
     *    after harvest against a fully populated `typeAsts` and the
     *    memoized `hashCache` to surface real-vs-spurious counts; see
     *    `StabsImporter`.
     */
    fun appendAsts(vararg asts: TypeAst) {
        val new = asts.groupBy { it.id }
        val collisions = new.keys.intersect(typeAsts.keys).filter { typeAsts[it]?.body !is TypeDecl.XRef }
        for (id in collisions) {
            val ex = typeAsts[id]!!
            // Cheap-equality skip: if every alternate body is `==` to
            // the merged entry (data-class structural equality, no
            // Ref-walk), the collision is a literal re-emission and
            // not worth recording. classifyCollisions does the deeper
            // Ref-aware check later for the entries that survive.
            val alternates = new[id]!!.filter { it.body != ex.body }.map { it.body }
            if (alternates.isEmpty()) continue
            val bucket = collidingAsts
                .getOrPut(id) { mutableMapOf() }
                .getOrPut(ex.name) { mutableSetOf() }
            bucket.add(ex.body)
            bucket.addAll(alternates)
        }

        for (ast in asts.filter { !collisions.contains(it.id) }) {
            typeAsts[ast.id] = ast
        }
    }

    fun parseSymbol(rec: StabRecord) = Parser(rec.name).parseSymbol().globalize(this).also {
        appendAsts(*walkDefinitions(it.type).toTypedArray())
    }
}
