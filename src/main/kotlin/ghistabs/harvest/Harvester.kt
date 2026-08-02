package ghistabs.harvest

import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.importer.AddressResolver
import ghistabs.importer.ImportContext
import ghistabs.parse.*

/**
 * Harvest typed symbols and ASTs from a flat stab record stream. [preSeedHeaders] populates
 * per-CU [IncludeContext]s from N_SO/N_BINCL/N_EINCL/N_EXCL; [harvest] dispatches the main
 * record stream into [store], [symbolsByCu], [openFunctions].
 *
 * The [HeaderRegistry] is shared across all CUs so two CUs that BINCL the same
 * (filename, checksum) get identical GlobalTypeIds for header-attributed types
 * (stabs-canonicalization.md §3).
 */

class Harvester(private val monitor: TaskMonitor, sink: DiagnosticSink, private val resolver: AddressResolver) :
    DiagnosticSink by sink,
    Globalizer {
    constructor(ctx: ImportContext<*>) : this(ctx.monitor, ctx, ctx.resolver)

    private val store = AstStore(sink = sink)
    private val symbolsByCu = mutableMapOf<String, MutableList<SymbolRecord>>()
    private val openFunctions = mutableListOf<OpenFunction>()
    private val includesByFile = mutableMapOf<String, IncludeContext>()
    private var parseErrors = 0
    private val constants = mutableListOf<SymbolDecl.Constant<GlobalTypeId>>()

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
     * function context.
     */
    private fun finaliseGcc12FunctionSize() {
        val f = currentFunction ?: return
        if (f.sizeBytes != null) return
        val lastRbrac = f.scopeBrackets.filter { it.type == StabType.N_RBRAC }.maxOfOrNull { it.addr.offset } ?: return
        f.sizeBytes = (lastRbrac - f.addr.offset).toULong()
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
                    val abs = resolver.stabAddress(rec.value, currentFunction?.addr)
                    val entry = LineEntry(rec.desc, abs, source)
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
                    try {
                        val sym = parseSymbol(rec)
                        when (sym.body) {
                            is SymbolDecl.Function -> currentFunction = OpenFunction(
                                name = mangled,
                                addr = addr,
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

                // Address-bearing statics: N_STSYM=data, N_LCSYM=bss, N_ROSYM=rodata
                // (stabs.texinfo §"Static Variables"). Section differs; n_value carries the address.
                StabType.N_STSYM, StabType.N_LCSYM, StabType.N_ROSYM -> harvestSymbol(rec)

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
                            store += TypeAst(
                                currentCu!!,
                                decl.id,
                                decl.name,
                                decl.type,
                                declLine = sym.declLine,
                                declSourceFile = sym.sourceFile,
                            )
                            store.hoistSymbolDefs(sym, currentCu!!)
                        }

                        is SymbolDecl.Typedef -> {
                            // Emit bare `name:t(cu,n)` forward-declarations too (body = self-Ref).
                            // appendAsts lets a real definition at the same id supersede the self-ref,
                            // so a concrete body elsewhere (box2d) wins over a bare re-declaration.
                            // (gcc's explicit void `(x,y)=(x,y)` is a distinct TypeDecl.Void, not a self-ref.)
                            store += TypeAst(
                                currentCu!!,
                                decl.id,
                                decl.name,
                                decl.type,
                                declLine = sym.declLine,
                                declSourceFile = sym.sourceFile,
                            )
                            store.hoistSymbolDefs(sym, currentCu!!)
                        }

                        is SymbolDecl.StackLocal, is SymbolDecl.RegLocal -> {
                            currentFunction?.locals?.add(sym)
                        }

                        is SymbolDecl.StaticVar -> {
                            // Function-scope statics get their address from rec.value.
                            symbolsByCu.getOrPut(currentCu!!.filename) { mutableListOf() } += sym
                        }

                        // Addressless compile-time constant — no address, so it's applied as an
                        // equate + synthetic enum catalog rather than data (see SymbolApplier).
                        is SymbolDecl.Constant -> constants += decl

                        is SymbolDecl.Function, is SymbolDecl.Global, is SymbolDecl.RegParam, is SymbolDecl.StackParam,
                        -> warn("unexpected-lsym", "$sym")
                    }
                } catch (e: StabsParseException) {
                    parseErrors++
                    warn("parse-error", "lsym @$i: ${e.message}")
                }

                StabType.N_LBRAC, StabType.N_RBRAC -> currentFunction?.let {
                    it.scopeBrackets += Bracket(rec.type, resolver.stabAddress(rec.value, it.addr), i)
                }

                // Known-irrelevant for type/symbol harvesting.
                StabType.N_DSLINE, StabType.N_BSLINE, StabType.N_FLINE,
                StabType.N_OPT, StabType.N_OLEVEL, StabType.N_PARAMS, StabType.N_VERSION,
                StabType.N_MAIN, StabType.N_PC, StabType.N_M2C, StabType.N_DEFD,
                StabType.N_SSYM, StabType.N_ENDM, StabType.N_OSO, StabType.N_FNAME,
                StabType.N_EHDECL, StabType.N_CATCH, StabType.N_LENG,
                StabType.N_SCOPE, StabType.N_BCOMM, StabType.N_ECOMM, StabType.N_ECOML,
                StabType.N_ENTRY, StabType.N_MAC_DEFINE, StabType.N_MAC_UNDEF,
                // Apple/Sun cross-toolchain codes; benign on x86 PE/ELF.
                StabType.N_BNSYM, StabType.N_ENSYM, StabType.N_OBJ,
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

        openFunctions.forEach { it.resolveBlocks() }

        val (typeAsts, rawCollisions) = store.toHarvest()
        debug("harvest-constants", count = constants.size.toLong())

        return Harvest(
            typeAsts,
            parseErrors,
            rawCollisions,
            symbolsByCu,
            openFunctions,
            lineEntries = lineEntriesByFile.mapValues { (_, v) ->
                v.sortedWith(compareBy({ it.line }, { it.addr.offset }))
            },
            constants,
        )
    }

    private fun harvestSymbol(rec: StabRecord) {
        try {
            symbolsByCu.getOrPut(currentCu!!.filename) { mutableListOf() } += parseSymbol(rec)
        } catch (e: StabsParseException) {
            parseErrors++
            warn("parse-error", "@${rec.index} '${rec.name.take(80)}': ${e.message}")
        }
    }

    fun parseSymbol(rec: StabRecord) = SymbolRecord(
        rec,
        Parser(rec.name, this).parseSymbol().globalize(this),
        lineSource,
        currentFunction?.name,
    ).also {
        store.hoistSymbolDefs(it, currentCu!!)
    }
}
