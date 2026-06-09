@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.parser

import ghidra.program.model.address.Address
import ghidra.program.model.symbol.SymbolUtilities
import ghidra.util.task.TaskMonitor
import ghistabs.builder.TypeResolver
import ghistabs.diag.DiagnosticSink
import ghistabs.importer.AddressResolver
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class TypeAst(
    val cu: SourceFile.CUSource,
    val id: GlobalTypeId,
    val name: String,
    val body: TypeDecl<GlobalTypeId>,
) {
    val source get() = id.source
    val ghidraName get() = SymbolUtilities.replaceInvalidChars(name, false)
}

@Serializable
data class ParamRecord(val decl: SymbolDecl<GlobalTypeId>, val rawValue: Long)

/**
 * Represents a local variable record from the stabs stream.
 *
 * @property decl The parsed symbol declaration.
 * @property rawValue The raw value from the stab record (stack offset for stack locals).
 * @property recordIndex The index of this record in the stabs stream (for scope filtering).
 */
@Serializable
data class LocalRecord(val decl: SymbolDecl<GlobalTypeId>, val rawValue: Long, val recordIndex: Int)

@Serializable
data class HarvestedSymbol(val decl: SymbolDecl<GlobalTypeId>, val recordType: StabType, val rawValue: Long)

@Serializable
data class SerializableAddress(val space: String, val offset: Long) {
    constructor(addr: Address) : this(addr.addressSpace.name, addr.offset) {
        address = addr
    }

    @Transient
    lateinit var address: Address
}

@Serializable
data class OpenFunction(
    val name: String,
    val addr: SerializableAddress,
    val decl: SymbolDecl.Function<GlobalTypeId>,
    val cu: SourceFile.CUSource,
    val locals: MutableList<LocalRecord>,
    val params: MutableList<ParamRecord>,
    val scopeBrackets: MutableList<Triple<StabType, Long, Int>>,
    var sizeBytes: Long = 0L,
)

@Serializable
data class Harvest(
    val parseErrors: Int,
    val typeAsts: Map<GlobalTypeId, TypeAst>,
    val collidingAsts: Map<GlobalTypeId, MutableMap<String, MutableSet<TypeDecl<GlobalTypeId>>>>,
    val symbolsByCu: Map<String, List<HarvestedSymbol>>,
    val openFunctions: List<OpenFunction>,
    val headerRegistry: HeaderRegistry,
) {
    val allHarvestedSymbols get() = symbolsByCu.values.flatten()
    val typeResolver get() = TypeResolver(typeAsts)
}

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
 * therefore receive the same [HeaderFile] instance, making their [GlobalTypeId]s
 * identical for header-attributed types (see stabs-canonicalization.md §3).
 */
class Harvester(
    private val monitor: TaskMonitor,
    private val sink: DiagnosticSink,
    private val resolver: AddressResolver,
) : DiagnosticSink by sink {
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
    fun globalIdFor(id: LocalTypeId) = GlobalTypeId(currentInclude?.sourceFor(id) ?: currentCu!!, id.n)

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
                        log("file-start", "${rec.name} starts here", address = resolver.buildAddress(rec.value))
                    }
                }

                StabType.N_SO -> {
                    if (rec.value != 0L) {
                        log(
                            "file-start",
                            "${currentCu?.filename} ends here",
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
                            listOf(TypeAst(currentCu!!, decl.id, decl.name, decl.type)),
                        )

                        is SymbolDecl.Typedef -> appendAsts(
                            listOf(TypeAst(currentCu!!, decl.id, decl.name, decl.type)),
                        )

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
            parseErrors,
            typeAsts,
            collidingAsts,
            symbolsByCu,
            openFunctions,
            sharedHeaderRegistry,
        )
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

    fun globalizeSymbol(sym: SymbolDecl<LocalTypeId>) = when (sym) {
        is SymbolDecl.Function -> SymbolDecl.Function(sym.name, sym.isFileStatic, globalize(sym.type))
        is SymbolDecl.Global -> SymbolDecl.Global(sym.name, globalize(sym.type))
        is SymbolDecl.RegLocal -> SymbolDecl.RegLocal(sym.name, globalize(sym.type), sym.regNum)
        is SymbolDecl.RegParam -> SymbolDecl.RegLocal(sym.name, globalize(sym.type), sym.regNum)
        is SymbolDecl.StackLocal -> SymbolDecl.StackLocal(sym.name, globalize(sym.type))
        is SymbolDecl.StackParam -> SymbolDecl.StackParam(sym.name, globalize(sym.type))
        is SymbolDecl.StaticVar -> SymbolDecl.StaticVar(sym.name, globalize(sym.type), sym.isFunctionLocal)
        is SymbolDecl.TaggedType -> SymbolDecl.TaggedType(sym.name, globalIdFor(sym.id), globalize(sym.type))
        is SymbolDecl.Typedef -> SymbolDecl.Typedef(sym.name, globalIdFor(sym.id), globalize(sym.type))
    }

    /**
     * Recursively converts a [TypeDecl] (with [LocalTypeId] nodes) to [TypeDecl] (with [GlobalTypeId] nodes)
     * by replacing local type references with global ones.
     *
     * Identity on terminal nodes: leaf types like [TypeDecl.Builtin] and [TypeDecl.Void] pass
     * through unchanged via `@Suppress("UNCHECKED_CAST")`.
     *
     * Recursion contract: every [TypeDecl] variant is handled; none falls through unprocessed.
     * For recursive types, child nodes are recursively globalized.
     *
     * InlineDef side effect: when an [TypeDecl.InlineDef] is encountered, its body is
     * globalized AND a [TypeAst] is emitted as a side effect (the side effect itself
     * happens in sibling methods [walkDefinitions] and [appendAsts], not within [globalize]).
     * This ensures inline-type definitions are hoisted into the top-level [typeAsts] collection.
     */
    @Suppress("UNCHECKED_CAST")
    fun globalize(decl: TypeDecl<LocalTypeId>): TypeDecl<GlobalTypeId> = when (decl) {
        is TypeDecl.Complex, is TypeDecl.Enum, is TypeDecl.XRef -> decl as TypeDecl<GlobalTypeId>
        is TypeDecl.Range -> TypeDecl.Range(globalIdFor(decl.of), decl.min, decl.max)
        is TypeDecl.Ref -> TypeDecl.Ref(globalIdFor(decl.id))
        is TypeDecl.Const -> TypeDecl.Const(globalize(decl.inner))
        is TypeDecl.Volatile -> TypeDecl.Volatile(globalize(decl.inner))
        is TypeDecl.WithSizeAttr -> TypeDecl.WithSizeAttr(decl.sizeBits, globalize(decl.inner))
        is TypeDecl.Pointer -> TypeDecl.Pointer(globalize(decl.pointee))
        is TypeDecl.Reference -> TypeDecl.Reference(globalize(decl.referent))
        is TypeDecl.Array -> TypeDecl.Array(globalize(decl.element), decl.length, decl.indexType?.let { globalize(it) })
        is TypeDecl.FunctionT -> TypeDecl.FunctionT(globalize(decl.ret), decl.params.map { globalize(it) })

        is TypeDecl.Method -> TypeDecl.Method(
            globalize(decl.cls),
            globalize(decl.ret),
            decl.params.map { globalize(it) },
        )

        is TypeDecl.Struct -> TypeDecl.Struct(
            decl.kind,
            decl.sizeBytes,
            decl.bases.map { BaseDecl(globalize(it.type), it.isVirtual, it.access, it.offsetBits) },
            decl.fields.map { FieldDecl(it.name, globalize(it.type), it.offsetBits, it.sizeBits, it.isStatic) },
            decl.methods.map {
                MethodDecl(
                    it.name,
                    it.mangled,
                    globalize(it.signature),
                    it.access,
                    it.virt,
                    it.isConst,
                    it.isVolatile,
                    it.vtableOffsetBits,
                )
            },
            decl.hasVTablePointerMarker,
            decl.vtableTargetTypeId?.let { globalIdFor(it) },
        )

        is TypeDecl.InlineDef -> TypeDecl.InlineDef(globalIdFor(decl.id), globalize(decl.body))
    }

    fun walkDefinitions(decl: TypeDecl<GlobalTypeId>): List<TypeAst> = when (decl) {
        is TypeDecl.Complex, is TypeDecl.Enum, is TypeDecl.Range, is TypeDecl.Ref, is TypeDecl.XRef -> listOf()
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

        is TypeDecl.InlineDef -> listOf(TypeAst(currentCu!!, decl.id, "${decl.id}", decl.body))
    }

    /**
     * Accumulates [TypeAst]s into [typeAsts], handling three collision cases:
     *
     * 1. **XRef replacement:** If a [TypeDecl.XRef] body already exists in [typeAsts] for a
     *    [GlobalTypeId], a concrete definition (Struct, Enum, etc.) replaces it. The first
     *    non-XRef definition wins.
     *
     * 2. **Same-hash suppression:** If an identical body (same content hash) already exists,
     *    the duplicate is logged as `ast-id-collision-same-hash` and silently discarded.
     *
     * 3. **Hash-differing first-writer-wins:** If a body with a different hash exists for the
     *    same [GlobalTypeId], the new body is discarded (first-writer-wins), and the collision
     *    is logged and recorded in [collidingAsts] for audit purposes. This happens when forward
     *    EXCL creates a placeholder HeaderFile that diverges from the real BINCL HeaderFile
     *    (see stabs-canonicalization.md §6 deviation D1).
     */
    fun appendAsts(asts: List<TypeAst>) {
        val new = asts.groupBy { it.id }
        // replace XRef by its definition
        val collisions = typeAsts.filter { it.value.body !is TypeDecl.XRef }.map { it.key }.intersect(new.keys)
        if (collisions.isNotEmpty()) {
            for (id in collisions) {
                val ex = typeAsts[id]!!
                val exHash = mapOf(ex.name to ex.body.hashCode())
                val newHash = new[id]!!.associate { it.name to it.body.hashCode() }
                if (exHash == newHash) {
                    log("ast-id-collision-same-hash")
                } else {
                    log("ast-id-collision", "$exHash != $newHash")
                    collidingAsts.getOrPut(id, { mutableMapOf() }).getOrPut(ex.name, { mutableSetOf() }).add(ex.body)
                    for (ex in new[id]!!) {
                        collidingAsts.getOrPut(id, { mutableMapOf() }).getOrPut(ex.name, { mutableSetOf() })
                            .add(ex.body)
                    }
                }
            }
        }
        for (ast in asts.filter { !collisions.contains(it.id) }) {
            typeAsts[ast.id] = ast
        }
    }

    fun parseSymbol(rec: StabRecord) = globalizeSymbol(Parser(rec.name).parseSymbol()).also {
        appendAsts(walkDefinitions(it.type))
    }
}
