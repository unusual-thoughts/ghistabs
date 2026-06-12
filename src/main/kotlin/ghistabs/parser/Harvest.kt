@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.parser

import ghidra.program.model.address.Address
import ghidra.program.model.symbol.SymbolUtilities
import ghidra.util.task.TaskMonitor
import ghistabs.diag.DiagnosticSink
import ghistabs.diag.DummySink
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
    val ghidraName: String
        get() = SymbolUtilities.replaceInvalidChars(name, false).ifEmpty {
            // XRef-bodied TypeAsts emitted by gcc for ABI-internal helpers
            // (e.g. `InlineDef(id, XRef(STRUCT, "__si_class_type_info_pseudo"))`)
            // have no name field. Without this clause every per-CU XRef
            // would get an auto-generated `XRef_[…]` name keyed on the
            // anonymous id — three CUs that all forward-declare the same
            // tag would then materialise as three separate empty
            // Structures, each applied at the SAME typeinfo address,
            // racing each other on every write. Fold to the tagName so
            // the byHash/registerWithConflict dedup actually fires.
            (body as? TypeDecl.XRef)?.tagName?.let { SymbolUtilities.replaceInvalidChars(it, false) }
                ?: "${body::class.java.simpleName}_$id"
        }
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
    val typeAsts: Map<GlobalTypeId, TypeAst>,
    val parseErrors: Int = 0,
    var collidingAsts: Map<GlobalTypeId, Map<String, Set<TypeDecl<GlobalTypeId>>>> = mapOf(),
    val symbolsByCu: Map<String, List<HarvestedSymbol>> = mapOf(),
    val openFunctions: List<OpenFunction> = listOf(),
    @Transient val sink: DiagnosticSink = DummySink,
) : DiagnosticSink by sink {
    val hashCache: MutableMap<GlobalTypeId, Int> = mutableMapOf()

    val allHarvestedSymbols by lazy { symbolsByCu.values.flatten() }

    /** Group ASTs once by Ghidra-sanitised name (only space is invalid; cf. SymbolUtilities.INVALIDCHARS). */
    val astsByGhidraName by lazy { typeAsts.values.groupBy { it.ghidraName } }

    /** All struct ASTs harvested in Pass A, indexed by name, for XRef purposes. */
    private val structAstsByName by lazy {
        typeAsts.values.mapNotNull { ast -> (ast.body as? TypeDecl.Struct)?.let { ast.name to (ast.id to it) } }.toMap()
    }

    fun getType(id: GlobalTypeId) = typeAsts[id]
    fun getStruct(id: GlobalTypeId) = typeAsts[id]?.body as? TypeDecl.Struct

    // XRef → canonical struct: look up by name + matching kind so
    // `XRef(STRUCT, "Foo")` in one CU hashes equally to `Ref(id)`
    // pointing at the same `struct Foo` defined in another CU.
    fun getByXRef(xref: TypeDecl.XRef<GlobalTypeId>) = structAstsByName[xref.tagName]
        ?.takeIf { (_, struct) -> struct.kind == xref.kind }
        ?.let { (id, _) -> typeAsts[id] }
        .also {
            if (it == null) {
                log("unresolved-xref", "${xref.tagName} [${xref.kind}]")
            }
        }

    fun definingCUs(ast: TypeAst) = astsByGhidraName[ast.ghidraName]?.map { it.id.source }?.toSet() ?: setOf(ast.cu)

    /**
     * Content-equivalence hash for a [TypeDecl] tree, using `typeAsts`
     * (plus the name-keyed XRef index) as the oracle. See the top-level
     * [contentHash] for semantics.
     */
    fun contentHash(body: TypeDecl<GlobalTypeId>): Int = body.contentHash(oracle, hashCache)

    /** Oracle exposing both id-based and name-based (XRef) lookups. */
    val oracle: TypeAstOracle by lazy { TypeAstOracle(byId = typeAsts::get, byXRef = ::getByXRef) }

    /**
     * Classify [collidingAsts] entries by whether their alternate bodies
     * are content-equivalent. Pre-warms [cache] by hashing every typeAst
     * body top-level first so cache state doesn't bias the result.
     *
     * Cache-pollution failure mode this avoids: with a cold cache the
     * first variant computed seeds cache entries for transitively-
     * referenced ids using a visited set that already contains the
     * colliding id, so inner self-Refs back-edge instead of recursing.
     * Subsequent variants then cache-hit those stale values, and
     * structurally-identical Ref-vs-InlineDef forms diverge purely on
     * cache state. Pre-warming with empty visited sets fixes this.
     */
    fun classifyCollisions() {
        // Classify collisions and drop the spurious (content-equivalent)
        // buckets before the Harvest is published. Downstream consumers
        // only ever see genuinely-divergent collisions; the warmed cache
        // is handed off to the Harvest so TypeRegistry doesn't redo the
        // hash work, and the stats ride along on `harvest.classification`.

        for (ast in typeAsts.values) {
            hashCache[ast.id] = contentHash(ast.body)
        }
        collidingAsts = collidingAsts.filterValues { byName ->
            byName.values.flatten().map { contentHash(it) }.toSet().size > 1
        }.mapValues { (_, byName) ->
            byName.mapValues { (_, types) ->
                types.groupBy { contentHash(it) }.map { it.value.first() }.toSet()
            }
        }.toMap()
    }
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

                        is SymbolDecl.Typedef -> {
                            // `name:t(cu,n)` with no `=body` parses as
                            // `Typedef(name, id, Ref(id))` — a self-Ref. The
                            // typedef adds a name but no new type definition,
                            // so emitting it as a TypeAst would create a
                            // body-less alias that collides with the real
                            // definition at the same id in another CU
                            // (every box2d typedef went this way).
                            if (decl.type !is TypeDecl.Ref || decl.type.id != decl.id) {
                                appendAsts(listOf(TypeAst(currentCu!!, decl.id, decl.name, decl.type)))
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
        ).apply { classifyCollisions() }
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
        is TypeDecl.Complex, is TypeDecl.Enum, is TypeDecl.XRef, is TypeDecl.Builtin ->
            decl as TypeDecl<GlobalTypeId>

        is TypeDecl.Range -> TypeDecl.Range(globalIdFor(decl.of), decl.min, decl.max)

        // Refs with negative ids never reach this point — the parser
        // (see [Parser.parseType]) emits [TypeDecl.Builtin] for those.
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
    fun appendAsts(asts: List<TypeAst>) {
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

    fun parseSymbol(rec: StabRecord) = globalizeSymbol(Parser(rec.name).parseSymbol()).also {
        appendAsts(walkDefinitions(it.type))
    }

//    /**
//     * Classify [collidingAsts] entries by whether their alternate bodies
//     * are content-equivalent. Pre-warms [cache] by hashing every typeAst
//     * body top-level first so cache state doesn't bias the result.
//     *
//     * Cache-pollution failure mode this avoids: with a cold cache the
//     * first variant computed seeds cache entries for transitively-
//     * referenced ids using a visited set that already contains the
//     * colliding id, so inner self-Refs back-edge instead of recursing.
//     * Subsequent variants then cache-hit those stale values, and
//     * structurally-identical Ref-vs-InlineDef forms diverge purely on
//     * cache state. Pre-warming with empty visited sets fixes this.
//     */
//    private fun classifyCollisions(): MutableMap<GlobalTypeId, Int> {
//        // Classify collisions and drop the spurious (content-equivalent)
//        // buckets before the Harvest is published. Downstream consumers
//        // only ever see genuinely-divergent collisions; the warmed cache
//        // is handed off to the Harvest so TypeRegistry doesn't redo the
//        // hash work, and the stats ride along on `harvest.classification`.
//        val cache = mutableMapOf<GlobalTypeId, Int>()
//        // Build a name-keyed struct index for XRef resolution: a CU that
//        // only saw `struct Foo;` (an XRef) must hash any wrapping type the
//        // same way as a CU with the full definition.
//        val structByName: Map<String, TypeAst> = typeAsts.values.mapNotNull { ast ->
//            (ast.body as? TypeDecl.Struct)?.let { ast.name to ast }
//        }.toMap()
//        val oracle = TypeAstOracle(
//            byId = typeAsts::get,
//            byXRef = { xref -> structByName[xref.tagName]?.takeIf { (it.body as TypeDecl.Struct).kind == xref.kind } },
//        )
//        for (ast in typeAsts.values) {
//            cache[ast.id] = ast.body.contentHash(oracle, cache = cache)
//        }
//        var totalVariants = 0
//        val spurious = mutableSetOf<GlobalTypeId>()
//        var real = 0
//        for ((id, byName) in collidingAsts) {
//            val variants = byName.values.flatten()
//            totalVariants += variants.size
//            val distinctHashes = variants.map { it.contentHash(oracle, cache = cache) }.toSet().size
//            if (distinctHashes <= 1) {
//                spurious += id
//            } else {
//                real++
//            }
//        }
//        for (id in spurious) {
//            collidingAsts.remove(id)
//        }
//        return cache
//    }
}
