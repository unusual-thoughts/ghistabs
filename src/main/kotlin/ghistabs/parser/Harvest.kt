@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.parser

import ghidra.program.model.address.Address
import ghidra.program.model.symbol.SymbolUtilities
import ghidra.util.task.TaskMonitor
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
    val typeAsts: Map<GlobalTypeId, TypeAst>,
    val parseErrors: Int = 0,
    val collidingAsts: Map<GlobalTypeId, Map<String, Set<TypeDecl<GlobalTypeId>>>> = mapOf(),
    val symbolsByCu: Map<String, List<HarvestedSymbol>> = mapOf(),
    val openFunctions: List<OpenFunction> = listOf(),
    val hashCache: MutableMap<GlobalTypeId, Int> = mutableMapOf(),
) {

    val allHarvestedSymbols by lazy { symbolsByCu.values.flatten() }

    /** Group ASTs once by Ghidra-sanitised name (only space is invalid; cf. SymbolUtilities.INVALIDCHARS). */
    val astsByGhidraName by lazy { typeAsts.values.groupBy { it.ghidraName } }

    /** All struct ASTs harvested in Pass A, indexed by name, for XRef purposes. */
    private val structAstsByName by lazy {
        typeAsts.values.mapNotNull { ast -> (ast.body as? TypeDecl.Struct)?.let { ast.name to (ast.id to it) } }.toMap()
    }

    fun getType(id: GlobalTypeId) = typeAsts[id]
    fun getStruct(id: GlobalTypeId) = typeAsts[id]?.body as? TypeDecl.Struct
    fun getStructByXRef(name: String) = structAstsByName[name]
    fun definingCUs(ast: TypeAst) = astsByGhidraName[ast.ghidraName]?.map { it.id.source }?.toSet() ?: setOf(ast.cu)

    /**
     * Content-equivalence hash for a [TypeDecl] tree, using `typeAsts`
     * as the oracle. See the top-level [contentHash] for semantics.
     */
    fun contentHash(body: TypeDecl<GlobalTypeId>): Int = contentHash(body, typeAsts::get, cache = hashCache)
}

/**
 * Content-equivalence hash for a [TypeDecl] tree. Differs from the
 * default `data class` `hashCode()` in two places:
 *
 *   1. Anywhere a [TypeDecl] holds an id (`Ref`, `Range.of`,
 *      `Struct.vtableTargetTypeId`, `InlineDef.id`), the id is resolved
 *      via [oracle] and the hash recurses into the referenced body —
 *      so a forward `Ref(id)` and an inline `InlineDef(id, body)` for
 *      the same content collapse to the same hash. gcc emits either
 *      form depending on per-CU history.
 *
 *   2. The `"Ref"` and `"InlineDef"` wrapper tags are intentionally
 *      omitted — both reduce to their wrapped content's hash. Per-CU
 *      template-instantiation clones end up content-equivalent because
 *      their fields' refs converge on the same primitive types
 *      regardless of which CU canonically owns the clone.
 *
 * Cycles (self-referential `Range.of`, recursive struct fields, vtable
 * pointing back at the enclosing class) are broken by [visited]: once
 * a [GlobalTypeId] is in flight, hitting it again yields a fixed
 * `"back-edge"` marker hash instead of recursing.
 *
 * [oracle] is parameterised so `Harvester.appendAsts` can compose its
 * in-flight batch with the merged store, while a finished [Harvest]
 * can pass `typeAsts::get` directly.
 *
 * Each `when` branch destructures the variant — adding a field to any
 * [TypeDecl] subclass is a compile error here.
 */
fun contentHash(
    body: TypeDecl<GlobalTypeId>,
    oracle: (GlobalTypeId) -> TypeAst?,
    visited: Set<GlobalTypeId> = emptySet(),
    cache: MutableMap<GlobalTypeId, Int>? = null,
): Int = when (body) {
    is TypeDecl.Ref -> {
        // Drop the "Ref" wrapper so `Ref(id)` and the equivalent inline
        // `InlineDef(id, content)` (gcc emits either form depending on
        // each CU's history) reduce to the same content hash.
        val (id) = body
        refKey(id, oracle, visited, cache)
    }

    is TypeDecl.Range -> {
        val (of, min, max) = body
        java.util.Objects.hash("Range", refKey(of, oracle, visited, cache), min, max)
    }

    is TypeDecl.Pointer -> {
        val (pointee) = body
        java.util.Objects.hash("Pointer", contentHash(pointee, oracle, visited, cache))
    }

    is TypeDecl.Reference -> {
        val (referent) = body
        java.util.Objects.hash("Reference", contentHash(referent, oracle, visited, cache))
    }

    is TypeDecl.Const -> {
        val (inner) = body
        java.util.Objects.hash("Const", contentHash(inner, oracle, visited, cache))
    }

    is TypeDecl.Volatile -> {
        val (inner) = body
        java.util.Objects.hash("Volatile", contentHash(inner, oracle, visited, cache))
    }

    is TypeDecl.Array -> {
        val (element, length, indexType) = body
        java.util.Objects.hash(
            "Array",
            contentHash(element, oracle, visited, cache),
            length,
            indexType?.let { contentHash(it, oracle, visited, cache) },
        )
    }

    is TypeDecl.Enum -> body.hashCode()

    // members: List<Pair<String, Long>> — no ids
    is TypeDecl.Struct -> {
        val (kind, sizeBytes, bases, fields, methods, hasVtbl, vtableTargetTypeId) = body
        java.util.Objects.hash(
            "Struct",
            kind,
            sizeBytes,
            bases.map { contentHashBase(it, oracle, visited, cache) },
            fields.map { contentHashField(it, oracle, visited, cache) },
            methods.map { contentHashMethod(it, oracle, visited, cache) },
            hasVtbl,
            vtableTargetTypeId?.let { refKey(it, oracle, visited, cache) },
        )
    }

    is TypeDecl.FunctionT -> {
        val (ret, params) = body
        java.util.Objects.hash(
            "FunctionT",
            contentHash(ret, oracle, visited, cache),
            params.map { contentHash(it, oracle, visited, cache) },
        )
    }

    is TypeDecl.Method -> {
        val (cls, ret, params) = body
        java.util.Objects.hash(
            "Method",
            contentHash(cls, oracle, visited, cache),
            contentHash(ret, oracle, visited, cache),
            params.map { contentHash(it, oracle, visited, cache) },
        )
    }

    is TypeDecl.Complex -> body.hashCode()

    // (rCode, sizeBytes) — primitives only
    is TypeDecl.XRef -> body.hashCode()

    // (kind, tagName) — primitives only
    is TypeDecl.WithSizeAttr -> {
        val (sizeBits, inner) = body
        java.util.Objects.hash("WithSizeAttr", sizeBits, contentHash(inner, oracle, visited, cache))
    }

    is TypeDecl.InlineDef -> {
        // The id is local-binding metadata; identity is the body. Drop
        // the "InlineDef" wrapper so this form is content-equivalent to
        // `Ref(id_at_same_content)` (see the Ref branch). Add the id to
        // `visited` so a back-edge inside the body (a forward Ref
        // pointing at this InlineDef's slot) stops recursing.
        val (id, inner) = body
        contentHash(inner, oracle, visited + id, cache)
    }
}

/**
 * Resolve [id] through [oracle] and recurse into the referenced body so
 * `Ref(id)` and the inline `InlineDef(id, body)` form converge on the
 * same hash (gcc emits both for the same logical content depending on
 * how a type was first introduced in each CU). [visited] guards against
 * self-referential cycles — `Range.of` always points at itself, and
 * struct fields can transitively reach back into the enclosing class.
 */

/**
 * Resolve a Ref-shaped id through [oracle] and recurse into the body,
 * memoizing the result. `Ref(id)` and `InlineDef(id, content)` for the
 * same content converge on the same hash (gcc emits either form
 * depending on per-CU history). [visited] guards against self-referential
 * cycles — `Range.of` always points at itself; struct fields can
 * transitively reach back into the enclosing class.
 *
 * Caching strategy: store every successful (non-back-edge) result keyed
 * by [id]. For tree-shaped types the cached value is exact. For
 * mutually-recursive types the first computation wins and is reused —
 * mild inconsistency with what a from-scratch recomputation would
 * produce, but still deterministic across calls and good enough for
 * collision detection and DTM dedup.
 */
private fun refKey(
    id: GlobalTypeId,
    oracle: (GlobalTypeId) -> TypeAst?,
    visited: Set<GlobalTypeId>,
    cache: MutableMap<GlobalTypeId, Int>?,
): Int {
    if (id in visited) return BACK_EDGE_HASH
    cache?.get(id)?.let { return it }
    val referenced = oracle(id) ?: return java.util.Objects.hash("unresolved", id)
    val h = contentHash(referenced.body, oracle, visited + id, cache)
    cache?.put(id, h)
    return h
}

private val BACK_EDGE_HASH = java.util.Objects.hash("back-edge")

private fun contentHashField(
    f: FieldDecl<GlobalTypeId>,
    oracle: (GlobalTypeId) -> TypeAst?,
    visited: Set<GlobalTypeId>,
    cache: MutableMap<GlobalTypeId, Int>?,
): Int {
    val (name, type, offsetBits, sizeBits, isStatic) = f
    return java.util.Objects.hash(
        "Field",
        name,
        contentHash(type, oracle, visited, cache),
        offsetBits,
        sizeBits,
        isStatic,
    )
}

private fun contentHashBase(
    b: BaseDecl<GlobalTypeId>,
    oracle: (GlobalTypeId) -> TypeAst?,
    visited: Set<GlobalTypeId>,
    cache: MutableMap<GlobalTypeId, Int>?,
): Int {
    val (type, isVirtual, access, offsetBits) = b
    return java.util.Objects.hash("Base", contentHash(type, oracle, visited, cache), isVirtual, access, offsetBits)
}

private fun contentHashMethod(
    m: MethodDecl<GlobalTypeId>,
    oracle: (GlobalTypeId) -> TypeAst?,
    visited: Set<GlobalTypeId>,
    cache: MutableMap<GlobalTypeId, Int>?,
): Int {
    val (name, mangled, signature, access, virt, isConst, isVolatile, vtableOffsetBits) = m
    return java.util.Objects.hash(
        "Method",
        name,
        mangled,
        contentHash(signature, oracle, visited, cache),
        access,
        virt,
        isConst,
        isVolatile,
        vtableOffsetBits,
    )
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

        val cache = classifyCollisions()
        return Harvest(
            typeAsts,
            parseErrors,
            collidingAsts,
            symbolsByCu,
            openFunctions,
            cache,
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
    private fun classifyCollisions(): MutableMap<GlobalTypeId, Int> {
        // Classify collisions and drop the spurious (content-equivalent)
        // buckets before the Harvest is published. Downstream consumers
        // only ever see genuinely-divergent collisions; the warmed cache
        // is handed off to the Harvest so TypeRegistry doesn't redo the
        // hash work, and the stats ride along on `harvest.classification`.
        val cache = mutableMapOf<GlobalTypeId, Int>()
        val oracle: (GlobalTypeId) -> TypeAst? = typeAsts::get
        for (ast in typeAsts.values) {
            cache[ast.id] = contentHash(ast.body, oracle, cache = cache)
        }
        var totalVariants = 0
        val spurious = mutableSetOf<GlobalTypeId>()
        var real = 0
        for ((id, byName) in collidingAsts) {
            val variants = byName.values.flatten()
            totalVariants += variants.size
            val distinctHashes = variants.map { contentHash(it, oracle, cache = cache) }.toSet().size
            if (distinctHashes <= 1) {
                spurious += id
            } else {
                real++
            }
        }
        for (id in spurious) {
            collidingAsts.remove(id)
        }
        return cache
    }
}
