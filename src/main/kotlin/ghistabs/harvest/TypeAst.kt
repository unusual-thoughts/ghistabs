@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.harvest

import ghidra.app.util.demangler.DemanglerUtil
import ghidra.program.model.address.Address
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SymbolUtilities
import ghistabs.parse.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlin.io.path.Path
import kotlin.io.path.nameWithoutExtension

@Serializable
data class TypeAst(
    val cu: SourceFile.CUSource,
    val id: GlobalTypeId,
    val name: String?,
    val body: TypeDecl<GlobalTypeId>,
    /** Source line from N_LSYM `desc`. gcc 3.x sets it; gcc 12 leaves 0. */
    val declLine: Int = 0,
    /** N_SOL-effective filename at definition time (header for stdlib, CU for app-local). */
    val declSourceFile: String? = null,
) {
    val source get() = id.source
    private val uniqueName
        get() = "Anon_${Path(id.source.filename).nameWithoutExtension}_${id.n}_${id.hashCode().toHexString()}"

    /** Anonymous TypeAst: prefer the XRef tagName (so all CUs forward-declaring the
     * same tag — e.g. `__si_class_type_info_pseudo` — collapse to the same name and
     *  byHash dedup actually fires). Otherwise, fall back to the synthetic.
     */
    val nameOrUnique get() = name?.ifEmpty { null } ?: (body as? TypeDecl.XRef)?.tagName?.ifEmpty { null } ?: uniqueName

    val ghidraName: String = SymbolUtilities.replaceInvalidChars(nameOrUnique, false).ifEmpty { uniqueName }

    inline fun <reified T : TypeDecl<GlobalTypeId>> asType() = if (body is T) {
        this to body
    } else {
        null
    }

    fun asStruct() = asType<TypeDecl.Struct<GlobalTypeId>>()
}

/**
 * One symbol stab. `recordIndex` is the stream position (for scope filtering); `declLine` comes
 * from the stab's `desc` field (0 when emitter omits it); `sourceFile` is the N_SOL-effective name.
 */
@Serializable
data class SymbolRecord(
    val recordIndex: Int,
    val recordType: StabType,
    val body: SymbolDecl<GlobalTypeId>,
    val rawValue: Long,
    val declLine: Int = 0,
    val sourceFile: String? = null,
) {
    constructor(
        record: StabRecord,
        decl: SymbolDecl<GlobalTypeId>,
        sourceFile: String? = null,
    ) : this(record.recordIndex, record.type, decl, record.value, record.desc, sourceFile)
}

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
    val locals: MutableList<SymbolRecord> = mutableListOf(),
    val params: MutableList<SymbolRecord> = mutableListOf(),
    val scopeBrackets: MutableList<Triple<StabType, Long, Int>> = mutableListOf(),
    // N_SLINEs emitted between this function's N_FUN and the next, in stab-stream order.
    // This is the authoritative membership: it includes exception-handler / landing-pad
    // lines that gcc attributes to the function but Ghidra's CFG-based body omits (nothing
    // flows to them), and it needs no address/size arithmetic — the entry point isn't even
    // guaranteed to be the function's lowest address.
    val lineEntries: MutableList<LineEntry> = mutableListOf(),
    // null = size not derivable from stabs (no N_LBRAC/N_RBRAC scope, no end-marker N_FUN).
    // Distinct from a genuine 0. Used by TypeResolver for header-hint address ranges.
    var sizeBytes: ULong? = null,
) {
    fun demangledName(program: Program? = null) =
        runCatching { DemanglerUtil.demangle(program, decl.name, addr.address) }.getOrNull()
            ?.firstNotNullOfOrNull { it.demangledName } ?: decl.name
//        val mangled = decl.name
//        val demangled = runCatching {
//            @Suppress("DEPRECATION")
//            DemanglerUtil.demangle(mangled)
//        }.getOrNull() ?: return mangled
//        return demangled.demangledName ?: demangled.name ?: mangled
}

/** N_SLINE record: line → text address, tagged with its active N_SOL source. Held both in
 *  [Harvest.lineEntries] (grouped by source) and on the owning [OpenFunction.lineEntries]. */
@Serializable
data class LineEntry(val line: Int, val addr: SerializableAddress, val source: String)

@Serializable(with = ToStringSerializer::class)
data class GhidraKey(val category: CategoryPath, val name: String) {
    constructor(path: String, name: String) : this(CategoryPath(path), name)

    override fun toString() = "$category/$name"
}

/** TypeAsts collapsed onto one DTM slot. `ast` materialises; `members` is for diagnostics. */
@Serializable
data class CanonicalGroup(val key: GhidraKey, val ast: TypeAst, val members: List<GlobalTypeId>, val distinct: Int)
