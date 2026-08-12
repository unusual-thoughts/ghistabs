@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.harvest

import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressRange
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.listing.Program
import ghidra.program.model.sourcemap.SourceMapEntry
import ghidra.program.model.symbol.SymbolUtilities
import ghistabs.baseStackParamOffset
import ghistabs.demangledName
import ghistabs.parse.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind.STRING
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.io.path.Path
import kotlin.io.path.nameWithoutExtension

@Serializable
data class Type(
    val cu: SourceFile.CUSource,
    val id: GlobalTypeId,
    val name: String?,
    val body: TypeDecl<GlobalTypeId>,
    /** Source line from N_LSYM `desc`. gcc 3.x sets it; gcc 12 leaves 0. */
    val declLine: Int = 0,
    /** N_SOL-effective source at definition time (header for stdlib, CU for app-local). */
    @Serializable(with = SourceFileSerializer::class) val declSourceFile: GhidraSourceFile? = null,
) {
    val source get() = id.source

    @OptIn(ExperimentalStdlibApi::class)
    private val uniqueName
        get() = "Anon_${Path(id.source.filename).nameWithoutExtension}_${id.n}_${id.hashCode().toHexString()}"

    /** Anonymous TypeAst: prefer the XRef tagName (so all CUs forward-declaring the
     * same tag — e.g. `__si_class_type_info_pseudo` — collapse to the same name and
     *  byHash dedup actually fires). Otherwise, fall back to the synthetic.
     */
    val nameOrUnique = name?.ifEmpty { null } ?: (body as? TypeDecl.XRef)?.tagName?.ifEmpty { null } ?: uniqueName

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
data class Symbol(
    val recordIndex: Int,
    val recordType: StabType,
    val body: SymbolDecl<GlobalTypeId>,
    val rawValue: Long,
    val declLine: Int = 0,
    /** N_SOL in effect when the record was read — except for function-scope symbols, where the N_SOL
     *  is meaningless, so [BlockTreeBuilder.finish] rebuilds them with the block's real source. */
    @Serializable(with = SourceFileSerializer::class) val sourceFile: GhidraSourceFile? = null,
    /** Enclosing function (mangled/linkage name) when harvested inside a function scope — set for
     *  procedure-scope (`V`) statics so the applier can annotate which function owns them. */
    val enclosingFunction: String? = null,
) {
    constructor(
        record: StabRecord,
        decl: SymbolDecl<GlobalTypeId>,
        sourceFile: GhidraSourceFile? = null,
        enclosingFunction: String? = null,
    ) : this(record.index, record.type, decl, record.value, record.desc, sourceFile, enclosingFunction)

    val location get() = when (body) {
        is SymbolDecl.Local -> body.location
        is SymbolDecl.Param -> body.location
        else -> null
    }

    fun storage(program: Program) = location?.let {
        dbxStorageName(
            program.defaultPointerSize,
            rawValue.toInt(),
            it == VariableLocation.REGISTER,
            program.baseStackParamOffset,
        )
    }

    /**
     * Where gcc put this local, as an address the decompiler indexes storage by: the register itself, or
     * the frame slot at Ghidra's origin rather than gcc's frame-pointer-relative one. Null for anything
     * that is neither — and for the dbx register numbers [dbxRegisterName] declines to map (the x87
     * stack), which is the same set the importer skips.
     */
    fun storageAddress(program: Program) = when (location) {
        VariableLocation.REGISTER -> dbxRegisterName(program.defaultPointerSize, rawValue.toInt())
            ?.let { program.getRegister(it)?.address }

        VariableLocation.STACK ->
            program.addressFactory.stackSpace.getAddress(rawValue - program.baseStackParamOffset)

        null -> null
    }

    companion object {
        fun parse(
            rec: StabRecord,
            globalizer: Globalizer,
            sourceFile: GhidraSourceFile? = null,
            enclosingFunction: String? = null,
        ) = Parser(rec.name).parseSymbol().map {
            Symbol(
                rec,
                it.globalize(globalizer),
                sourceFile,
                enclosingFunction,
            )
        }
    }
}

/** A source identity in a dump is its normalised path — the whole of what it is, minus an id type
 *  stabs never gives us. */
class SourceFileSerializer : KSerializer<GhidraSourceFile> {
    override val descriptor = PrimitiveSerialDescriptor("ghidra.program.database.sourcemap.SourceFile", STRING)
    override fun serialize(encoder: Encoder, value: GhidraSourceFile) = encoder.encodeString(value.path)
    override fun deserialize(decoder: Decoder) =
        throw UnsupportedOperationException("SourceFileSerializer is serialize-only")
}

class AddressSerializer : KSerializer<Address> {
    @Serializable
    private data class AddressSurrogate(val space: String, val offset: Long) {
        constructor(addr: Address) : this(addr.addressSpace.name, addr.offset)
    }
    override val descriptor =
        SerialDescriptor("ghidra.program.model.address.Address", AddressSurrogate.serializer().descriptor)
    override fun serialize(encoder: Encoder, value: Address) =
        encoder.encodeSerializableValue(AddressSurrogate.serializer(), AddressSurrogate(value))

    override fun deserialize(decoder: Decoder) =
        throw UnsupportedOperationException("AddressSerializer is serialize-only")
}

@Serializable
data class Func(
    val name: String,
    @Serializable(with = AddressSerializer::class)
    val addr: Address,
    val decl: SymbolDecl.Function<GlobalTypeId>,
    val cu: SourceFile.CUSource,
    // Both assigned once, by BlockTreeBuilder.finish, when the function's last record has been seen:
    // a function-scope symbol's source isn't knowable until then, so there is no window in which
    // these hold records that are about to be corrected.
    val locals: List<Symbol> = emptyList(),
    val params: List<Symbol> = emptyList(),
    val blocks: List<BlockScope> = emptyList(),
    // N_SLINEs emitted between this function's N_FUN and the next, in stab-stream order.
    // This is the authoritative membership: it includes exception-handler / landing-pad
    // lines that gcc attributes to the function but Ghidra's CFG-based body omits (nothing
    // flows to them), and it needs no address/size arithmetic — the entry point isn't even
    // guaranteed to be the function's lowest address.
    val lineEntries: List<LineEntry> = emptyList(),
    // null = size not derivable from stabs (no N_LBRAC/N_RBRAC scope, no end-marker N_FUN).
    // Distinct from a genuine 0. Used by TypeResolver for header-hint address ranges.
    val sizeBytes: ULong? = null,
) {
    val demangledName by lazy { demangledName(decl.name) }

    /**
     * Function signature via Ghidra's API at the function's entry address — Ghidra has
     * already resolved calling convention, parameter names and types from analysis +
     * imported stabs types, so the rendered signature reflects what the binary actually
     * does (not the demangler's textual guess).
     */
    fun signature(program: Program) = program.functionManager.getFunctionAt(addr)?.signature?.prototypeString ?: name

    /**
     * [signature] with the `static` gcc emitted as `:f` (internal linkage) restored. Ghidra models
     * no linkage, so its prototypeString can't carry it and a file-static renders like any other
     * free function — the stab is the only place that distinction survives.
     */
    fun sourceSignature(program: Program) = signature(program).let {
        when (decl.scope) {
            FunctionScope.FILE -> "static $it"
            FunctionScope.GLOBAL -> it
        }
    }

    /**
     * Pull the outermost class / namespace name out of an Itanium-ABI
     * mangled symbol — e.g. `_ZN13EquExpressionC1ERKS_` → `EquExpression`,
     * `_ZN7CParser11ParseSymbolEv` → `CParser`. Used to look up the
     * class's `declSourceFile` and pin the function there when N_SLINE
     * would otherwise drag a defaulted/implicit method into whichever
     * header materialized it (e.g. gcc's implicit `EquExpression` copy
     * ctor materialized inside `std::pair<…, EquExpression>` lands at
     * `stl_pair.h:84`; the class itself lives elsewhere).
     *
     * Returns null for non-nested-name mangles (`_Z…` without `N`) and
     * for symbols whose first segment is a substitution-prefix like
     * `St` (std) — we WANT those to keep their N_SLINE attribution.
     */
    fun outermostClass(): String? = outermostClassOf(name)

    /**
     * gcc emits file-scope synthetic init/destruct wrappers
     * (`_GLOBAL__I_<sym>`, `_GLOBAL__D_<sym>`,
     * `__static_initialization_and_destruction_0`) at the CU's
     * end-of-file but under whatever N_SOL was last active — typically
     * the last `#include`d header. They belong to the CU that owns the
     * static they initialize, not to that header.
     */
    val isSyntheticInit get() = name.startsWith("_GLOBAL__I_") ||
        name.startsWith("_GLOBAL__D_") ||
        name.startsWith("_GLOBAL__N_") ||
        name.startsWith("_Z41__static_initialization_and_destruction_0") ||
        name == "__static_initialization_and_destruction_0"
}

/**
 * N_SLINE record: line → text address, tagged with its active N_SOL source. Held both in
 * [Harvest.lineEntries] (grouped by source) and on the owning [Func.lineEntries].
 *
 * A [SourceMapEntry] of length 0, which is what an N_SLINE is — a point, not a range. So one type
 * flows parse → render → program, and the program's own DB-backed entries are an alternative
 * *producer* of it rather than a second model. Zero length means [getRange] is null, per the
 * interface's own contract, and means an entry never conflicts with any other.
 *
 * [compareTo] is Ghidra's order — (file, line, address, length), not address-first — so anything
 * wanting address order sorts by [addr] explicitly.
 */
@Serializable
data class LineEntry(
    val line: Int,
    @Serializable(with = AddressSerializer::class) val addr: Address,
    @Serializable(with = SourceFileSerializer::class) val source: GhidraSourceFile,
) : SourceMapEntry {
    override fun getLineNumber() = line

    override fun getSourceFile() = source

    override fun getBaseAddress() = addr

    override fun getLength() = 0L

    override fun getRange(): AddressRange? = null

    override fun compareTo(other: SourceMapEntry) = COMPARATOR.compare(this, other)

    private companion object {
        // Lengths are non-negative by the interface's contract, so an unsigned compare adds nothing.
        val COMPARATOR =
            compareBy<SourceMapEntry>({ it.sourceFile }, { it.lineNumber }, { it.baseAddress }, { it.length })
    }
}

@Serializable(with = ToStringSerializer::class)
data class TypeLocation(val category: CategoryPath, val name: String) {
    constructor(path: String, name: String) : this(CategoryPath(path), name)

    override fun toString() = "$category/$name"
}

/**
 *  Types with the same [location] collapsed onto one DTM slot.
 *  [type] is the one chosen to materialize
 *  [members] and [distinct] are for diagnostics.
 *  [members] contains all the harvested [Type]s that located there, and
 *  [distinct] is the count of truly different types among them according to [ContentIndex]
 */
@Serializable
data class LocatedType(val location: TypeLocation, val type: Type, val members: List<GlobalTypeId>, val distinct: Int)
