@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.harvest

import ghidra.program.model.address.Address
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.symbol.SymbolUtilities
import ghistabs.parse.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class TypeAst(
    val cu: SourceFile.CUSource,
    val id: GlobalTypeId,
    val name: String?,
    val body: TypeDecl<GlobalTypeId>,
    /**
     * Source-file line where the type was declared. Captured from N_LSYM's
     * `desc` field. gcc 3.x sets it; gcc 12 leaves it 0. The companion
     * `sourceFile` is the N_SOL-effective filename at definition time
     * (typically a header for stdlib types, the CU itself for app-local
     * declarations).
     */
    val declLine: Int = 0,
    val declSourceFile: String? = null,
) {
    val source get() = id.source
    val nameOrId get() = name ?: "$id"
    val ghidraName: String
        get() = SymbolUtilities.replaceInvalidChars(nameOrId, false).ifEmpty {
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

    inline fun <reified T : TypeDecl<GlobalTypeId>> asType() = if (body is T) {
        this to body
    } else {
        null
    }

    fun asStruct() = asType<TypeDecl.Struct<GlobalTypeId>>()
}

/**
 * @property recordIndex Index in the stabs stream (for scope filtering).
 * @property declLine N_GSYM / N_LCSYM / N_STSYM / N_PSYM / N_LSYM / N_RSYM's `desc` field — source line where
 * the local/parameter/global/static was declared. 0 when the emitter doesn't write it.
 * @property sourceFile N_SOL-effective filename at decl time.
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
    var sizeBytes: Long = 0L,
)

/**
 * A line-number record (N_SLINE) — `(source, line)` mapped to a text
 * address. Captured in [Harvest.lineEntries] grouped by source filename.
 */
@Serializable
data class LineEntry(val line: Int, val addr: SerializableAddress)

@Serializable(with = ToStringSerializer::class)
data class GhidraKey(val category: CategoryPath, val name: String) {
    constructor(path: String, name: String) : this(CategoryPath(path), name)

    override fun toString() = "$category/$name"
}

/**
 * One bucket of TypeAsts mapping to a single (CategoryPath, ghidraName) slot —
 * Ghidra's uniqueness constraint. `winner` is the AST whose body materialises
 * into the DTM; the other members are tracked for diagnostics only.
 */
@Serializable
data class CanonicalGroup(val key: GhidraKey, val ast: TypeAst, val members: List<GlobalTypeId>, val distinct: Int)
