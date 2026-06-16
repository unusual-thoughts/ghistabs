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

/**
 * One bucket of TypeAsts mapping to a single (CategoryPath, ghidraName) slot —
 * Ghidra's uniqueness constraint. `winner` is the AST whose body materialises
 * into the DTM; the other members are tracked for diagnostics only.
 */
data class CanonicalGroup(val key: Pair<CategoryPath, String>, val members: List<TypeAst>, val winner: TypeAst)
