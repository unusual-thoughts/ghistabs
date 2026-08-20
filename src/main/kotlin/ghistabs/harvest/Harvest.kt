@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.harvest

import ghidra.program.model.address.AddressRange
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SymbolDecl
import ghistabs.parse.TypeDecl
import kotlinx.serialization.Serializable

/**
 * Passive parser output, keyed on raw source spellings. Source folding (§15), XRef resolution, and
 * content-hash queries are all derived views on [HarvestIndex]. [rawCollisions] includes
 * content-equivalent dupes; content-distinct survivors live on [HarvestIndex.divergentCollisions].
 */
@Serializable
data class Harvest(
    val types: Map<GlobalTypeId, Type>,
    val rawCollisions: Map<GlobalTypeId, Map<String, Set<TypeDecl<GlobalTypeId>>>>,
    val staticsByCu: Map<
        @Serializable(with = SourceFileSerializer::class)
        GhidraSourceFile,
        List<StaticSymbol>,
        >,
    val functions: List<Func>,
    /** N_SLINE entries grouped by N_SOL-effective source; sorted by line on insertion. */
    val lineEntries: Map<
        @Serializable(with = SourceFileSerializer::class)
        GhidraSourceFile,
        List<LineEntry>,
        >,
    /** Addressless `:c` compile-time constants — applied as equates + a synthetic enum catalog. */
    val constants: List<SymbolDecl.Constant<GlobalTypeId>>,
    /** N_SO/N_SOL text partition — which file each run of text came from, address-backed. */
    val textRanges: Map<
        @Serializable(with = AddressRangeSerializer::class)
        AddressRange,
        @Serializable(with = SourceFileSerializer::class)
        GhidraSourceFile,
        > = mapOf(),
    /** [N_SO start, N_SO end] per CU. Gaps between them are COMDAT shared by several CUs. */
    val cuRanges: Map<
        @Serializable(with = AddressRangeSerializer::class)
        AddressRange,
        @Serializable(with = SourceFileSerializer::class)
        GhidraSourceFile,
        > = mapOf(),
) {
    companion object {
        /** A harvest of nothing but [types] — for resolvers/tests that need no symbol side. */
        fun of(types: Map<GlobalTypeId, Type>) = Harvest(
            types = types,
            rawCollisions = mapOf(),
            staticsByCu = mapOf(),
            functions = listOf(),
            lineEntries = mapOf(),
            constants = listOf(),
        )
    }
}
