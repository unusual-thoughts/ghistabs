@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.harvest

import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SymbolDecl
import ghistabs.parse.TypeDecl
import kotlinx.serialization.Serializable

/**
 * Passive parser output, keyed on raw source spellings. Source folding (§15), XRef resolution, and
 * content-hash queries are all derived views on [TypeResolver]. [rawCollisions] includes
 * content-equivalent dupes; content-distinct survivors live on [TypeResolver.divergentCollisions].
 */
@Serializable
data class Harvest(
    val typeAsts: Map<GlobalTypeId, TypeAst>,
    val parseErrors: Int,
    val rawCollisions: Map<GlobalTypeId, Map<String, Set<TypeDecl<GlobalTypeId>>>>,
    val symbolsByCu: Map<String, List<SymbolRecord>>,
    val openFunctions: List<OpenFunction>,
    /** N_SLINE entries grouped by N_SOL-effective source filename; sorted by line on insertion. */
    val lineEntries: Map<String, List<LineEntry>>,
    /** Addressless `:c` compile-time constants — applied as equates + a synthetic enum catalog. */
    val constants: List<SymbolDecl.Constant<GlobalTypeId>>,
) {
    companion object {
        /** A harvest of nothing but [typeAsts] — for resolvers/tests that need no symbol side. */
        fun of(typeAsts: Map<GlobalTypeId, TypeAst>) = Harvest(
            typeAsts = typeAsts,
            parseErrors = 0,
            rawCollisions = mapOf(),
            symbolsByCu = mapOf(),
            openFunctions = listOf(),
            lineEntries = mapOf(),
            constants = listOf(),
        )
    }

    fun getType(id: GlobalTypeId) = typeAsts[id]
}
