@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.harvest

import ghistabs.parse.GlobalTypeId
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
    val parseErrors: Int = 0,
    val rawCollisions: Map<GlobalTypeId, Map<String, Set<TypeDecl<GlobalTypeId>>>> = mapOf(),
    val symbolsByCu: Map<String, List<SymbolRecord>> = mapOf(),
    val openFunctions: List<OpenFunction> = listOf(),
    /** N_SLINE entries grouped by N_SOL-effective source filename; sorted by line on insertion. */
    val lineEntries: Map<String, List<LineEntry>> = mapOf(),
) {

    fun getType(id: GlobalTypeId) = typeAsts[id]
}
