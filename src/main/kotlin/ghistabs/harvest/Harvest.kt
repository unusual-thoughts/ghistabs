@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.harvest

import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import kotlinx.serialization.Serializable

/**
 * Passive parser output. Canonicalization, XRef resolution, and content-hash queries are done
 * via [TypeResolver]. [rawCollisions] includes content-equivalent dupes; content-distinct survivors
 * live on [TypeResolver.divergentCollisions].
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
    /** type name → owning-header hint (raw spelling), voted pre-canonicalization; see [multiSourceHeaderHints]. */
    /**
     * Raw source spelling → canonical (§15), built once at harvest and already applied to the
     * render-facing per-record fields ([LineEntry.source], [SymbolRecord.sourceFile]) and the
     * [lineEntries]/[symbolsByCu] keys. [TypeAst.id] stays raw (DTM identity), so [TypeResolver]
     * still consults this map for type render-source attribution. Empty when canonicalization is off.
     */
) {

    fun getType(id: GlobalTypeId) = typeAsts[id]
}
