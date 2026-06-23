@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.harvest

import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl
import kotlinx.serialization.Serializable

/**
 * Passive bag of what the parser produced. All canonicalization, XRef
 * resolution, and content-hash queries happen via [TypeResolver], constructed
 * by [ghistabs.importer.StabsImporter] from the harvest plus a sink/diagnostics
 * context.
 *
 * [rawCollisions] are multi-body name collisions as observed during parsing —
 * including content-equivalent duplicates. The filtered, content-distinct
 * survivors live on [TypeResolver.divergentCollisions].
 */
@Serializable
data class Harvest(
    val typeAsts: Map<GlobalTypeId, TypeAst>,
    val parseErrors: Int = 0,
    val rawCollisions: Map<GlobalTypeId, Map<String, Set<TypeDecl<GlobalTypeId>>>> = mapOf(),
    val symbolsByCu: Map<String, List<HarvestedSymbol>> = mapOf(),
    val openFunctions: List<OpenFunction> = listOf(),
    /**
     * N_SLINE entries grouped by source filename. N_SOL switches the
     * "current source file" for subsequent N_SLINE records (so a line
     * number inside an `#include`d header lands under that header's
     * filename, not the enclosing CU's). Sorted by line on insertion.
     */
    val lineEntries: Map<String, List<LineEntry>> = mapOf(),
) {
    val allHarvestedSymbols by lazy { symbolsByCu.values.flatten() }

    fun getType(id: GlobalTypeId) = typeAsts[id]
    fun getStruct(id: GlobalTypeId) = typeAsts[id]?.body as? TypeDecl.Struct
}
