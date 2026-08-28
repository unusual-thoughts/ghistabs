@file:UseSerializers(AddressRangeSerializer::class, SourceFileSerializer::class)
@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.harvest

import ghidra.program.model.address.AddressRange
import ghistabs.parse.GlobalTypeDecl
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.SourceFile
import ghistabs.parse.SymbolDecl
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers

/**
 * Passive parser output, keyed on raw source spellings. Source folding (§15), XRef resolution, and
 * content-hash queries are all derived views on [HarvestIndex]. [rawCollisions] includes
 * content-equivalent dupes; content-distinct survivors live on [HarvestIndex.divergentCollisions].
 */
@Serializable
data class Harvest(
    val types: Map<GlobalTypeId, Type>,
    val rawCollisions: Map<GlobalTypeId, Map<String, Set<GlobalTypeDecl>>>,
    val staticsByCu: Map<GhidraSourceFile, List<StaticSymbol>>,
    val functions: List<Func>,
    /** N_SLINE entries grouped by N_SOL-effective source; sorted by line on insertion. */
    val lineEntries: Map<GhidraSourceFile, List<LineEntry>>,
    /** Addressless `:c` compile-time constants — applied as equates + a synthetic enum catalog. */
    val constants: List<SymbolDecl.Constant<GlobalTypeId>>,
    /** N_SO/N_SOL text partition — which file each run of text came from, address-backed. */
    val textRanges: Map<AddressRange, GhidraSourceFile>,
    /** What each CU's N_SO pair bracketed; null where it declared no text, its code having gone to
     *  COMDAT sections that the `Ltext` labels never see — 59 of 61 CUs on locale_test (§39). */
    val cuSpans: Map<SourceFile.CUSource, AddressRange?>,
)
