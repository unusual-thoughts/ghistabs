@file:UseSerializers(AddressRangeSerializer::class, SourceFileSerializer::class)
@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package ghistabs.harvest

import ghidra.program.model.address.AddressRange
import ghistabs.parse.GlobalTypeDecl
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.Language
import ghistabs.parse.SymbolDecl
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers

/**
 * Passive parser output, keyed on raw source spellings. Source folding (§15), XRef resolution, and
 * content-hash queries all live in `ghistabs.index`, built over this. [rawCollisions] includes
 * content-equivalent dupes; content-distinct survivors are `TypeGraph.divergentCollisions`.
 *
 * [functions]/[constants]/[statics] are cached flattenings of [sources] — arrangement, not
 * interpretation, which is why they belong here and not on an index. Consumers that want the facts
 * (`DataTypeRegistry.byDemangledClass`, [SourceHints]) read these; `SourceIndex.functions` is the
 * folded counterpart for the render.
 */
@Serializable
data class Harvest(
    val types: Map<GlobalTypeId, Type>,
    val rawCollisions: Map<GlobalTypeId, Map<String, Set<GlobalTypeDecl>>>,
    /** Every source the stream named, however it named it — see [StabCursor.toHarvest]. */
    val sources: Map<GhidraSourceFile, SourceHarvest>,
    /** N_SO/N_SOL text partition — which file each run of text came from, address-backed. */
    val textRanges: Map<AddressRange, GhidraSourceFile>,
) {
    private val cus get() = sources.values.mapNotNull { it.cu }

    /** Every open function, source attribution already on each [Func.cu]. */
    val functions by lazy { cus.flatMap { it.functions } }

    /** Addressless `:c` compile-time constants — applied as equates + a synthetic enum catalog. */
    val constants by lazy { cus.flatMap { it.constants } }

    /** Every file-scope symbol, the CU it was filed under already the [sources] key. */
    val statics by lazy { cus.flatMap { it.statics } }
}

/**
 * What one source file contributed. [lineEntries] is the only part a file earns just by being named
 * — an `N_SOL` is enough. Everything gcc can only say about a translation unit hangs off [cu], which
 * is null for a file that was never one.
 */
@Serializable
data class SourceHarvest(
    /** N_SLINE entries attributed here by the N_SOL-effective source; sorted by line. */
    val lineEntries: List<LineEntry>,
    /** Present iff gcc compiled this file as a translation unit of its own — it had an `N_SO`. */
    val cu: CompilationUnit?,
)

/**
 * What a file being a translation unit adds: the symbols filed under it, and its own `N_SO` pair.
 *
 * These are the symbols this CU **emitted**, not the ones this file **declares** — the two differ for
 * everything that lives in a header. An inline method or template instantiation is emitted into every
 * CU that included it, so it is filed here while its own `sourceFile` and line entries name the
 * header: 208 of 366 statics and 11540 of 15499 functions on crypto_mi_gcc421 read a header that way.
 * Reconstructing the declaring file from that is [SourceHints]' and [EffectiveSource]'s job, not this
 * type's. A header is never a key of its own — only an `N_SO` opens a CU, and gcc emits none for an
 * include (measured 0 header-keyed CUs corpus-wide).
 */
@Serializable
data class CompilationUnit(
    val statics: List<StaticSymbol>,
    val functions: List<Func>,
    val constants: List<SymbolDecl.Constant<GlobalTypeId>>,
    /** What this CU's N_SO pair bracketed; null where it declared no text, its code having gone to
     *  COMDAT sections that the `Ltext` labels never see — 59 of 61 CUs on locale_test (§39). */
    val span: AddressRange?,
    /** The opening `N_SO`'s `desc` language. Set by gcc 4.2.1 and 12.2, left 0 by gcc 3.4.5 and
     *  earlier, so null means "this emitter didn't say" rather than "not a known language". */
    val language: Language?,
)
