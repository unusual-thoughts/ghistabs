package ghistabs.index

import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.harvest.*
import ghistabs.parse.*

/**
 * Which physical file each raw gcc spelling means, and the per-source views the render iterates.
 *
 * gcc names one file several ways — a bare `#include "x.h"` in one CU, a full include path in
 * another — so the raw spellings a [Harvest] is keyed on are not identities. [fold] is the mapping
 * that makes them one (§15), and everything below it is the same harvest data with that mapping
 * already applied.
 *
 * Reads [Harvest] and nothing else: [allSources] enumerates each type's `id.source`, which is a key,
 * not a query, so this never needs [TypeGraph]. Attribution — *which* file a type or function belongs
 * to — is [SourceHints]/[EffectiveSource] and needs both halves; it is deliberately not here.
 */
class SourceIndex(
    private val harvest: Harvest,
    private val foldSources: Boolean = true,
    sink: DiagnosticSink = DummySink,
) : DiagnosticSink by sink {
    /**
     * Every source spelling the stabs mention, however they mention it: a file that was inlined from,
     * a file that holds statics, and a type's own `N_SOL` or CU. `image.h` is in none of the first
     * two — nothing was inlined from it and it declares no statics — and is known only as some type's
     * `id.source`.
     */
    val allSources by lazy {
        harvest.sources.keys +
            harvest.types.values.flatMap { listOfNotNull(it.sourceFile, it.id.source.identity) }
    }

    // ── §15 source folds (private mechanism): two gcc spellings of one physical header → one output
    // file. Render never sees these — only the folded per-source views in the facade below. ──
    val sourceFolds: Map<GhidraSourceFile, GhidraSourceFile> by lazy { foldSourcePaths(allSources) }

    /**
     * A raw spelling's render identity: its basename fold (§15). [foldSources] off → bypass, so
     * `sourceFolds` is never computed.
     *
     * A CU's compilation directory used to be joined on here too, from a `cuDirectories` map. It is
     * applied at [ghistabs.harvest.identity] now, so a CU with a directory-`N_SO` shares one key with
     * its own N_SOL/N_BINCL spellings from the harvest onward. The fold still carries the CUs gcc gave
     * no directory-`N_SO` at all (33 of 94 on crypto_mi_gcc421): `spelling == filename` leaves those
     * bare, and only a basename match against the full spelling reunites them — 9 of that fixture's 9
     * remaining folds are such CUs, not the headers this pass was written for.
     */
    fun fold(source: GhidraSourceFile) = if (foldSources) sourceFolds[source] ?: source else source

    fun LineEntry.folded() = copy(source = fold(source))
    fun <S : SymbolDecl<GlobalTypeId>> Symbol<S>.folded() = copy(sourceFile = fold(sourceFile))

    // Blocks carry a source too, and it was the one field left raw — so `inlineParams`, which asks
    // whether a block belongs to the file being rendered, compared a raw N_SOL spelling against a
    // folded one. It matched only while the fold happened to pick the bare spelling N_SOL usually
    // uses; folding onto the full path exposed it, and every pseudo-call in xvimage.cpp lost its
    // parameter names to the dataflow fallback.
    private fun BlockScope.folded(): BlockScope = copy(
        source = source?.let(::fold),
        locals = locals.map { it.folded() },
        children = children.map { it.folded() },
    )

    // ── Render facade: per-source views with every source spelling already folded (§15). ──

    /**
     * Every spelling the stabs mention → the identity it renders as. `SourceMapApplier` registers
     * both sides, so the program ends up listing every file it was built from — including headers
     * that carry no line entry and no symbol, which are still files this binary was built from and
     * which the render draws types in.
     *
     * The line map is published under the raw spellings and then folded with
     * `transferSourceMapEntries`, so a folded-away spelling stays listed with zero entries: honest
     * about what gcc emitted, while the entries sit on the identity the render reads them back by.
     */
    val renderIdentityBySource: Map<GhidraSourceFile, GhidraSourceFile> by lazy {
        allSources.associateWith(::fold)
    }

    /**
     * The sources gcc compiled as a translation unit — an `N_SO` of its own — as against the files it
     * only ever included. The render had been asking "does this file define functions", which is a
     * different question and answers wrong for a header full of inline methods.
     *
     * Read straight off [SourceHarvest.cu], which is the `N_SO` itself. It used to union that with the
     * CUs derived from `Func.cu` and each type's `id.source`, back when the declared half was only the
     * CUs holding statics; those two are a strict subset now (54 against 55 on locale_test, whose
     * COMDAT-only CU declares neither) and contribute nothing — measured 0 across four fixtures.
     */
    val compilationUnits: Set<GhidraSourceFile> by lazy {
        harvest.sources.filterValues { it.cu != null }.keys.mapTo(mutableSetOf(), ::fold)
    }

    /**
     * Open functions with their line entries / params / locals folded onto output spellings.
     *
     * The counterpart of [Harvest.functions], which stays raw. Consumers that only want the facts —
     * `DataTypeRegistry.byDemangledClass` walks `this`-param types, which folding never touches —
     * read that one and never force this copy.
     */
    val functions: List<Func> by lazy {
        harvest.functions.map { f ->
            f.copy(
                lineEntries = f.lineEntries.map { it.folded() }.toMutableList(),
                params = f.params.map { it.folded() }.toMutableList(),
                locals = f.locals.map { it.folded() }.toMutableList(),
                blocks = f.blocks.map { it.folded() },
            )
        }
    }

    /** Functions by linkage name — the lookup `renderFull` needs to attach a real signature to a
     *  method stab, built once rather than per rendered struct. */
    val functionsByMangledName: Map<String, Func> by lazy { functions.associateBy { it.name } }
}
