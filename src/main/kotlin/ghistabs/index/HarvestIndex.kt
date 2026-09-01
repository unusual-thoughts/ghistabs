package ghistabs.index

import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.harvest.*

/**
 * The three indexes over one [Harvest], held together so a caller that wants several gets them
 * consistent — one [TypeGraph], one fold table, one [SourceHints] vote.
 *
 * A holder, not a layer: it owns components and no derived state of its own. Everything it used to
 * compute now lives with the half that answers it — resolution on [types], folding and the per-source
 * views on [sources], attribution on [hints] and [EffectiveSource], slot assignment on
 * [TypeGraph.locateTypes]. Consumers that need only one half should take that half; this exists for
 * the ones that genuinely need more than one, and for constructing them together.
 */
class HarvestIndex(val harvest: Harvest, foldSources: Boolean = true, sink: DiagnosticSink = DummySink) :
    DiagnosticSink by sink {
    val types = TypeGraph(harvest, sink)

    val sources = SourceIndex(harvest, foldSources, sink)

    /** Where the stabs say a type lives, before any source root. One shared instance: the per-name
     *  vote is the expensive part of attribution and both materialize and render want one answer. */
    val hints = SourceHints(this)
}
