package ghicpp

import ghidra.program.model.listing.Program
import ghidra.util.classfinder.ClassSearcher
import ghidra.util.classfinder.ExtensionPoint

/**
 * A source of class records other than the RTTI the class analyzers read: ghistabs' import, from the stabs.
 * Found by Ghidra's [ClassSearcher] like any analyzer or plugin: a class whose name ends in
 * `ClassRecordSource`, the suffix this extension's `data/ExtensionPoint.manifest` registers. So ghicpp asks
 * about a program without knowing which extension can describe it.
 */
interface ClassRecordSource : ExtensionPoint {
    /** Whether [program]'s class record, when it has one, is this source's rather than the RTTI's. */
    fun describes(program: Program): Boolean

    /** How to get [program] its class record from this source, when it has none; null if this source can't. */
    fun missingRecordHint(program: Program): String?

    companion object {
        private val all: List<ClassRecordSource> get() = ClassSearcher.getInstances(ClassRecordSource::class.java)

        /** Whether some installed source, not the RTTI, describes [program]'s classes. */
        fun describedElsewhere(program: Program) = all.any { it.describes(program) }

        /** The first installed source's [missingRecordHint] for [program]. */
        fun hintFor(program: Program) = all.firstNotNullOfOrNull { it.missingRecordHint(program) }
    }
}
