package ghistabs.builder

import ghistabs.parser.LocalTypeId

/**
 * Sealed classification of an unresolved type reference.
 * Tag identifies the classification category for logging and diagnostics.
 */
sealed class RefClassification(val tag: String) {
    /** Forward reference within the same CU: defined later in the CU's stream. */
    object ForwardSameCu : RefClassification("forward-same-cu")

    /**
     * Cross-CU reference that should have resolved via BINCL/EXCL include tables
     * but did not (missing include context or include table gap).
     */
    object CrossCuIncludeMiss : RefClassification("cross-cu-include-miss")

    /**
     * Type is not in any known source: truly missing from the entire harvest.
     */
    object TrulyMissing : RefClassification("truly-missing")
}

/**
 * Pure classifier for unresolved type references.
 * No Ghidra imports; operates on plain data only.
 *
 * Classifies a dangling ref by:
 * 1. Checking if the ref is to the same CU → ForwardSameCu
 * 2. Checking if the ref's CU is in the known include table → CrossCuIncludeMiss
 * 3. Otherwise → TrulyMissing
 */
object ResolverDecision {
    /**
     * Classifies a dangling type reference.
     *
     * @param refId The TypeId being referenced (cu, n).
     * @param refererCu The file number (cu) of the referrer's CU.
     * @param knownTypeIds All TypeIds that were observed in the harvest.
     * @param knownFileNums All file numbers known to the referrer's CU (from IncludeContext.fileNumToHeader.keys).
     * @return RefClassification: ForwardSameCu, CrossCuIncludeMiss, or TrulyMissing.
     *
     * @throws IllegalArgumentException if refId is in knownTypeIds (resolved refs must not reach here).
     */
    fun classifyRef(
        refId: LocalTypeId,
        refererCu: Int,
        knownTypeIds: Set<LocalTypeId>,
        knownFileNums: Set<Int>,
    ): RefClassification {
        // If the ref resolves, this is an error — the caller should have checked first.
        if (refId in knownTypeIds) {
            throw IllegalArgumentException(
                "Refs that resolve must not reach the classifier (refId=$refId found in knownTypeIds)",
            )
        }

        // Same CU: likely a forward ref to something defined later in the same stream
        return when (refId.file) {
            refererCu -> RefClassification.ForwardSameCu

            // Different CU but in the known include table: should have resolved, but didn't
            in knownFileNums -> RefClassification.CrossCuIncludeMiss

            // Not in knownTypeIds, not in known includes: truly missing
            else -> RefClassification.TrulyMissing
        }
    }
}
