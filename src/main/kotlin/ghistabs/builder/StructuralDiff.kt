package ghistabs.builder

/**
 * Pure POKO representing a single component/field in a struct.
 * No Ghidra imports — this is pure data.
 */
data class ComponentRecord(
    val offsetBytes: Int,
    val lengthBytes: Int,
    val fieldName: String?,
    val dtPathName: String, // e.g. "/std/int" — opaque identity string
    val isBitfield: Boolean,
)

/**
 * Result of comparing two struct layouts byte-by-byte.
 */
sealed class StructDiffResult {
    object Identical : StructDiffResult()

    data class GapMergeable(val mergePlan: List<MergeOp>) : StructDiffResult()

    data class Conflicting(val reason: String) : StructDiffResult()
}

/**
 * Represents a field from one side that should be merged into the other.
 * sourceFromLeft: true means the field comes from the left side, false means right side.
 * sourceComponent: the actual component being merged (includes offsetBytes for target position).
 */
data class MergeOp(val sourceFromLeft: Boolean, val sourceComponent: ComponentRecord)

/**
 * Pure structural diff implementation.
 * Compares two struct layouts byte-by-byte and determines if they are:
 * - Identical: same fields, same layout
 * - GapMergeable: fields only defined on one side (can be merged by filling gaps)
 * - Conflicting: incompatible field definitions at the same offset
 *
 * Algorithm:
 * 1. Internal-overlap defensive check: ensure no side has overlapping components
 * 2. Length-extension policy: longer side must not disagree with shorter side in overlap region
 * 3. Byte-walk: for each byte, check coverage and agreement
 * 4. Merge candidate validation: components that fill gaps on the other side
 * 5. Bitfield carve-out: bitfield collisions are conflicts
 * 6. Return Identical, GapMergeable, or Conflicting
 */
object StructuralDiff {
    fun diff(
        left: List<ComponentRecord>,
        leftLengthBytes: Int,
        right: List<ComponentRecord>,
        rightLengthBytes: Int,
    ): StructDiffResult {
        // 1. Build byte coverage arrays for each side
        val leftCoverage = buildCoverage(left, leftLengthBytes)
        val rightCoverage = buildCoverage(right, rightLengthBytes)

        // 2. Check internal overlaps on each side (should be impossible in well-formed structs)
        val internalOverlapLeft = hasInternalOverlap(left)
        if (internalOverlapLeft != null) {
            return StructDiffResult.Conflicting("internal overlap in left: ${internalOverlapLeft.fieldName}")
        }

        val internalOverlapRight = hasInternalOverlap(right)
        if (internalOverlapRight != null) {
            return StructDiffResult.Conflicting("internal overlap in right: ${internalOverlapRight.fieldName}")
        }

        // 3. Check length extension: if lengths differ, longer side must have no defined components
        // beyond min(left.length, right.length) that disagree with the shorter side
        val minLen = minOf(leftLengthBytes, rightLengthBytes)
        val maxLen = maxOf(leftLengthBytes, rightLengthBytes)

        // 4. Byte-walk to find disagreements and merge candidates
        val mergeCandidates = mutableMapOf<ComponentRecord, Boolean>() // component -> fromLeft
        val processedLeft = mutableSetOf<ComponentRecord>()
        val processedRight = mutableSetOf<ComponentRecord>()

        for (i in 0 until maxLen) {
            val leftComponent = leftCoverage.getOrNull(i)
            val rightComponent = rightCoverage.getOrNull(i)

            when {
                // Gap on both sides, continue
                leftComponent == null && rightComponent == null -> continue

                leftComponent != null && rightComponent == null -> {
                    // Left defines, right is gap — candidate for merge into right
                    if (leftComponent !in processedLeft) {
                        mergeCandidates[leftComponent] = true
                        processedLeft.add(leftComponent)
                    }
                }

                rightComponent != null && leftComponent == null -> {
                    // Right defines, left is gap — candidate for merge into left
                    if (rightComponent !in processedRight) {
                        mergeCandidates[rightComponent] = false
                        processedRight.add(rightComponent)
                    }
                }

                leftComponent != null && rightComponent != null -> {
                    // Both define at this byte — must be identical
                    if (leftComponent.offsetBytes != rightComponent.offsetBytes ||
                        leftComponent.lengthBytes != rightComponent.lengthBytes ||
                        leftComponent.dtPathName != rightComponent.dtPathName ||
                        leftComponent.fieldName != rightComponent.fieldName
                    ) {
                        val leftDesc =
                            "${leftComponent.fieldName}@${leftComponent.offsetBytes} (${leftComponent.dtPathName})"
                        val rightDesc =
                            "${rightComponent.fieldName}@${rightComponent.offsetBytes} (${rightComponent.dtPathName})"
                        return StructDiffResult.Conflicting(
                            "disagreement at byte $i: $leftDesc vs $rightDesc",
                        )
                    }

                    // Bitfield collision check
                    if ((leftComponent.isBitfield || rightComponent.isBitfield) && leftComponent != rightComponent) {
                        return StructDiffResult.Conflicting("bitfield collision at byte $i")
                    }
                }
            }
        }

        // 5. Validate merge candidates: each component must fully fit in the gap region
        val mergeOps = mutableListOf<MergeOp>()

        for ((component, fromLeft) in mergeCandidates) {
            val targetCoverage = if (fromLeft) rightCoverage else leftCoverage
            val targetLen = if (fromLeft) rightLengthBytes else leftLengthBytes

            // Check if the entire component fits in the gap on the target side
            var canFit = true
            for (byte in component.offsetBytes until minOf(component.offsetBytes + component.lengthBytes, targetLen)) {
                if (targetCoverage.getOrNull(byte) != null) {
                    canFit = false
                    break
                }
            }

            if (!canFit) {
                // Shingled overlap — this is a conflict
                return StructDiffResult.Conflicting(
                    "shingled overlap of ${component.fieldName} at offset ${component.offsetBytes}: " +
                        "cannot fit in gap on target side",
                )
            }

            mergeOps.add(MergeOp(fromLeft, component))
        }

        // 6. Return result
        // If lengths differ but no merge ops are needed, still return GapMergeable (with empty plan)
        // so the caller can reconcile the lengths. NEVER return Identical if lengths differ.
        return if (mergeOps.isEmpty() && leftLengthBytes == rightLengthBytes) {
            StructDiffResult.Identical
        } else {
            StructDiffResult.GapMergeable(mergeOps)
        }
    }

    /**
     * Build a byte-coverage array where each position maps to the ComponentRecord
     * that covers that byte, or null if no component covers it.
     */
    private fun buildCoverage(components: List<ComponentRecord>, lengthBytes: Int): Array<ComponentRecord?> {
        val coverage = arrayOfNulls<ComponentRecord>(lengthBytes)
        for (component in components) {
            for (byte in component.offsetBytes until minOf(
                component.offsetBytes + component.lengthBytes,
                lengthBytes,
            )) {
                coverage[byte] = component
            }
        }
        return coverage
    }

    /**
     * Check if a component list has internal overlaps (should not happen in well-formed structs).
     * Returns the first overlapping component found, or null if none.
     */
    private fun hasInternalOverlap(components: List<ComponentRecord>): ComponentRecord? {
        val seen = mutableMapOf<Int, ComponentRecord>()
        for (component in components) {
            for (byte in component.offsetBytes until component.offsetBytes + component.lengthBytes) {
                if (byte in seen) {
                    return component
                }
                seen[byte] = component
            }
        }
        return null
    }
}
