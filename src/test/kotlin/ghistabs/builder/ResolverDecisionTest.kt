package ghistabs.builder

import ghistabs.parser.LocalTypeId
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

/**
 * Pure unit tests for ResolverDecision classifier.
 * No Ghidra imports, no mocks — operates on plain data only.
 */
class ResolverDecisionTest {
    /**
     * Test forward-same-cu classification: ref and referrer in the same CU.
     */
    @Test
    fun testClassifyForwardSameCu() {
        val refId = LocalTypeId(file = 1, n = 42)
        val refererCu = 1
        val knownTypeIds = setOf(LocalTypeId(1, 10), LocalTypeId(2, 20))
        val knownFileNums = setOf(1, 2, 3)

        val result = ResolverDecision.classifyRef(refId, refererCu, knownTypeIds, knownFileNums)

        assertEquals(RefClassification.ForwardSameCu, result)
        assertEquals("forward-same-cu", result.tag)
    }

    /**
     * Test cross-cu-include-miss classification: ref is to a different CU that is known
     * in the include table, but the specific type is not in knownTypeIds.
     */
    @Test
    fun testClassifyCrossCuIncludeMiss() {
        val refId = LocalTypeId(file = 2, n = 42)
        val refererCu = 1
        val knownTypeIds = setOf(LocalTypeId(1, 10), LocalTypeId(3, 30))
        val knownFileNums = setOf(1, 2, 3)

        val result = ResolverDecision.classifyRef(refId, refererCu, knownTypeIds, knownFileNums)

        assertEquals(RefClassification.CrossCuIncludeMiss, result)
        assertEquals("cross-cu-include-miss", result.tag)
    }

    /**
     * Test truly-missing classification: ref is to a CU not in the include table.
     */
    @Test
    fun testClassifyTrulyMissing() {
        val refId = LocalTypeId(file = 99, n = 42)
        val refererCu = 1
        val knownTypeIds = setOf(LocalTypeId(1, 10), LocalTypeId(2, 20))
        val knownFileNums = setOf(1, 2, 3)

        val result = ResolverDecision.classifyRef(refId, refererCu, knownTypeIds, knownFileNums)

        assertEquals(RefClassification.TrulyMissing, result)
        assertEquals("truly-missing", result.tag)
    }

    /**
     * Test error case: if refId is in knownTypeIds, it should not reach the classifier.
     * The function throws an IllegalArgumentException.
     */
    @Test
    fun testErrorOnResolvedRef() {
        val refId = LocalTypeId(file = 1, n = 42)
        val refererCu = 1
        val knownTypeIds = setOf(refId, LocalTypeId(2, 20)) // refId is already known
        val knownFileNums = setOf(1, 2)

        val exception =
            assertThrows(IllegalArgumentException::class.java) {
                ResolverDecision.classifyRef(refId, refererCu, knownTypeIds, knownFileNums)
            }

        assertEquals(true, exception.message?.contains("Refs that resolve must not reach the classifier"))
    }

    /**
     * Test edge case: empty knownTypeIds and knownFileNums.
     * Any ref with an unknown CU should be truly-missing.
     */
    @Test
    fun testTrulyMissingWithEmptyKnowns() {
        val refId = LocalTypeId(file = 5, n = 42)
        val refererCu = 1
        val knownTypeIds = emptySet<LocalTypeId>()
        val knownFileNums = emptySet<Int>()

        val result = ResolverDecision.classifyRef(refId, refererCu, knownTypeIds, knownFileNums)

        assertEquals(RefClassification.TrulyMissing, result)
    }

    /**
     * Test edge case: ref to same CU even when knownFileNums is empty.
     * ForwardSameCu is detected by cu number match, regardless of knownFileNums.
     */
    @Test
    fun testForwardSameCuWithEmptyFileNums() {
        val refId = LocalTypeId(file = 1, n = 42)
        val refererCu = 1
        val knownTypeIds = setOf(LocalTypeId(1, 10))
        val knownFileNums = emptySet<Int>()

        val result = ResolverDecision.classifyRef(refId, refererCu, knownTypeIds, knownFileNums)

        assertEquals(RefClassification.ForwardSameCu, result)
    }
}
