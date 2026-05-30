package ghistabs.builder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Pure unit tests for StructuralDiff.
 * No Ghidra imports, no mockito — operates entirely on ComponentRecord POKOs.
 */
class StructuralDiffTest {
    /**
     * Test 1: Identical structures with same fields and layout.
     */
    @Test
    fun testIdenticalStructs() {
        val left =
            listOf(
                ComponentRecord(0, 4, "field1", "/int", false),
                ComponentRecord(4, 4, "field2", "/float", false),
            )
        val right =
            listOf(
                ComponentRecord(0, 4, "field1", "/int", false),
                ComponentRecord(4, 4, "field2", "/float", false),
            )

        val result = StructuralDiff.diff(left, 8, right, 8)
        assertTrue(result is StructDiffResult.Identical, "Two identical structs should diff as Identical")
    }

    /**
     * Test 2: Pure gap-fill merge.
     * A defines [0..4), B defines [4..8), both 8 bytes — should merge.
     */
    @Test
    fun testPureGapFillMerge() {
        val left =
            listOf(
                ComponentRecord(0, 4, "fieldA", "/int", false),
            )
        val right =
            listOf(
                ComponentRecord(4, 4, "fieldB", "/int", false),
            )

        val result = StructuralDiff.diff(left, 8, right, 8)
        assertTrue(result is StructDiffResult.GapMergeable, "Gap-fill scenario should produce GapMergeable")

        val plan = (result as StructDiffResult.GapMergeable).mergePlan
        assertEquals(2, plan.size, "Should have 2 merge ops (fieldA from left to right, fieldB from right to left)")
        // One op should place fieldB at offset 4
        val fieldBOp = plan.find { !it.sourceFromLeft && it.sourceComponent.offsetBytes == 4 }
        assertTrue(fieldBOp != null, "Should have merge op for fieldB at offset 4")
        // One op should place fieldA at offset 0
        val fieldAOp = plan.find { it.sourceFromLeft && it.sourceComponent.offsetBytes == 0 }
        assertTrue(fieldAOp != null, "Should have merge op for fieldA at offset 0")
    }

    /**
     * Test 3: Same-offset disagreement → Conflicting.
     */
    @Test
    fun testSameOffsetDisagreement() {
        val left =
            listOf(
                ComponentRecord(0, 4, "field", "/int", false),
            )
        val right =
            listOf(
                ComponentRecord(0, 4, "field", "/float", false),
            )

        val result = StructuralDiff.diff(left, 4, right, 4)
        assertTrue(result is StructDiffResult.Conflicting, "Different types at same offset should conflict")
        assertTrue((result as StructDiffResult.Conflicting).reason.contains("disagreement"), "Reason should mention disagreement")
    }

    /**
     * Test 4: Shingled overlap → Conflicting.
     * A has int32 at [0..4) and another int32 at [4..8).
     * B has int64 at [0..8).
     * These overlap but are not identical → conflict.
     */
    @Test
    fun testShingledOverlapConflict() {
        val left =
            listOf(
                ComponentRecord(0, 4, "fieldA", "/int", false),
                ComponentRecord(4, 4, "fieldB", "/int", false),
            )
        val right =
            listOf(
                ComponentRecord(0, 8, "bigField", "/long", false),
            )

        val result = StructuralDiff.diff(left, 8, right, 8)
        assertTrue(result is StructDiffResult.Conflicting, "Shingled overlap should conflict")
        assertTrue(
            (result as StructDiffResult.Conflicting).reason.contains("disagreement"),
            "Reason should mention disagreement or conflict",
        )
    }

    /**
     * Test 5: Subset overlap → Conflicting.
     * A defines [0..8), B defines [2..4) inside A's span.
     * Both cover bytes 2-4, but B is a subset → conflict at the differing component.
     */
    @Test
    fun testSubsetOverlapConflict() {
        val left =
            listOf(
                ComponentRecord(0, 8, "big", "/long", false),
            )
        val right =
            listOf(
                ComponentRecord(2, 2, "small", "/short", false),
            )

        val result = StructuralDiff.diff(left, 8, right, 8)
        assertTrue(result is StructDiffResult.Conflicting, "Subset overlap with different components should conflict")
    }

    /**
     * Test 6: Bitfield collision → Conflicting.
     * A has bitfield at byte 0, B has int32 at [0..4).
     */
    @Test
    fun testBitfieldVsPrimitive() {
        val left =
            listOf(
                ComponentRecord(0, 4, "bits", "/bitfield", true),
            )
        val right =
            listOf(
                ComponentRecord(0, 4, "field", "/int", false),
            )

        val result = StructuralDiff.diff(left, 4, right, 4)
        assertTrue(result is StructDiffResult.Conflicting, "Bitfield collision with primitive should conflict")
        assertTrue((result as StructDiffResult.Conflicting).reason.contains("bitfield"), "Reason should mention bitfield")
    }

    /**
     * Test 7: Length extension OK.
     * A is 8 bytes with field at [0..4), B is 16 bytes with same field at [0..4) plus additional field at [12..16).
     * Should merge, extending A.
     */
    @Test
    fun testLengthExtensionOk() {
        val left =
            listOf(
                ComponentRecord(0, 4, "fieldA", "/int", false),
            )
        val right =
            listOf(
                ComponentRecord(0, 4, "fieldA", "/int", false),
                ComponentRecord(12, 4, "fieldB", "/int", false),
            )

        val result = StructuralDiff.diff(left, 8, right, 16)
        assertTrue(result is StructDiffResult.GapMergeable, "Length extension with same base fields should merge")

        val plan = (result as StructDiffResult.GapMergeable).mergePlan
        assertEquals(1, plan.size, "Should have 1 merge op for the extended field")
        assertEquals(12, plan[0].sourceComponent.offsetBytes, "Extended field at byte 12")
        assertFalse(plan[0].sourceFromLeft, "Extended field comes from right")
    }

    /**
     * Test 8: Length-extension disagreement → Conflicting.
     * A is 8 bytes with float32 at [4..8), B is 16 bytes with int32 at [4..8).
     * Overlap region disagrees → conflict.
     */
    @Test
    fun testLengthExtensionDisagreement() {
        val left =
            listOf(
                ComponentRecord(4, 4, "field", "/float", false),
            )
        val right =
            listOf(
                ComponentRecord(4, 4, "field", "/int", false),
                ComponentRecord(12, 4, "extra", "/int", false),
            )

        val result = StructuralDiff.diff(left, 8, right, 16)
        assertTrue(result is StructDiffResult.Conflicting, "Disagreement in overlap region should conflict")
    }
}
