package ghistabs.builder

import ghistabs.parser.Access
import ghistabs.parser.BaseDecl
import ghistabs.parser.TypeDecl
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Pure unit tests for BaseInsertionPlanner.
 * No Ghidra imports, no mocks — operates on plain data only.
 */
class BaseInsertionPlannerTest {
    /**
     * Case 1: Single public non-virtual base at offset 0.
     * Expected: 1 InsertOp with name `_base_Base`, comment `"public base"`.
     */
    @Test
    fun testSinglePublicBase() {
        val baseDecl =
            BaseDecl(
                type = TypeDecl.Ref(id = ghistabs.parser.TypeId(cu = 0, n = 1)),
                isVirtual = false,
                access = Access.PUBLIC,
                offsetBits = 0L,
            )

        val resolveBase: (TypeDecl) -> ResolvedBase? = { _typeDecl ->
            ResolvedBase(simpleName = "Base", lengthBytes = 8)
        }

        val ops = BaseInsertionPlanner.planBaseInsertions(listOf(baseDecl), resolveBase)

        assertEquals(1, ops.size, "Expected exactly 1 InsertOp")
        val op = ops[0]
        assertEquals(0, op.offsetBytes)
        assertEquals("_base_Base", op.fieldName)
        assertEquals("public base", op.comment)
        assertEquals("Base", op.baseSimpleName)
    }

    /**
     * Case 2: Two public bases at offsets 0 and 8, supplied out of order.
     * Expected: 2 InsertOps in offset order (0, then 8).
     */
    @Test
    fun testMultipleBasesOutOfOrder() {
        val base1 =
            BaseDecl(
                type = TypeDecl.Ref(id = ghistabs.parser.TypeId(cu = 0, n = 1)),
                isVirtual = false,
                access = Access.PUBLIC,
                offsetBits = 64L, // 8 bytes
            )
        val base0 =
            BaseDecl(
                type = TypeDecl.Ref(id = ghistabs.parser.TypeId(cu = 0, n = 2)),
                isVirtual = false,
                access = Access.PUBLIC,
                offsetBits = 0L,
            )

        val resolveBase: (TypeDecl) -> ResolvedBase? = { typeDecl ->
            when (typeDecl) {
                is TypeDecl.Ref -> {
                    if (typeDecl.id.n == 1) {
                        ResolvedBase("Base1", 8)
                    } else {
                        ResolvedBase("Base0", 8)
                    }
                }
                else -> null
            }
        }

        val ops = BaseInsertionPlanner.planBaseInsertions(listOf(base1, base0), resolveBase)

        assertEquals(2, ops.size, "Expected 2 InsertOps")
        assertEquals(0, ops[0].offsetBytes, "First op should be at offset 0")
        assertEquals("_base_Base0", ops[0].fieldName)
        assertEquals("public base", ops[0].comment)
        assertEquals(8, ops[1].offsetBytes, "Second op should be at offset 8")
        assertEquals("_base_Base1", ops[1].fieldName)
        assertEquals("public base", ops[1].comment)
    }

    /**
     * Case 3: Virtual protected base.
     * Expected: 1 InsertOp with name `_vbase_VBase`, comment `"protected virtual base"`.
     */
    @Test
    fun testVirtualProtectedBase() {
        val baseDecl =
            BaseDecl(
                type = TypeDecl.Ref(id = ghistabs.parser.TypeId(cu = 0, n = 5)),
                isVirtual = true,
                access = Access.PROTECTED,
                offsetBits = 0L,
            )

        val resolveBase: (TypeDecl) -> ResolvedBase? = { _typeDecl ->
            ResolvedBase(simpleName = "VBase", lengthBytes = 16)
        }

        val ops = BaseInsertionPlanner.planBaseInsertions(listOf(baseDecl), resolveBase)

        assertEquals(1, ops.size)
        val op = ops[0]
        assertEquals("_vbase_VBase", op.fieldName)
        assertEquals("protected virtual base", op.comment)
    }

    /**
     * Case 4: Base whose resolveBase returns null (dangling ref).
     * Expected: Mapped to null, output is empty (no exception).
     */
    @Test
    fun testDanglingBaseRef() {
        val baseDecl =
            BaseDecl(
                type = TypeDecl.Ref(id = ghistabs.parser.TypeId(cu = 0, n = 10)),
                isVirtual = false,
                access = Access.PUBLIC,
                offsetBits = 0L,
            )

        val resolveBase: (TypeDecl) -> ResolvedBase? = { _typeDecl ->
            null // Simulates an unresolved type
        }

        val ops = BaseInsertionPlanner.planBaseInsertions(listOf(baseDecl), resolveBase)

        assertTrue(ops.isEmpty(), "Dangling bases should be filtered out")
    }

    /**
     * Case 5: Base with zero length (invalid).
     * Expected: Skipped (no exception).
     */
    @Test
    fun testZeroLengthBase() {
        val baseDecl =
            BaseDecl(
                type = TypeDecl.Ref(id = ghistabs.parser.TypeId(cu = 0, n = 15)),
                isVirtual = false,
                access = Access.PUBLIC,
                offsetBits = 0L,
            )

        val resolveBase: (TypeDecl) -> ResolvedBase? = { _typeDecl ->
            ResolvedBase(simpleName = "EmptyBase", lengthBytes = 0)
        }

        val ops = BaseInsertionPlanner.planBaseInsertions(listOf(baseDecl), resolveBase)

        assertTrue(ops.isEmpty(), "Zero-length bases should be skipped")
    }

    /**
     * Case 6: Mix of valid and invalid bases.
     * Expected: Only valid bases in output (1 good, 1 dangling, 1 zero-length → 1 in output).
     */
    @Test
    fun testMixedValidAndInvalidBases() {
        val goodBase =
            BaseDecl(
                type = TypeDecl.Ref(id = ghistabs.parser.TypeId(cu = 0, n = 1)),
                isVirtual = false,
                access = Access.PUBLIC,
                offsetBits = 0L,
            )
        val danglingBase =
            BaseDecl(
                type = TypeDecl.Ref(id = ghistabs.parser.TypeId(cu = 0, n = 2)),
                isVirtual = false,
                access = Access.PUBLIC,
                offsetBits = 8L,
            )
        val zeroLengthBase =
            BaseDecl(
                type = TypeDecl.Ref(id = ghistabs.parser.TypeId(cu = 0, n = 3)),
                isVirtual = false,
                access = Access.PUBLIC,
                offsetBits = 16L,
            )

        val resolveBase: (TypeDecl) -> ResolvedBase? = { typeDecl ->
            when (typeDecl) {
                is TypeDecl.Ref -> {
                    when (typeDecl.id.n) {
                        1 -> ResolvedBase("Good", 8)
                        2 -> null // Dangling
                        3 -> ResolvedBase("Empty", 0) // Zero-length
                        else -> null
                    }
                }
                else -> null
            }
        }

        val ops =
            BaseInsertionPlanner.planBaseInsertions(
                listOf(goodBase, danglingBase, zeroLengthBase),
                resolveBase,
            )

        assertEquals(1, ops.size, "Only 1 valid base should be in output")
        assertEquals("_base_Good", ops[0].fieldName)
        assertEquals("public base", ops[0].comment)
        assertEquals(0, ops[0].offsetBytes)
    }
}
