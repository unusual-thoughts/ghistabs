package ghistabs.materialize

import ghistabs.parse.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BaseInsertionPlannerTest {
    private val cu = SourceFile.CUSource("/test")

    @Test
    fun testSinglePublicBase() {
        val baseDecl = BaseDecl(
            type = TypeDecl.Ref(id = GlobalTypeId(cu, 1)),
            isVirtual = false,
            access = Access.PUBLIC,
            offsetBits = 0L,
        )

        val resolveBase: (TypeDecl<GlobalTypeId>) -> ResolvedBase? = {
            ResolvedBase(simpleName = "Base", lengthBytes = 8)
        }

        val ops = BaseInsertionPlanner.planBaseInsertions(listOf(baseDecl), resolveBase)

        assertEquals(1, ops.size)
        val op = ops[0]
        assertEquals(0, op.offsetBytes)
        assertEquals("_base_Base", op.fieldName)
        assertEquals("public base", op.comment)
        assertEquals("Base", op.baseSimpleName)
    }

    @Test
    fun testMultipleBasesOutOfOrder() {
        val base1 = BaseDecl(
            type = TypeDecl.Ref(id = GlobalTypeId(cu, 1)),
            isVirtual = false,
            access = Access.PUBLIC,
            offsetBits = 64L,
        )
        val base0 = BaseDecl(
            type = TypeDecl.Ref(id = GlobalTypeId(cu, 2)),
            isVirtual = false,
            access = Access.PUBLIC,
            offsetBits = 0L,
        )

        val resolveBase: (TypeDecl<GlobalTypeId>) -> ResolvedBase? = { typeDecl ->
            when (typeDecl) {
                is TypeDecl.Ref -> if (typeDecl.id.n == 1) ResolvedBase("Base1", 8) else ResolvedBase("Base0", 8)
                else -> null
            }
        }

        val ops = BaseInsertionPlanner.planBaseInsertions(listOf(base1, base0), resolveBase)

        assertEquals(2, ops.size)
        assertEquals(0, ops[0].offsetBytes)
        assertEquals("_base_Base0", ops[0].fieldName)
        assertEquals("public base", ops[0].comment)
        assertEquals(8, ops[1].offsetBytes)
        assertEquals("_base_Base1", ops[1].fieldName)
        assertEquals("public base", ops[1].comment)
    }

    @Test
    fun testVirtualProtectedBase() {
        val baseDecl = BaseDecl(
            type = TypeDecl.Ref(id = GlobalTypeId(cu, 5)),
            isVirtual = true,
            access = Access.PROTECTED,
            offsetBits = 0L,
        )

        val resolveBase: (TypeDecl<GlobalTypeId>) -> ResolvedBase? = {
            ResolvedBase(simpleName = "VBase", lengthBytes = 16)
        }

        val ops = BaseInsertionPlanner.planBaseInsertions(listOf(baseDecl), resolveBase)

        assertEquals(1, ops.size)
        assertEquals("_vbase_VBase", ops[0].fieldName)
        assertEquals("protected virtual base", ops[0].comment)
    }

    @Test
    fun testDanglingBaseRef() {
        val baseDecl = BaseDecl(
            type = TypeDecl.Ref(id = GlobalTypeId(cu, 10)),
            isVirtual = false,
            access = Access.PUBLIC,
            offsetBits = 0L,
        )

        val resolveBase: (TypeDecl<GlobalTypeId>) -> ResolvedBase? = { null }

        val ops = BaseInsertionPlanner.planBaseInsertions(listOf(baseDecl), resolveBase)

        assertTrue(ops.isEmpty())
    }

    @Test
    fun testZeroLengthBase() {
        val baseDecl = BaseDecl(
            type = TypeDecl.Ref(id = GlobalTypeId(cu, 15)),
            isVirtual = false,
            access = Access.PUBLIC,
            offsetBits = 0L,
        )

        val resolveBase: (TypeDecl<GlobalTypeId>) -> ResolvedBase? = {
            ResolvedBase(simpleName = "EmptyBase", lengthBytes = 0)
        }

        val ops = BaseInsertionPlanner.planBaseInsertions(listOf(baseDecl), resolveBase)

        assertTrue(ops.isEmpty())
    }

    @Test
    fun testMixedValidAndInvalidBases() {
        val goodBase =
            BaseDecl(
                type = TypeDecl.Ref(id = GlobalTypeId(cu, 1)),
                isVirtual = false,
                access = Access.PUBLIC,
                offsetBits = 0L,
            )
        val danglingBase =
            BaseDecl(
                type = TypeDecl.Ref(id = GlobalTypeId(cu, 2)),
                isVirtual = false,
                access = Access.PUBLIC,
                offsetBits = 8L,
            )
        val zeroLengthBase =
            BaseDecl(
                type = TypeDecl.Ref(id = GlobalTypeId(cu, 3)),
                isVirtual = false,
                access = Access.PUBLIC,
                offsetBits = 16L,
            )

        val resolveBase: (TypeDecl<GlobalTypeId>) -> ResolvedBase? = { typeDecl ->
            when (typeDecl) {
                is TypeDecl.Ref -> when (typeDecl.id.n) {
                    1 -> ResolvedBase("Good", 8)
                    2 -> null
                    3 -> ResolvedBase("Empty", 0)
                    else -> null
                }

                else -> null
            }
        }

        val ops = BaseInsertionPlanner.planBaseInsertions(listOf(goodBase, danglingBase, zeroLengthBase), resolveBase)

        assertEquals(1, ops.size)
        assertEquals("_base_Good", ops[0].fieldName)
        assertEquals("public base", ops[0].comment)
        assertEquals(0, ops[0].offsetBytes)
    }
}
