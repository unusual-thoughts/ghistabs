package ghicpp

import ghidra.program.model.data.IntegerDataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.StructureDataType
import ghidra.program.model.gclass.ClassUtils
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

/**
 * [splitAround] is the whole of what `SPLIT_BASE` does to a base subobject, and the two ABIs land on
 * opposite edges of it: Itanium puts the vptr at the base's front, gcc 2.x after the base's fields.
 */
class BaseSplitTest {
    @Test
    fun `vptr at the front leaves a tail only`() {
        splitAround(baseLength = 16, vptrInBase = 0, ptrSize = 4) mustBe BaseSplit(null, 4..<16)
    }

    @Test
    fun `vptr after the fields leaves a head only`() {
        splitAround(baseLength = 16, vptrInBase = 12, ptrSize = 4) mustBe BaseSplit(0..<12, null)
    }

    @Test
    fun `vptr in the middle leaves both runs`() {
        splitAround(baseLength = 16, vptrInBase = 8, ptrSize = 4) mustBe BaseSplit(0..<8, 12..<16)
    }

    /** A base that is nothing but its vptr has no fields to re-embed, so there is no split to make. */
    @Test
    fun `a base the size of the pointer splits into nothing`() {
        splitAround(baseLength = 4, vptrInBase = 0, ptrSize = 4) mustBe null
    }

    /** The offset is derived by subtraction when the base carries no `{vfptr}` of its own, so it can
     *  land outside the base entirely; the runs would otherwise be read off the following bytes. */
    @Test
    fun `a pointer that does not fit inside the base is no split`() {
        splitAround(baseLength = 16, vptrInBase = 14, ptrSize = 4) mustBe null
        splitAround(baseLength = 16, vptrInBase = -4, ptrSize = 4) mustBe null
        splitAround(baseLength = 16, vptrInBase = 16, ptrSize = 4) mustBe null
    }

    /** 64-bit moves the boundary the vptr sits on, so the runs follow the pointer width. */
    @Test
    fun `run bounds follow the pointer width`() {
        splitAround(baseLength = 24, vptrInBase = 8, ptrSize = 8) mustBe BaseSplit(0..<8, 16..<24)
    }

    private val vfptr = PointerDataType(IntegerDataType.dataType, 4)

    /**
     * MSVC's `RunFunctionTaskBase<T>` holds its first vptr in its first base, `QFutureInterface<T>`, and has a
     * `{vfptr}` of its own past it, for `QRunnable`: a deriving class's vptr at +0 is the base's at +0.
     */
    @Test
    fun `a vptr in a base of the base is where the deriving class says, not the base's own vfptr`() {
        val first = StructureDataType("QFutureInterface", 4).apply {
            replaceAtOffset(0, vfptr, 4, ClassUtils.VFPTR, null)
        }
        val base = StructureDataType("RunFunctionTaskBase", 16).apply {
            replaceAtOffset(0, first, 4, "${ClassNaming.BASE_PREFIX}QFutureInterface", null)
            replaceAtOffset(8, vfptr, 4, ClassUtils.VFPTR, null)
            replaceAtOffset(12, IntegerDataType.dataType, 4, "own", null)
        }
        vptrInBase(base, expected = 0) mustBe 0
        vptrInBase(base, expected = 8) mustBe 8
    }

    /** gcc 2.x appends a base's vptr after its fields, which the deriving class may not say. */
    @Test
    fun `a base with no vfptr where the deriving class says has its vptr at its own vfptr`() {
        val base = StructureDataType("TiXmlBase", 12).apply {
            replaceAtOffset(0, IntegerDataType.dataType, 4, "location", null)
            replaceAtOffset(8, vfptr, 4, ClassUtils.VFPTR, null)
        }
        vptrInBase(base, expected = 0) mustBe 8
        vptrInBase(StructureDataType("Plain", 8), expected = 4) mustBe 4
    }
}
