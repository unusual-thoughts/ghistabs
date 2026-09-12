package ghistabs.materialize

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/**
 * [splitAround] is the whole of what `SPLIT_BASE` does to a base subobject, and the two ABIs land on
 * opposite edges of it: Itanium puts the vptr at the base's front, gcc 2.x after the base's fields.
 */
class BaseSplitTest {
    @Test
    fun `vptr at the front leaves a tail only`() {
        splitAround(baseLength = 16, vptrInBase = 0, ptrSize = 4) mustBe BaseSplit(null, Run(4, 16))
    }

    @Test
    fun `vptr after the fields leaves a head only`() {
        splitAround(baseLength = 16, vptrInBase = 12, ptrSize = 4) mustBe BaseSplit(Run(0, 12), null)
    }

    @Test
    fun `vptr in the middle leaves both runs`() {
        splitAround(baseLength = 16, vptrInBase = 8, ptrSize = 4) mustBe BaseSplit(Run(0, 8), Run(12, 16))
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
        splitAround(baseLength = 24, vptrInBase = 8, ptrSize = 8) mustBe BaseSplit(Run(0, 8), Run(16, 24))
    }
}
