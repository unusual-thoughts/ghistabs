package ghistabs.materialize.cpp

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/**
 * [virtualBaseOffsets] places virtual bases after the non-virtual data, and the stab's complete size is
 * the only check it has: sizes and alignments below are `(size, alignment)` pairs, in bytes.
 */
class VirtualBaseOffsetsTest {
    /** `hello.cc`'s `Diamond` on i386: 32 bytes of Left, Right, Named and `d`, then `Base` once. */
    @Test
    fun `the diamond's one virtual base follows the non-virtual data`() {
        virtualBaseOffsets(nvEnd = 32, nvAlign = 4, vbases = listOf(4 to 4), completeSize = 36) mustBe listOf(32)
    }

    @Test
    fun `each virtual base starts at the next offset its alignment allows`() {
        virtualBaseOffsets(nvEnd = 5, nvAlign = 1, vbases = listOf(2 to 2, 8 to 8), completeSize = 16) mustBe
            listOf(6, 8)
    }

    @Test
    fun `the complete object rounds up to its strictest alignment`() {
        virtualBaseOffsets(nvEnd = 9, nvAlign = 4, vbases = listOf(1 to 1), completeSize = 12) mustBe listOf(9)
    }

    @Test
    fun `no virtual base places nothing, as long as the size agrees`() {
        virtualBaseOffsets(nvEnd = 8, nvAlign = 4, vbases = emptyList(), completeSize = 8) mustBe emptyList()
    }

    /** A layout that is not the compiler's: a nearly-empty primary virtual base shares the vptr's bytes. */
    @Test
    fun `a layout that misses the stated size is none`() {
        virtualBaseOffsets(nvEnd = 32, nvAlign = 4, vbases = listOf(4 to 4), completeSize = 40) mustBe null
        virtualBaseOffsets(nvEnd = 8, nvAlign = 4, vbases = listOf(4 to 4), completeSize = 8) mustBe null
    }
}
