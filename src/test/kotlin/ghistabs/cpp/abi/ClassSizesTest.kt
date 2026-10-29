package ghistabs.cpp.abi

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

class ClassSizesTest {
    @Test
    fun `a class is at least as large as its last vptr and its bases reach`() {
        // class D : B, S with S at 0x58; B and S each a vptr and nothing known past it
        val bounds = sizeBounds(
            bases = mapOf("D" to listOf("B" to 0L, "S" to 0x58L)),
            vptrs = mapOf("B" to 0L, "S" to 0L, "D" to 0x58L),
            allocated = emptyMap(),
            ptrSize = 4,
        )
        bounds.getValue("D") mustBe 0x5cL..Long.MAX_VALUE
        // B ends where S starts
        bounds.getValue("B") mustBe 4L..0x58L
    }

    @Test
    fun `new says a class's size, which bounds its last base`() {
        val bounds = sizeBounds(
            bases = mapOf("D" to listOf("B" to 0L, "S" to 0x58L)),
            vptrs = mapOf("S" to 0L),
            allocated = mapOf("D" to 0x7cL),
            ptrSize = 4,
        )
        bounds.getValue("D") mustBe 0x7cL..0x7cL
        bounds.getValue("S").last mustBe 0x24
    }

    @Test
    fun `bounds that meet are the size`() {
        // B has a vptr and an int, and D's second base starts right after it
        val bounds = sizeBounds(
            bases = mapOf("D" to listOf("B" to 0L, "S" to 8L), "B" to listOf("A" to 0L)),
            vptrs = mapOf("A" to 0L, "B" to 4L),
            allocated = emptyMap(),
            ptrSize = 4,
        )
        bounds.getValue("B") mustBe 8L..8L
        bounds.getValue("A").last mustBe 8
    }
}
