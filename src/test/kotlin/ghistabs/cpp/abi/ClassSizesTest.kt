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
        bounds.getValue("D") mustBe SizeBounds(atLeast = 0x5c, atMost = null, exact = null)
        // B ends where S starts
        bounds.getValue("B") mustBe SizeBounds(atLeast = 4, atMost = 0x58, exact = null)
    }

    @Test
    fun `new says a class's size, which bounds its last base`() {
        val bounds = sizeBounds(
            bases = mapOf("D" to listOf("B" to 0L, "S" to 0x58L)),
            vptrs = mapOf("S" to 0L),
            allocated = mapOf("D" to 0x7cL),
            ptrSize = 4,
        )
        bounds.getValue("D").size mustBe 0x7c
        bounds.getValue("S").atMost mustBe 0x24
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
        bounds.getValue("B").exact mustBe 8
        bounds.getValue("A").atMost mustBe 8
    }
}
