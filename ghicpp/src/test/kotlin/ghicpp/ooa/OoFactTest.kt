package ghicpp.ooa

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class OoFactTest {
    @Test
    fun `numbers are hex, strings quoted atoms, terms bare, lists bracketed`() {
        val fact = OoFact.of(
            "rTTITypeDescriptor",
            0x41a004L,
            Term("sv_401000_0"),
            ".?AVCls'3@@",
            listOf(0x418630L, 0L),
            -8L,
        )
        assertEquals("rTTITypeDescriptor(0x41a004, sv_401000_0, '.?AVCls\\'3@@', [0x418630, 0], -0x8).", "$fact")
    }

    @Test
    fun `this comes in where the ABI passes it`() {
        assertEquals(listOf("ecx", "rcx", "0", "rdi"), OoAbi.entries.map { OoFact.term(it.thisParam) })
        assertEquals(
            listOf("__thiscall", "__x64call", "__sysv32call", "__sysv64call"),
            OoAbi.entries.map {
                it.thisCall
            },
        )
    }
}
