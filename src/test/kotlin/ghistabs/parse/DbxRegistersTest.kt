package ghistabs.parse

import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class DbxRegistersTest {
    @Test
    fun testSparcNumbersAreTheHardwareRegisters() {
        // gcc/config/sparc/aout.h maps dbx number → register number straight through: four banks of
        // eight, %g %o %l %i. 24..29 (%i0..%i5) is the whole of what SunOS cc allocates — the
        // argument window a callee sees after `save`.
        DbxArch.SPARC.registerName(0) mustBe "g0"
        DbxArch.SPARC.registerName(8) mustBe "o0"
        DbxArch.SPARC.registerName(16) mustBe "l0"
        DbxArch.SPARC.registerName(24) mustBe "i0"
        DbxArch.SPARC.registerName(29) mustBe "i5"
        // Ghidra names the two window pointers, %o6 and %i6, for their role.
        DbxArch.SPARC.registerName(14) mustBe "sp"
        DbxArch.SPARC.registerName(30) mustBe "fp"
        // %f0.. — off the end of the integer bank, deliberately unmapped.
        DbxArch.SPARC.registerName(32) mustBe null
    }

    @Test
    fun testArchPicksTheMapNotTheWidth() {
        // The number is meaningless without the architecture: 24 is %i0 on SPARC and off the end of
        // i386's eight, and both are 4-byte targets, so pointer size cannot choose between them.
        DbxArch.X86.registerName(4) mustBe "EBP"
        DbxArch.X86.registerName(24) mustBe null
        DbxArch.X86_64.registerName(4) mustBe "RSI"
    }

    @Test
    fun testX87StackIsTwelveToNineteen() {
        // i386's dbx_register_map sends gcc's fp regs 8..15 to 12..19, st(0)..st(7); 8..11 name nothing.
        // gcc345's `long double` and `float` temporaries in the libstdc++ float conversions arrive as 12.
        DbxArch.X86.registerName(12) mustBe "ST0"
        DbxArch.X86.registerName(19) mustBe "ST7"
        DbxArch.X86.registerName(8) mustBe null
        DbxArch.X86.registerName(11) mustBe null
        DbxArch.X86.registerName(20) mustBe null
        // x86_64's x87 stack sits elsewhere (33..40); no fixture keeps a local there.
        DbxArch.X86_64.registerName(12) mustBe "R12"
    }
}
