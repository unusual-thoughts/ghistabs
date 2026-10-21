package ghistabs.integration

import ghidra.program.database.ProgramBuilder
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.ascii.AsciiCharSetRecognizer
import ghidra.util.ascii.CharSetRecognizer
import ghistabs.cBytesAt
import ghistabs.cStringAt
import ghistabs.test.mustBe
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.nio.charset.Charset

/**
 * [cStringAt] and [cBytesAt] read a NUL-terminated string no further than its length bound, and keeps it only when
 * every character is in the charset: by default ASCII, so a UTF-8 string is turned down, not mangled,
 * unless the caller decodes as UTF-8.
 */
@Tag("integration")
class CStringAtIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var builder: ProgramBuilder
    private val program get() = builder.program

    @BeforeEach
    fun setUp() {
        builder = ProgramBuilder("test", ProgramBuilder._X86)
        builder.createMemory(".data", "0x401000", 64) // nothing mapped past 0x40103f
    }

    @AfterEach
    fun tearDown() = builder.dispose()

    private fun at(
        bytes: String,
        where: String = "0x401000",
        lengths: IntRange = 1..8,
        charSet: CharSetRecognizer = AsciiCharSetRecognizer(),
        charset: Charset = Charsets.US_ASCII,
    ) = builder.setBytes(where, bytes).let { program.cStringAt(builder.addr(where), lengths, charSet, charset) }

    /** Anything printable that decoded, which is what a UTF-8 caller wants. */
    private val decoded = CharSetRecognizer { it != 0xFFFD && !Character.isISOControl(it) }

    @Test
    fun `an ASCII string up to its NUL`() = at("68 69 00 41").mustBe("hi")

    @Test
    fun `a string as long as the bound, but not one longer`() {
        at("61 62 63 64 00", lengths = 1..4).mustBe("abcd")
        at("61 62 63 64 65 00", lengths = 1..4).mustBe(null)
    }

    @Test
    fun `an empty string only when the bound allows it`() {
        at("00", lengths = 1..4).mustBe(null)
        at("00", lengths = 0..4).mustBe("")
    }

    @Test
    fun `UTF-8 is turned down by the default ASCII charset`() = at("63 61 66 c3 a9 00").mustBe(null) // "café"

    @Test
    fun `a charset that takes anything gets US-ASCII's replacement characters for UTF-8`() =
        at("63 61 66 c3 a9 00", charSet = { true }).mustBe("caf��")

    @Test
    fun `UTF-8 decodes cleanly when asked for, its bound counted in bytes`() {
        at("63 61 66 c3 a9 00", charSet = decoded, charset = Charsets.UTF_8).mustBe("café")
        at("63 61 66 c3 a9 00", lengths = 1..4, charSet = decoded, charset = Charsets.UTF_8).mustBe(null)
    }

    @Test
    fun `bytes that aren't UTF-8 are turned down rather than mangled`() =
        at("63 61 66 e9 00", charSet = decoded, charset = Charsets.UTF_8).mustBe(null) // Latin-1 "café"

    @Test
    fun `the raw bytes, NUL left off, whatever they decode to`() {
        builder.setBytes("0x401000", "63 61 66 e9 00")
        program.cBytesAt(builder.addr("0x401000"), 1..8)?.toList().mustBe(listOf<Byte>(0x63, 0x61, 0x66, 0xe9.toByte()))
        program.cBytesAt(builder.addr("0x401000"), 1..3).mustBe(null)
    }

    @Test
    fun `a run that reaches unmapped memory before any NUL`() = at("78 79 7a", where = "0x40103d").mustBe(null)

    @Test
    fun `a long run without a NUL stops at the bound`() = at("41 ".repeat(40).trim(), lengths = 1..4).mustBe(null)
}
