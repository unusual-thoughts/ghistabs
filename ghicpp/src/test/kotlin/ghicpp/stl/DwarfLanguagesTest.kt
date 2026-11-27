package ghicpp.stl

import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

class DwarfLanguagesTest {
    /** One compile unit DIE's abbreviation: producer (strp), language ([languageForm]), name (string). */
    private fun abbrev(languageForm: Int) = bytes(1, 0x11, 0, 0x25, 0x0e, 0x13, languageForm, 0x03, 0x08, 0, 0, 0)

    private fun bytes(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }

    /** A unit of [version] whose DIE gives [language] in [size] bytes. */
    private fun unit(version: Int, language: Int, size: Int): ByteArray {
        val body = ByteArrayOutputStream()
        fun le(value: Long, n: Int) = repeat(n) { body.write((value shr (8 * it)).toInt() and 0xff) }
        le(version.toLong(), 2)
        if (version == 5) {
            body.write(1)
            body.write(4)
            le(0, 4)
        } else {
            le(0, 4)
            body.write(4)
        }
        body.write(1)
        le(0x10, 4)
        le(language.toLong(), size)
        body.write('a'.code)
        body.write(0)
        val out = ByteBuffer.allocate(4 + body.size()).order(ByteOrder.LITTLE_ENDIAN)
        out.putInt(body.size())
        out.put(body.toByteArray())
        return out.array()
    }

    @Test
    fun `each unit's language, in DWARF 2 to 5`() {
        DwarfLanguages.of(unit(2, 0x01, 1), abbrev(0x0b), ByteOrder.LITTLE_ENDIAN) mustBe listOf(0x01)
        DwarfLanguages.of(unit(4, 0x04, 1) + unit(3, 0x1a, 1), abbrev(0x0b), ByteOrder.LITTLE_ENDIAN) mustBe
            listOf(0x04, 0x1a)
        DwarfLanguages.of(unit(5, 0x8001, 2), abbrev(0x05), ByteOrder.LITTLE_ENDIAN) mustBe listOf(0x8001)
    }

    @Test
    fun `a unit it cannot read gives no answer`() {
        DwarfLanguages.of(unit(6, 0x04, 1), abbrev(0x0b), ByteOrder.LITTLE_ENDIAN) mustBe null
        DwarfLanguages.of(unit(4, 0x04, 1), bytes(1, 0x11, 0, 0x13, 0x7e, 0, 0, 0), ByteOrder.LITTLE_ENDIAN) mustBe
            null
    }
}
