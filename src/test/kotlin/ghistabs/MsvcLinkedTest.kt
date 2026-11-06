package ghistabs

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * A MinGW PE carries no Rich header, so [loadProgram] hints it `gcc`; the same PE with one, as
 * Microsoft's `link` writes it into the DOS stub, is left the loader's own spec.
 */
class MsvcLinkedTest {
    private val mingw = File("src/test/resources/binaries/features/hello_gcc421.exe")

    @Test
    fun `a MinGW PE is not MSVC-linked`() {
        mingw.isMsvcLinked() mustBe false
    }

    @Test
    fun `a PE with a Rich header is MSVC-linked`(@TempDir dir: File) {
        val bytes = mingw.readBytes()
        val peHeader = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt(0x3c)
        richHeader().copyInto(bytes, peHeader - RICH_SIZE)
        File(dir, "linked.exe").apply { writeBytes(bytes) }.isMsvcLinked() mustBe true
    }

    // `DanS`, three zero pads and one tool record, all masked; then `Rich` and the mask in the clear.
    private fun richHeader(): ByteArray {
        val mask = 0x5a5a1234
        val masked = intArrayOf(DANS, 0, 0, 0, 0x00010000, 1).map { it xor mask }
        return ByteBuffer.allocate(RICH_SIZE).order(ByteOrder.LITTLE_ENDIAN).apply {
            masked.forEach(::putInt)
            putInt(RICH)
            putInt(mask)
        }.array()
    }

    private companion object {
        const val DANS = 0x536e6144
        const val RICH = 0x68636952
        const val RICH_SIZE = 32
    }
}
