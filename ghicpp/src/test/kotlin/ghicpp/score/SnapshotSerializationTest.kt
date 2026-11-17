package ghicpp.score

import ghidrakt.DetachedAddresses
import ghidrakt.test.mustBe
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test
import java.io.File
import java.util.zip.GZIPInputStream

/** A class view holds Ghidra addresses, yet is written out and read back with no program open: the truth files. */
class SnapshotSerializationTest {
    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun `every committed truth file reads back and writes out as committed`() {
        val files = File("src/test/resources/ghicpp/scorecard/truth").listFiles { f -> f.name.endsWith(".json.gz") }
        files.isNullOrEmpty() mustBe false
        for (file in files!!) {
            val text = GZIPInputStream(file.inputStream()).bufferedReader().use { it.readText() }.trimEnd()
            val truth = json.decodeFromString(TruthFile.serializer(), text)
            json.encodeToString(TruthFile.serializer(), truth) mustBe text
        }
    }

    @Test
    fun `an address reads back as Ghidra prints it, its space named unless the default`() {
        for (text in listOf("00401000", "EXTERNAL:00000001", "ffffffff80001000")) {
            DetachedAddresses.parse(text).toString() mustBe text
        }
        DetachedAddresses.parse("00401000") mustBe DetachedAddresses.at(0x401000)
        (DetachedAddresses.parse("EXTERNAL:00401000") == DetachedAddresses.at(0x401000)) mustBe false
    }
}
