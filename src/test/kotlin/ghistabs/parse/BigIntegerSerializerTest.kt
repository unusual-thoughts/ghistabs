package ghistabs.parse

import ghidrakt.test.mustBe
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test
import java.math.BigInteger

class BigIntegerSerializerTest {
    @Test
    fun `a BigInteger reads back as written, past a Long too`() {
        for (n in listOf(BigInteger.ZERO, BigInteger.valueOf(-42), BigInteger.TWO.pow(64) - BigInteger.ONE)) {
            val text = Json.encodeToString(BigIntegerSerializer, n)
            text mustBe n.toString()
            Json.decodeFromString(BigIntegerSerializer, text) mustBe n
        }
    }
}
