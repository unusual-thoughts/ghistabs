package ghistabs.harvest

import ghidra.program.model.address.AddressRangeImpl
import ghidrakt.DetachedAddresses
import ghidrakt.test.mustBe
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test

class AddressRangeSerializerTest {
    @Test
    fun `a range reads back as written, a named space's ends too`() {
        for (range in listOf(
            AddressRangeImpl(DetachedAddresses.at(0x401000), DetachedAddresses.at(0x4010ff)),
            AddressRangeImpl(DetachedAddresses.at(1, "EXTERNAL"), DetachedAddresses.at(4, "EXTERNAL")),
        )) {
            val text = Json.encodeToString(AddressRangeSerializer(), range)
            Json.decodeFromString(AddressRangeSerializer(), text) mustBe range
        }
        Json.encodeToString(
            AddressRangeSerializer(),
            AddressRangeImpl(DetachedAddresses.at(0x401000), DetachedAddresses.at(0x4010ff)),
        ) mustBe "\"00401000-004010ff\""
    }
}
