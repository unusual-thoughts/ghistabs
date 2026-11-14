package ghicpp.hierarchy

import ghidra.program.model.symbol.SourceType
import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class PickOverrideTest {
    private fun rank(
        source: SourceType = SourceType.ANALYSIS,
        signature: String = "int(A*)",
        hops: Int = 1,
        cls: String = "B",
    ) = OverrideRank(source, signature, hops, cls)

    @Test
    fun `the surest signature source wins over every other rank`() {
        pickOverride(listOf(rank(), rank(), rank(SourceType.IMPORTED, "void(A*)", hops = 3, cls = "Z"))) mustBe 2
    }

    @Test
    fun `then the signature most overrides share`() {
        pickOverride(listOf(rank(signature = "void(A*)", cls = "A"), rank(hops = 2), rank(hops = 3))) mustBe 1
    }

    @Test
    fun `then the nearest, then the first class by name`() {
        pickOverride(listOf(rank(hops = 2, cls = "A"), rank(cls = "Y"), rank(cls = "X"))) mustBe 2
    }
}
