package ghistabs.parse

import ghistabs.test.longRange
import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/** What the parser reads past without modelling is noted in [ParseResult.Ok.skipped], not dropped silently. */
class ParserSkippedTest {
    private fun skipped(stab: String) = when (val res = Parser(stab).parseSymbol()) {
        is ParseResult.Ok -> res.skipped.map { it.substringBefore(" at +") }
        is ParseResult.Error -> error("$stab: ${res.ex.message}")
    }

    @Test
    fun `a size attribute is modelled, others are noted`() {
        skipped("b:t(0,21)=@a8;@s8;@P;-16") mustBe listOf("type attribute `@a8;`", "type attribute `@P;`")
        skipped("b:t(0,21)=@sx;-16") mustBe listOf("type attribute `@sx;`")
    }

    @Test
    fun `a non-integral constant is noted as 0`() {
        skipped("pi:c=r3.14;") mustBe listOf("constant form `r`, read as 0")
    }

    @Test
    fun `an unknown access or virtuality is noted`() {
        skipped("D:T(0,1)=s4!1,x20,(0,2);;") mustBe listOf("base virtuality `x`, read as non-virtual")
        skipped("S:T(0,1)=s4x:/9(0,2),0,32;;") mustBe listOf("access `9`, read as public")
    }

    @Test
    fun `an unknown method qualifier or kind is noted`() {
        skipped("A:T(0,1)=s4f::(0,2)=#(0,1),(0,3),(0,1);:_ZN1A1fEv;2E.;;") mustBe
            listOf("method qualifier `E`, read as none")
        skipped("A:T(0,1)=s4f::(0,2)=#(0,1),(0,3),(0,1);:_ZN1A1fEv;2A;;") mustBe
            listOf("no method kind before `;`, read as normal")
    }

    /** gcc's inline sizetype base is the only definition of its id, so the range keeps it. */
    @Test
    fun `an inline range base is kept, not skipped`() {
        val stab = "c:t(0,1)=r(0,2)=r(0,2);0;127;;0;1;"
        skipped(stab) mustBe emptyList()
        val range = Parser(stab).parseSymbol().mustBeOk().type as TypeDecl.Range
        range.inner mustBe TypeDecl.InlineDef(LocalTypeId(0, 2), longRange(LocalTypeId(0, 2), 0, 127))
    }
}
