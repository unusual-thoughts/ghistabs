package ghistabs.render

import ghistabs.harvest.Func
import ghistabs.harvest.LineEntry
import ghistabs.harvest.sourceFileOf
import ghistabs.parse.FunctionScope
import ghistabs.parse.SourceFile
import ghistabs.parse.SymbolDecl
import ghistabs.parse.TypeDecl
import ghistabs.test.GenericAddressResolver
import ghistabs.test.mustBe
import ghistabs.test.mustBeEmpty
import org.junit.jupiter.api.Test

/**
 * Pure-unit coverage of the two things a `{` vs `}` count per file cannot see: a run that balances
 * while nesting wrongly, and a function whose rendered close is not on the line its span puts it on.
 */
class NestingTest {
    // Rows as their brace tokens, which is what the run is fed: `""` is a row with no braces.
    private fun fix(vararg rows: String) = braceFix(rows.asSequence().flatMap { it.asSequence() })

    @Test
    fun `a balanced run still needs braces when its nesting dips`() {
        fix("}{") mustBe (1 to 1)
        fix("}}", "", "{{") mustBe (2 to 2)
        fix("{", "", "}") mustBe (0 to 0)
    }

    @Test
    fun `an unbalanced run is closed or opened at the end that is short`() {
        fix("{", "{") mustBe (0 to 2)
        fix("", "}", "}") mustBe (2 to 0)
    }

    // `Integer::IsConvertableToLong`: `if (sign == POSITIVE) {` anchored at L2805, both of its
    // branches at L2803. Placed at their anchors the branches render outside the block.
    @Test
    fun `a block's contents are held below its opener`() {
        nestingRows(listOf(2799, 2805, 2803, 2803), floor = 2798) mustBe listOf(2799, 2805, 2805, 2805)
    }

    // A sibling block anchored earlier than the one before it would sort above the lot and wrap it —
    // balanced, never negative, clauses inverted. Only a total order rules that out.
    @Test
    fun `a sibling block cannot rise above the block before it`() {
        nestingRows(listOf(100, 101, 102, 50), floor = 99) mustBe listOf(100, 101, 102, 102)
    }

    // An anchorless region rides whatever came before it rather than resetting the floor.
    @Test
    fun `a null anchor neither moves the floor nor is placed`() {
        nestingRows(listOf(100, null, 40), floor = 99) mustBe listOf(100, 100, 100)
    }

    private fun fn(name: String, base: Long, lines: List<Int>) = Func(
        name = name,
        addr = GenericAddressResolver.buildAddress(base),
        decl = SymbolDecl.Function(name, FunctionScope.GLOBAL, TypeDecl.Builtin(-1)),
        cu = SourceFile.CUSource("s.cpp"),
        lineEntries = lines.mapIndexed { i, l ->
            LineEntry(l, GenericAddressResolver.buildAddress(base + i), sourceFileOf("s.cpp"))
        }
            .toMutableList(),
    )

    private fun spansOf() = FunctionSpans.of(
        listOf(fn("a", 0x1000, listOf(2, 3)), fn("b", 0x2000, listOf(6, 7))),
        sourceFileOf("s.cpp"),
    )

    // `a` spans L2..L3 and closes on L4; `b` opens on L6. Rendering a's close past L6 puts b inside
    // it — the shape image.cpp's swallowed accessors had, with every brace count balancing.
    @Test
    fun `a function still open where the next one opens is reported`() {
        val rows = listOf("", "void a() {", "  x();", "  y();", "", "void b() {", "  z();", "}", "}")

        spansOf().closeAnomalies(rows) mustBe listOf(
            "function a opens at L2 and is still open where the next one opens at L6 (span says it closes at L4)",
        )
    }

    // A body that borrows a row below its span, and one crammed onto its opener, are both within
    // the slack the layout grants — neither reaches the next opener.
    @Test
    fun `closes short of the next opener report nothing`() {
        val late = listOf("", "void a() {", "  x();", "  y();", "}", "void b() {", "  z();", "}")
        val crammed = listOf("", "void a() { x(); }", "", "", "", "void b() {", "  z();", "}")

        spansOf().closeAnomalies(late).mustBeEmpty()
        spansOf().closeAnomalies(crammed).mustBeEmpty()
    }
}
