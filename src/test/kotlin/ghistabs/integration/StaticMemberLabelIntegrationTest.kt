package ghistabs.integration

import ghidra.program.model.listing.Program
import ghistabs.test.*
import org.junit.jupiter.api.Tag
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

/**
 * A gcc 2.x static data member is labelled `Class::member`, not by its linkage name. Its symbol is
 * `_5Shape.count` (`_<len><Class>.<member>`, `$` for `.` on a.out), which Ghidra's demangler analyzer
 * never names; left to the stab, the label is that raw string and every decompiled use reads it.
 */
@Tag("integration")
class StaticMemberLabelIntegrationTest : FeatureFixtureTest() {
    @ParameterizedTest
    @ValueSource(strings = ["hello_elf_gcc295", "hello_elf_gcc272"])
    fun `a static data member is labelled Class member`(fixture: String) {
        load(fixture)
        program.mustHaveNoGcc2StaticMemberPrimary()

        val count = program.symbolTable.getSymbols("count").filter { it.parentNamespace.name == "Shape" }
        count.must("no Shape::count label") { isNotEmpty() }
        count.first().must("Shape::count is not primary") { isPrimary }
    }

    companion object {
        private val GCC2_STATIC_MEMBER = Regex("""^_[0-9]+[A-Za-z_].*[.$]""")

        fun Program.mustHaveNoGcc2StaticMemberPrimary() {
            val raw = symbolTable.getSymbolIterator(true).iterator().asSequence()
                .filter { it.isPrimary && GCC2_STATIC_MEMBER.containsMatchIn(it.name) }
                .map { "${it.address} ${it.name}" }
                .toList()
            raw.take(10).mustBeEmpty("${raw.size} static members keep their gcc 2.x linkage name as primary")
        }
    }
}
