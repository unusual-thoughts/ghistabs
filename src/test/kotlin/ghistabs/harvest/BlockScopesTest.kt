package ghistabs.harvest

import ghidra.program.model.address.AddressSpace
import ghistabs.parse.StabType
import ghistabs.parse.SymbolDecl
import ghistabs.parse.TypeDecl
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * The record stream of `unbouniaf.exe`'s `main` (records 1771-1813), where gcc inlined six
 * std::string/allocator members: one `fs` of its own, then a `this`/`__str`/`this`/`__val` per
 * expansion, each emitted immediately *before* the N_LBRAC of the block it belongs to.
 */
class BlockScopesTest {
    private fun local(index: Int, name: String, line: Int) = SymbolRecord(
        recordIndex = index,
        recordType = StabType.N_LSYM,
        body = SymbolDecl.StackLocal(name, TypeDecl.Complex(0, 1)),
        rawValue = 0,
        declLine = line,
        sourceFile = "unfile.cpp", // the trailing N_SOL gcc leaves in effect — always this, never useful
    )

    private fun addr(offset: Long) = AddressSpace.OTHER_SPACE.getAddress(offset)

    private fun line(line: Int, offset: Long, source: String) = LineEntry(line, addr(offset), source)

    private fun bracket(type: StabType, offset: Long, index: Int) = Bracket(type, addr(offset), index)

    private val brackets = listOf(
        bracket(StabType.N_LBRAC, 0x5d, 1772),
        bracket(StabType.N_LBRAC, 0x11f, 1774),
        bracket(StabType.N_RBRAC, 0x122, 1775),
        bracket(StabType.N_LBRAC, 0x15d, 1777),
        bracket(StabType.N_LBRAC, 0x1b2, 1779),
        bracket(StabType.N_RBRAC, 0x1b5, 1780),
        bracket(StabType.N_LBRAC, 0x1b5, 1782),
        bracket(StabType.N_RBRAC, 0x1c2, 1783),
        bracket(StabType.N_RBRAC, 0x1de, 1784),
        bracket(StabType.N_RBRAC, 0xad2, 1813),
    )

    private val locals = listOf(
        local(1771, "fs", 89),
        local(1773, "this", 664),
        local(1776, "__str", 953),
        local(1778, "this", 665),
        local(1781, "__val", 38),
    )

    private val lines = listOf(
        line(75, 0x5d, "unfile.cpp"),
        line(664, 0x11f, "stl_alloc.h"),
        line(953, 0x15d, "basic_string.h"),
        line(665, 0x1b2, "stl_alloc.h"),
        line(38, 0x1b5, "atomicity.h"),
    )

    @Test
    fun `a block owns the symbols emitted before its LBRAC, not the ones between its brackets`() {
        val root = buildBlocks(brackets, locals).single()

        assertEquals(listOf("fs"), root.locals.map { it.body.name })
        assertEquals(addr(0x5d) to addr(0xad2), root.start to root.end)

        val (first, second) = root.children
        assertEquals(listOf("this"), first.locals.map { it.body.name })
        assertEquals(addr(0x11f) to addr(0x122), first.start to first.end)
        assertEquals(listOf("__str"), second.locals.map { it.body.name })
        assertEquals(
            listOf(listOf("this"), listOf("__val")),
            second.children.map { c ->
                c.locals.map { it.body.name }
            },
        )
    }

    @Test
    fun `a local's source is its block's, not the N_SOL left over at the closing brace`() {
        val sources = buildBlocks(brackets, locals).attributedSources(lines, "unfile.cpp")

        assertEquals(
            mapOf(
                1771 to "unfile.cpp", // the function's own local: inherits the function
                1773 to "stl_alloc.h",
                1776 to "basic_string.h",
                1778 to "stl_alloc.h",
                1781 to "atomicity.h",
            ),
            sources,
        )
    }

    @Test
    fun `a block whose own code spans several files falls back to the enclosing block`() {
        val spanning = lines + line(700, 0x120, "stl_construct.h")
        val sources = buildBlocks(brackets, locals).attributedSources(spanning, "unfile.cpp")

        // 0x11f..0x122 now covers stl_alloc.h:664 and stl_construct.h:700 — the decl line still
        // pins it, so only a local with no line match would inherit.
        assertEquals("stl_alloc.h", sources[1773])
        assertEquals("unfile.cpp", sources[1771])
    }
}
