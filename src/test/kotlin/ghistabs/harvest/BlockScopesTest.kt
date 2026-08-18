package ghistabs.harvest

import ghistabs.GenericAddressResolver
import ghistabs.parse.StabType
import ghistabs.parse.SymbolDecl
import ghistabs.parse.TypeDecl
import ghistabs.parse.VariableLocation
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * The record stream of `unbouniaf.exe`'s `main` (records 1771-1813), where gcc inlined six
 * std::string/allocator members: one `fs` of its own, then a `this`/`__str`/`this`/`__val` per
 * expansion, each emitted immediately *before* the N_LBRAC of the block it belongs to.
 */
class BlockScopesTest {
    private var nextIndex = 1771

    private fun addr(offset: Long) = GenericAddressResolver.buildAddress(offset)

    private fun line(line: Int, offset: Long, source: String) = LineEntry(line, addr(offset), sourceFileOf(source))

    private fun BlockTreeBuilder.local(name: String, declLine: Int) = local(
        Symbol(
            recordIndex = nextIndex++,
            recordType = StabType.N_LSYM,
            body = SymbolDecl.Local(name, TypeDecl.Complex(0, 1), VariableLocation.STACK),
            rawValue = 0,
            line = declLine,
            // The trailing N_SOL gcc leaves in effect — always the CU, never the local's own file.
            sourceFile = sourceFileOf("unfile.cpp"),
        ),
    )

    private fun BlockTreeBuilder.openAt(offset: Long) = open(addr(offset)).also { nextIndex++ }

    private fun BlockTreeBuilder.closeAt(offset: Long) = close(addr(offset)).also { nextIndex++ }

    /** main's records, in stream order. */
    private fun mainBuilder() = BlockTreeBuilder().apply {
        local("fs", 89)
        openAt(0x5d)
        local("this", 664)
        openAt(0x11f)
        closeAt(0x122)
        local("__str", 953)
        openAt(0x15d)
        local("this", 665)
        openAt(0x1b2)
        closeAt(0x1b5)
        local("__val", 38)
        openAt(0x1b5)
        closeAt(0x1c2)
        closeAt(0x1de)
        closeAt(0xad2)
    }

    private val lines = listOf(
        line(75, 0x5d, "unfile.cpp"),
        line(664, 0x11f, "stl_alloc.h"),
        line(953, 0x15d, "basic_string.h"),
        line(665, 0x1b2, "stl_alloc.h"),
        line(38, 0x1b5, "atomicity.h"),
    )

    private fun names(blocks: List<BlockScope>) = blocks.map { b -> b.locals.map { it.body.name } }

    private fun flatten(blocks: List<BlockScope>): List<String> =
        blocks.flatMap { b -> b.locals.map { it.body.name } + flatten(b.children) }

    @Test
    fun `a block owns the symbols emitted before its LBRAC, not the ones between its brackets`() {
        val (_, blocks) = mainBuilder().finish(lines, sourceFileOf("unfile.cpp"))

        val root = blocks.single()
        assertEquals(listOf("fs"), root.locals.map { it.body.name })
        assertEquals(addr(0x5d) to addr(0xad2), root.start to root.end)

        assertEquals(listOf(listOf("this"), listOf("__str")), names(root.children))
        val (first, second) = root.children
        assertEquals(addr(0x11f) to addr(0x122), first.start to first.end)
        assertEquals(listOf(listOf("this"), listOf("__val")), names(second.children))
    }

    @Test
    fun `a local's source is its block's, not the N_SOL left over at the closing brace`() {
        val (locals, _) = mainBuilder().finish(lines, sourceFileOf("unfile.cpp"))

        assertEquals(
            listOf(
                "__str" to "basic_string.h",
                "__val" to "atomicity.h",
                "fs" to "unfile.cpp", // the function's own local: inherits the function
                "this" to "stl_alloc.h",
                "this" to "stl_alloc.h",
            ),
            locals.map { it.body.name to it.sourceFile.filename }.sortedBy { it.first },
        )
    }

    @Test
    fun `a block whose own code spans several files falls back to the enclosing block`() {
        // 0x11f..0x122 now covers stl_alloc.h:664 and stl_construct.h:700, so the range alone can't
        // decide — the decl line still pins it. Only a local with no line match would inherit.
        val spanning = lines + line(700, 0x120, "stl_construct.h")
        val (locals, _) = mainBuilder().finish(spanning, sourceFileOf("unfile.cpp"))

        assertEquals("stl_alloc.h", locals.first { it.line == 664 }.sourceFile.filename)
        assertEquals("unfile.cpp", locals.first { it.body.name == "fs" }.sourceFile.filename)
    }

    /**
     * gcc's `dbxout_reg_parms` emits register parameters at depth 0 without setting `did_output`, so
     * in a C++ function — whose depth-0 block never owns variables — they trail with no N_LBRAC to
     * claim them. They are still the function's.
     */
    @Test
    fun `a local no block claims belongs to the function`() {
        val (locals, blocks) = mainBuilder().apply { local("orphan", 27) }.finish(lines, sourceFileOf("unfile.cpp"))

        assertEquals("unfile.cpp", locals.single { it.body.name == "orphan" }.sourceFile.filename)
        assertEquals(false, "orphan" in flatten(blocks))
    }
}
