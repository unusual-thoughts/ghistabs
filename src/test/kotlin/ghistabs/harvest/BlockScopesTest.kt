package ghistabs.harvest

import ghistabs.diagnose.CapturingSink
import ghistabs.diagnose.Level
import ghistabs.parse.StabType
import ghistabs.parse.SymbolDecl
import ghistabs.parse.TypeDecl
import ghistabs.parse.VariableLocation
import ghistabs.test.GenericAddressResolver
import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/**
 * The record stream of a `main` (records 1771-1813) where gcc inlined six
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
            sourceFile = sourceFileOf("main.cpp"),
        ),
    )

    // gcc leaves the bracket's `n_desc` at 0, so `main` below passes no level anywhere.
    private fun BlockTreeBuilder.openAt(offset: Long, level: Int? = null) =
        open(addr(offset), level).also { nextIndex++ }

    private fun BlockTreeBuilder.closeAt(offset: Long, level: Int? = null) =
        close(addr(offset), level).also { nextIndex++ }

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
        line(75, 0x5d, "main.cpp"),
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
        val (_, blocks) = mainBuilder().finish(lines, sourceFileOf("main.cpp"))

        val root = blocks.single()
        root.locals.map { it.body.name } mustBe listOf("fs")
        (root.start to root.end) mustBe (addr(0x5d) to addr(0xad2))

        names(root.children) mustBe listOf(listOf("this"), listOf("__str"))
        val (first, second) = root.children
        (first.start to first.end) mustBe (addr(0x11f) to addr(0x122))
        names(second.children) mustBe listOf(listOf("this"), listOf("__val"))
    }

    @Test
    fun `a local's source is its block's, not the N_SOL left over at the closing brace`() {
        val (locals, _) = mainBuilder().finish(lines, sourceFileOf("main.cpp"))

        locals.map { it.body.name to it.sourceFile.filename }.sortedBy { it.first } mustBe listOf(
            "__str" to "basic_string.h",
            "__val" to "atomicity.h",
            "fs" to "main.cpp", // the function's own local: inherits the function
            "this" to "stl_alloc.h",
            "this" to "stl_alloc.h",
        )
    }

    @Test
    fun `a block whose own code spans several files falls back to the enclosing block`() {
        // 0x11f..0x122 now covers stl_alloc.h:664 and stl_construct.h:700, so the range alone can't
        // decide — the decl line still pins it. Only a local with no line match would inherit.
        val spanning = lines + line(700, 0x120, "stl_construct.h")
        val (locals, _) = mainBuilder().finish(spanning, sourceFileOf("main.cpp"))

        locals.first { it.line == 664 }.sourceFile.filename mustBe "stl_alloc.h"
        locals.first { it.body.name == "fs" }.sourceFile.filename mustBe "main.cpp"
    }

    /**
     * Sun's C compiler numbers lexical depth in each bracket's `n_desc` — 2 for a function's outermost
     * block, and it counts scopes that emitted no brackets, so the number runs ahead of the pairing
     * depth (sibling blocks at level 5 where pairing says 3, in `graphcnv.SUN4`'s `wpsio.c`). The
     * emitter knowing more than us is worth a note, not a correction: the tree comes from pairing and
     * the level must not perturb it.
     *
     * Levels are read relative to the function's first bracket. Absolutely, Sun's base of 2 differs
     * from our depth of 0 at *every* bracket — 513 of 513 on that binary, which reports nothing.
     */
    @Test
    fun `a level running ahead of the pairing depth is noted, not corrected`() {
        val sink = CapturingSink()
        val (_, blocks) = BlockTreeBuilder(sink).apply {
            local("path", 4)
            openAt(0x14, level = 2)
            local("i", 7)
            openAt(0x30, level = 5)
            closeAt(0x44, level = 5)
            closeAt(0x48, level = 2)
        }.finish(emptyList(), sourceFileOf("otpth.c"))

        val root = blocks.single()
        names(root.children) mustBe listOf(listOf("i"))
        // The outer bracket sets the base and is silent; only the level-5 jump is reported.
        sink.lines.map { it.tag to it.level } mustBe listOf("bracket-level-depth" to Level.DEBUG)
    }

    /** The base is per function, so a nesting that tracks it is silent whatever the emitter counts from. */
    @Test
    fun `levels that track the pairing depth report nothing`() {
        val sink = CapturingSink()
        BlockTreeBuilder(sink).apply {
            openAt(0x14, level = 2)
            openAt(0x30, level = 3)
            closeAt(0x44, level = 3)
            closeAt(0x48, level = 2)
        }.finish(emptyList(), sourceFileOf("otpth.c"))

        sink.lines.map { it.tag } mustBe emptyList()
    }

    /** Levels that cross mean this N_RBRAC closes a scope its author didn't think was innermost. */
    @Test
    fun `an RBRAC closing a level it did not open is reported`() {
        val sink = CapturingSink()
        BlockTreeBuilder(sink).apply {
            openAt(0x14, level = 2)
            openAt(0x30, level = 3)
            closeAt(0x44, level = 2)
        }.finish(emptyList(), sourceFileOf("otpth.c"))

        // Both opens track the depth, so nothing is noted there — only the crossed pair is.
        sink.lines.map { it.tag to it.level } mustBe listOf("bracket-level-mismatch" to Level.WARN)
    }

    /**
     * gcc's `dbxout_reg_parms` emits register parameters at depth 0 without setting `did_output`, so
     * in a C++ function — whose depth-0 block never owns variables — they trail with no N_LBRAC to
     * claim them. They are still the function's.
     */
    @Test
    fun `a local no block claims belongs to the function`() {
        val (locals, blocks) = mainBuilder().apply { local("orphan", 27) }.finish(lines, sourceFileOf("main.cpp"))

        locals.single { it.body.name == "orphan" }.sourceFile.filename mustBe "main.cpp"
        ("orphan" in flatten(blocks)) mustBe false
    }
}
