package ghistabs

import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.program.model.data.Composite
import ghidra.program.model.data.Enum
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.StabsAnalyzer.Companion.import
import ghistabs.diagnose.CapturingSink
import ghistabs.diagnose.Level
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.diagnose.defaultContext
import ghistabs.importer.ImportContext
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * a.out support: stabs read from the linker symbol table instead of `.stab`/`.stabstr` sections.
 *
 * a.out has no debug *sections* — each stab is an entry in the symbol table itself (`n_type >= 0x20`),
 * interleaved with the link-time symbols and sharing one flat string table, so `n_strx` is absolute with no
 * `N_UNDF` header rebasing it per compilation unit. Ghidra's `UnixAoutLoader` discards the records but
 * exposes both tables as `.symtab`/`.strtab`, which is what [ghistabs.parse.Layout.SYMTAB] reads.
 *
 * Two fixtures, kept out of `binaries/`'s gitignore rule (see `.gitignore`) because reproducing them
 * needs a 1997 toolchain — Debian bo's `aout-binutils` assembler fed from gcc 2.95 `-gstabs` output in a
 * period container. (bo's own gcc 2.7 cannot run on a modern kernel: libc5's `sbrk` requires `brk()` to
 * return the exact unaligned address it asked for, and today's kernel page-aligns it.)
 *
 *  - `hello_aout_gcc295.o` — one CU, C: typedef, enum, struct with a self-referential pointer and an
 *    array member, static vs global data and functions.
 *  - `tinyxml_aout_gcc295.o` — four C++ CUs merged with `ld -r -m i386linux`, giving a virtual class
 *    hierarchy and the multi-CU case that has no `N_UNDF` delimiters to lean on.
 */
@Tag("integration")
class AoutStabsIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    private lateinit var program: Program

    private fun load(name: String) {
        val fixture = File("src/test/resources/binaries/$name")
        assumeTrue(fixture.isFile, "a.out fixture missing: $fixture")
        program = ProgramLoader.builder()
            .source(fixture)
            .log(MessageLog())
            .monitor(TaskMonitor.DUMMY)
            .load()
            .getPrimaryDomainObject(this)
    }

    @AfterEach
    fun tearDown() {
        if (::program.isInitialized) program.release(this)
    }

    @Test
    fun importsStabsFromTheSymbolTable() {
        load("hello_aout_gcc295.o")
        program.defaultContext().import()

        val dtm = program.dataTypeManager
        fun find(name: String) = dtm.getAllDataTypes().asSequence().firstOrNull { it.name == name }

        val message = find("message")
        assertNotNull(message, "struct 'message' was not materialized from the a.out symbol table")
        assertEquals(28, (message as Composite).length, "struct 'message' has the wrong size")

        val kind = find("kind")
        assertNotNull(kind, "enum 'kind' was not materialized")
        assertEquals(3, (kind as Enum).count, "enum 'kind' should have three enumerators")

        assertNotNull(find("uint32"), "typedef 'uint32' was not materialized")
    }

    /**
     * The overlay is on by default in production but off in [defaultContext], so it needs its own pass:
     * on a.out it has to decorate `.symtab`, and hard-coding `.stab` made it throw here.
     */
    @Test
    fun overlaysDecodedRecordsOntoTheSymbolTable() {
        load("hello_aout_gcc295.o")
        val ctx = ImportContext(
            program,
            TaskMonitor.DUMMY,
            StabsOptions(minLogLevel = Level.DEBUG),
            CapturingSink(),
            StabsDiagnostics(),
        )
        assertTrue(ctx.options.overlaySection, "this test is meaningless unless the overlay is on")
        ctx.import()

        val symtab = program.memory.getBlock(".symtab")
        assertNotNull(symtab, "a.out loader should expose the symbol table as .symtab")

        // Not at symtab.start: entry 0 is a link-time symbol (`.Ltext0`), which SYMTAB layout
        // skips. Only the stab-typed entries get decorated.
        val overlaid = program.listing.getDefinedData(symtab.start, true).iterator().asSequence()
            .takeWhile { it.address <= symtab.end }
            .filter { it.dataType.name == "StabRecord" }
            .toList()
        assertTrue(overlaid.isNotEmpty(), "no decoded StabRecord laid anywhere in .symtab")
        assertTrue(
            overlaid.any { program.listing.getComment(CommentType.EOL, it.address)?.contains("N_SO") == true },
            "expected the N_SO record to be decoded and commented",
        )
    }

    /**
     * TinyXML 1.x, four translation units merged with `ld -r -m i386linux` into one relocatable a.out.
     * The single-CU fixture can't reach this: a.out has no `N_UNDF` headers delimiting compilation
     * units, so cross-CU type identity rests entirely on `N_SO` — and the classes here carry virtual
     * methods and a base-class list, which the hello fixture has none of.
     */
    @Test
    fun harvestsEveryCompilationUnitOfAMergedCxxObject() {
        load("tinyxml_aout_gcc295.o")
        program.defaultContext().import()

        val dtm = program.dataTypeManager
        fun find(name: String) = dtm.getAllDataTypes().asSequence().firstOrNull { it.name == name }

        // One type from each of two different translation units: proves N_SO-delimited CU tracking,
        // not just that the first unit parsed.
        assertNotNull(find("TiXmlString"), "TiXmlString (tinystr.cpp) was not materialized")
        assertNotNull(find("TiXmlElement"), "TiXmlElement (tinyxml.cpp) was not materialized")

        val node = find("TiXmlNode")
        assertNotNull(node, "TiXmlNode, the polymorphic base of the hierarchy, was not materialized")
        assertTrue((node as Composite).length > 0, "TiXmlNode materialized with no layout")
    }
}
