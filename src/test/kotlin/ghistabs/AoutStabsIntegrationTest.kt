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
import org.junit.jupiter.api.Assertions.*
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
 * Three committed fixtures, all expensive to reproduce — a 1990s toolchain is required. gcc 2.6.3
 * cannot run on a modern kernel at all (libc5's `sbrk` needs `brk()` to return the exact unaligned
 * address it asked for, which Linux has page-aligned for years) and is run under `qemu-system-i386`
 * on a 2.4.18 kernel; gcc 2.95.2 from Debian potato still runs natively, so only its *assembler*
 * has to be period-correct — see the corpus README for both recipes.
 *
 *  - `hello_aout_gcc295.o` — one CU, C: typedef, enum, struct with a self-referential pointer and an
 *    array member, static vs global data and functions.
 *  - `tinyxml_aout_gcc295.o` — one CU, C++: the TiXml class hierarchy, 464 functions, balanced
 *    298/298 scope brackets. Covers a.out C++ as far as it goes — gcc 2.95 defaults to minimal
 *    debug, so its method encodings are the `##` form the parser does not implement, and the class
 *    bodies fail at the first one. Structs and fields materialize; inheritance and vtables do not,
 *    which the `@ExpectedToFail` entries in the regression base record.
 *  - `zlib_aout_gcc263.o` — zlib 1.1.4's fourteen C translation units from Debian buzz's **gcc
 *    2.6.3** targeting `i486-linuxaout` directly, merged with `ld -r`. Covers the multi-CU case,
 *    which has no `N_UNDF` delimiters to lean on, plus unions, forward references and 294 register
 *    variables. Its scope brackets balance exactly (140 `N_LBRAC` / 140 `N_RBRAC`).
 *
 * gcc 2.6.3 **C++** is a step further still, and has no fixture: on top of the `##` forms above it
 * predates two changes that landed in 2.8.0 — `DBX_USE_BINCL`, and with it the `(file,type)` pair,
 * did not exist, so type ids are bare on every target; and the `DECL_ARTIFICIAL` guard restricting
 * the combined tag+typedef `Tt` to C++'s implicit typedefs had not arrived, so plain C typedefs
 * take that form too. C from the same compiler parses cleanly.
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
        fun find(name: String) = dtm.allDataTypes.asSequence().firstOrNull { it.name == name }

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
     * zlib's fourteen translation units merged into one relocatable a.out. The single-CU fixture
     * can't reach this: a.out has no `N_UNDF` headers delimiting compilation units, so cross-CU type
     * identity rests entirely on `N_SO`.
     */
    @Test
    fun harvestsEveryCompilationUnitOfAMergedObject() {
        load("zlib_aout_gcc263.o")
        program.defaultContext().import()

        val dtm = program.dataTypeManager
        fun find(name: String) = dtm.allDataTypes.asSequence().firstOrNull { it.name == name }

        // One type from each of two different translation units — proves N_SO-delimited CU tracking
        // rather than just that the first unit parsed.
        val gz = find("gz_stream")
        assertNotNull(gz, "gz_stream (gzio.c) was not materialized")
        assertEquals(100, (gz as Composite).length, "gz_stream has the wrong size")

        val blocks = find("inflate_blocks_state")
        assertNotNull(blocks, "inflate_blocks_state (infblock.c) was not materialized")
        assertEquals(64, (blocks as Composite).length, "inflate_blocks_state has the wrong size")

        assertNotNull(find("config_s"), "config_s (deflate.c) was not materialized")

        // zlib also gives a divergent cross-CU definition for free: `internal_state` is a 4-byte
        // opaque stub in zlib.h but the real 5816-byte struct inside deflate.c. Not asserted here —
        // which of the two should win is a question about collision policy, not about a.out.
    }
}
