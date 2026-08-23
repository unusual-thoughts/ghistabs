package ghistabs.probe

import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.harvest.sourceFileOf
import ghistabs.parse.SourceFile
import ghistabs.parse.StabReader
import ghistabs.parse.StabType
import ghistabs.parse.isRootedPath
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.io.File

/**
 * Does a CU's compilation directory belong in front of its filename?
 *
 * `cuDirectories` used to join the two by concatenation, which assumes gcc writes the CU relative to
 * the directory it compiled in. It doesn't always: `xmltest_gcc345_fullstabs` pairs the build
 * directory `…/build_dir/objs/mingw-runtime-3.12/` with the *rooted* `…/build_dir/src/…/crt1.c`, and
 * the concatenation is two paths glued end to end — a file that is nowhere, under a directory that
 * isn't even the source's (`objs/` vs `src/`).
 *
 * So this classifies every CU by the shape of its spelling and prints the concatenation next to what
 * [SourceFile.CUSource.spelling] now reads the pair as, so the shapes the rule changes are visible
 * per fixture. 44 of `xmltest_gcc345`'s 58 CUs are rooted; `-fullstabs` builds spell the same files
 * `../../…` relative, where the join was right all along.
 *
 * Parser only — the pairing is the two leading `N_SO` records and nothing downstream of them.
 * Tagged `probe`; run via `probeDump`, writes `build/test-output/cudirectory/<fixture>.txt`.
 */
@Tag("probe")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CuDirectoryProbe : AbstractGhidraHeadlessIntegrationTest() {
    /** One CU's `N_SO` pair. [directory] is absent where gcc emitted no trailing-slash record. */
    private data class Cu(val directory: String?, val filename: String) {
        val shape = when {
            directory == null -> "no directory"
            filename.isRootedPath -> "rooted spelling"
            filename.startsWith("..") -> "../-relative spelling"
            else -> "bare spelling"
        }

        /** Concatenation, the rule before [SourceFile.CUSource.spelling] existed. */
        val joined = sourceFileOf(directory.orEmpty() + filename).path

        /** What the pair names, as the harvest now reads it. */
        val named = sourceFileOf(SourceFile.CUSource(filename, directory).spelling).path
    }

    @ParameterizedTest
    @MethodSource("ghistabs.integration.Fixtures#all")
    fun dumpCuDirectories(binaryName: String) {
        val fixture = File("src/test/resources/binaries/$binaryName")
        assumeTrue(fixture.exists(), "fixture absent")

        ProgramLoader.builder().source(fixture).compiler("gcc").log(MessageLog()).monitor(TaskMonitor.DUMMY).load()
            .use { loadResults ->
                val program = loadResults.getPrimaryDomainObject(this)
                val records = StabReader.fromProgram(program)?.readAll()?.records
                assumeTrue(records != null, "no .stab section")

                // The cursor's own reading of N_SO: trailing slash = directory for the CU that
                // follows, non-empty = CU start, empty = CU end.
                var pending: String? = null
                val cus = records!!.filter { it.type == StabType.N_SO }.mapNotNull { rec ->
                    when {
                        rec.name.endsWith('/') -> null.also { pending = rec.name }
                        rec.name.isEmpty() -> null.also { pending = null }
                        else -> Cu(pending, rec.name).also { pending = null }
                    }
                }.distinct()

                val wrong = cus.filter { it.joined != it.named }
                val out = File("build/test-output/cudirectory/${fixture.nameWithoutExtension}.txt")
                out.parentFile.mkdirs()
                out.bufferedWriter().use { w ->
                    w.write("fixture: $binaryName\n")
                    w.write("compilation units: ${cus.size}, misplaced by the join: ${wrong.size}\n")
                    cus.groupingBy { it.shape }.eachCount().forEach { (shape, n) -> w.write("  $shape: $n\n") }
                    for (cu in cus) {
                        w.write("\n${cu.shape}${if (cu in wrong) " — MISPLACED" else ""}\n")
                        w.write("  dir    ${cu.directory ?: "(none)"}\n")
                        w.write("  file   ${cu.filename}\n")
                        w.write("  joined ${cu.joined}\n")
                        if (cu in wrong) w.write("  names  ${cu.named}\n")
                    }
                }
                println(
                    "[$binaryName] CUs=${cus.size} misplaced=${wrong.size} ${cus.groupingBy {
                        it.shape
                    }.eachCount()}",
                )
                program.release(this)
            }
    }
}
