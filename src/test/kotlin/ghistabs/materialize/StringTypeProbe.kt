package ghistabs.materialize

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.importer.ProgramLoader
import ghidra.program.model.data.Composite
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.data.TypeDef
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.ImportOptions
import ghistabs.StabsAnalyzer
import ghistabs.StabsAnalyzer.Companion.import
import ghistabs.diagnose.CapturingSink
import ghistabs.diagnose.Level
import ghistabs.diagnose.StabsDiagnostics
import ghistabs.disableWindowsResourceAnalyzer
import ghistabs.importer.ImportContext
import ghistabs.importer.ImportProbe
import ghistabs.runTransaction
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import java.io.File

/**
 * One-shot probe focused on `std::basic_string<…>` / `string`:
 *  - Where do the `string`-named Structures live (and which categories
 *    contain the Demangler stubs that aren't getting replaced)?
 *  - For the materialized `basic_string<…>` Structure, walk every field
 *    transitively and flag any Undefined* slot — the "this string type is
 *    fully resolved" check.
 */
@Tag("probe")
class StringTypeProbe : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun probeXapasmcsr() {
        val fixture = File("src/test/resources/binaries/xapasmcsr.exe")
        assumeTrue(fixture.exists(), "fixture absent")
        runProbe(fixture, "xapasmcsr")
    }

    @Test
    fun probeAppquery() {
        val fixture = File("src/test/resources/binaries/appquery.exe")
        assumeTrue(fixture.exists(), "fixture absent")
        runProbe(fixture, "appquery")
    }

    private fun runProbe(fixture: File, label: String) {
        val log = MessageLog()
        val monitor = TaskMonitor.DUMMY
        ProgramLoader.builder()
            .source(fixture)
            .compiler("gcc")
            .log(log)
            .monitor(monitor)
            .load()
            .use { loadResults ->
                val program = loadResults.getPrimaryDomainObject(this)
                val mgr = AutoAnalysisManager.getAnalysisManager(program)
                // Enable typedef shortening (OPT_SHORTEN_TYPEDEFS) so the probe exercises the
                // basic_string→string rename path — the regression in render-backlog §14 (the
                // /Demangler/string stub no longer replaced) only appears when shortening is on.
                val ctx = ImportContext(
                    program,
                    TaskMonitor.DUMMY,
                    ImportOptions(shortenTypedefs = true, minLogLevel = Level.DEBUG),
                    CapturingSink(),
                    StabsDiagnostics(),
                )
                ImportProbe.install(ctx)
                val options = program.getOptions(ghidra.program.model.listing.Program.ANALYSIS_PROPERTIES)
                program.runTransaction("disable-stabs-analyzer") {
                    options.setBoolean(StabsAnalyzer().name, false)
                }
                mgr.initializeOptions()
                program.disableWindowsResourceAnalyzer()
                program.runTransaction("auto-analyze") {
                    mgr.startAnalysis(monitor)
                    mgr.waitForAnalysis(null, monitor)
                }
                program.runTransaction("stabs-analyze") {
                    ctx.import()
                }

                val out = File("build/test-output/degradations/$label.string-probe.txt")
                out.parentFile.mkdirs()
                out.bufferedWriter().use { w ->
                    w.write("=== DataTypes whose name == \"string\" ===\n")
                    val strings = program.dataTypeManager.allDataTypes.asSequence()
                        .filter { it.name == "string" }
                        .toList()
                    for (s in strings) {
                        val kind = s::class.simpleName
                        val len = (s as? Composite)?.length ?: -1
                        val nc = (s as? Composite)?.numComponents ?: -1
                        val tdBase = (s as? TypeDef)?.baseDataType?.pathName
                        w.write(
                            "  ${s.categoryPath.path}/${s.name} kind=$kind len=$len components=$nc tdBase=$tdBase\n",
                        )
                    }

                    w.write("\n=== All basic_string-shaped DataTypes (name contains 'basic_string') ===\n")
                    val bs = program.dataTypeManager.allDataTypes.asSequence()
                        .filter { it.name.contains("basic_string") }
                        .toList()
                    for (s in bs) {
                        val kind = s::class.simpleName
                        val len = (s as? Composite)?.length ?: -1
                        val nc = (s as? Composite)?.numComponents ?: -1
                        w.write("  ${s.categoryPath.path}/${s.name} kind=$kind len=$len components=$nc\n")
                    }

                    w.write("\n=== Field tree for the first non-Demangler basic_string<char,…> Structure ===\n")
                    val primary = bs.asSequence()
                        .filterIsInstance<Structure>()
                        .filter { !it.categoryPath.path.startsWith("/Demangler") }
                        // The real basic_string<char,…> — not template-instantiation-of-something-OVER-basic_string.
                        .filter { it.name.startsWith("basic_string<") }.firstOrNull { it.numComponents > 0 }
                    if (primary == null) {
                        w.write("  (none)\n")
                    } else {
                        w.write("Root: ${primary.categoryPath.path}/${primary.name} (${primary.length} bytes)\n")
                        val visited = mutableSetOf<String>()
                        dumpTree(primary, prefix = "  ", depth = 0, visited = visited, w = w)
                    }

                    w.write("\n=== Undefined-named DataTypes referenced from basic_string subtree ===\n")
                    if (primary != null) {
                        val undef = mutableSetOf<String>()
                        collectUndef(primary, mutableSetOf(), undef)
                        if (undef.isEmpty()) {
                            w.write("  none — fully resolved.\n")
                        } else {
                            for (u in undef.sorted()) w.write("  $u\n")
                        }
                    }
                }
                println("Wrote string probe to ${out.absolutePath}")
            }
    }

    private fun dumpTree(
        dt: ghidra.program.model.data.DataType,
        prefix: String,
        depth: Int,
        visited: MutableSet<String>,
        w: java.io.BufferedWriter,
    ) {
        if (depth > 5) {
            w.write("$prefix… (depth > 5)\n")
            return
        }
        val key = dt.pathName
        if (!visited.add(key)) {
            w.write("$prefix$key (cycle)\n")
            return
        }
        when (dt) {
            is Structure -> {
                for (c in dt.components) {
                    val fname = c.fieldName ?: "<unnamed>"
                    val tname = c.dataType.pathName
                    w.write(
                        "$prefix${
                            c.offset.toString().padStart(
                                3,
                            )
                        } $fname: $tname (${c.dataType::class.simpleName} ${c.length}b)\n",
                    )
                    if (c.dataType is Structure || c.dataType is TypeDef || c.dataType is Pointer) {
                        dumpTree(c.dataType, "$prefix  ", depth + 1, visited, w)
                    }
                }
            }

            is TypeDef -> {
                w.write("${prefix}typedef → ${dt.baseDataType.pathName}\n")
                dumpTree(dt.baseDataType, "$prefix  ", depth + 1, visited, w)
            }

            is Pointer -> {
                val pointee = dt.dataType
                if (pointee == null) {
                    w.write("${prefix}pointer → null\n")
                } else {
                    w.write("${prefix}pointer → ${pointee.pathName} (${pointee::class.simpleName})\n")
                    if (pointee is Structure || pointee is TypeDef) {
                        dumpTree(pointee, "$prefix  ", depth + 1, visited, w)
                    }
                }
            }

            else -> {}
        }
    }

    private fun collectUndef(
        dt: ghidra.program.model.data.DataType,
        visited: MutableSet<String>,
        out: MutableSet<String>,
    ) {
        if (!visited.add(dt.pathName)) return
        if (dt.isUndefined) {
            out.add(dt.pathName)
            return
        }
        when (dt) {
            is Structure -> {
                for (c in dt.components) collectUndef(c.dataType, visited, out)
            }

            is TypeDef -> collectUndef(dt.baseDataType, visited, out)

            is Pointer -> dt.dataType?.let { collectUndef(it, visited, out) }

            else -> {}
        }
    }
}
