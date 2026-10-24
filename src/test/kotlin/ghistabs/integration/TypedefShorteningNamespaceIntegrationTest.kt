package ghistabs.integration

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.util.importer.MessageLog
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.test.AbstractGhidraHeadlessIntegrationTest
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.CapturingSink
import ghistabs.entrypoints.StabsAnalyzer
import ghistabs.importer.ImportContext
import ghistabs.importer.ImportOptions
import ghistabs.importer.import
import ghistabs.materialize.TemplateNameShortener
import ghistabs.materialize.typedefAliases
import ghistabs.runTransaction
import ghistabs.test.disableWindowsResourceAnalyzer
import ghistabs.test.importAndAnalyze
import ghistabs.test.mustBeEmpty
import ghistabs.withProgram
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test

/**
 * With typedef shortening on, a class's namespace is shortened with its struct, and its methods' primary
 * symbols live under the short name: that is what the decompiler prints, and what Ghidra's auto-`this`
 * looks the class struct up by. A long namespace left holding them typed every `this` with an empty
 * placeholder (699 methods on crypto_mi_test_gcc421_fullstabs, 4 on this fixture).
 *
 * Re-running Ghidra's demangler recreates the long namespace for the mangled labels, but only as
 * secondary symbols, so the same holds after it.
 */
@Tag("integration")
class TypedefShorteningNamespaceIntegrationTest : AbstractGhidraHeadlessIntegrationTest() {
    @Test
    fun methodsLiveInTheShortenedNamespaceAndBindThis() {
        val monitor = TaskMonitor.DUMMY
        withProgram(Fixtures.orDefault(DEFAULT_FIXTURE), log = MessageLog(), monitor = monitor) { program ->
            val ctx = ImportContext(program, monitor, CapturingSink(), ImportOptions { shortenTypedefs = true })
            val mgr = AutoAnalysisManager.getAnalysisManager(program)
            program.runTransaction("disable-stabs-analyzer") {
                program.getOptions(Program.ANALYSIS_PROPERTIES).setBoolean(StabsAnalyzer().name, false)
            }
            mgr.initializeOptions()
            program.disableWindowsResourceAnalyzer()
            program.runTransaction("auto-analyze") {
                mgr.startAnalysis(monitor)
                mgr.waitForAnalysis(null, monitor)
            }
            val result = program.runTransaction("stabs-import") { ctx.importAndAnalyze() }
            val registry = checkNotNull(result.artifacts) { "artifacts not populated" }.registry
            val shortener = TemplateNameShortener(registry.typedefAliases())

            program.methodsUnderLongNamespaces(shortener)
                .mustBeEmpty("methods left under a namespace typedef shortening renames")
            program.methodsWithEmptyThis().map { it.describe() }
                .mustBeEmpty("methods whose `this` is an empty placeholder")
            val bound = program.methods().filter { it.thisStruct() != null }.map { it.entryPoint }.toSet()

            program.runTransaction("re-demangle") {
                mgr.scheduleOneTimeAnalysis(mgr.getAnalyzer("Demangler GNU"), program.memory)
                mgr.startAnalysis(monitor)
            }
            program.methodsUnderLongNamespaces(shortener)
                .mustBeEmpty("methods moved back under a long namespace by re-demangling")
            // Only the methods that were bound: re-demangling also turns some plain namespaces into
            // classes (`__cxxabiv1`), which have no struct to bind, shortening or not.
            program.methodsWithEmptyThis().filter { it.entryPoint in bound }.map { it.describe() }
                .mustBeEmpty("methods whose `this` lost its struct to re-demangling")
        }
    }

    private fun Program.methods() = functionManager.getFunctions(true).filter { it.parentNamespace is GhidraClass }

    private fun Program.methodsUnderLongNamespaces(shortener: TemplateNameShortener) = methods()
        .filter { shortener.shortenedNestedOrNull(it.parentNamespace.name) != null }
        .map { it.getName(true) }

    private fun Program.methodsWithEmptyThis() = methods()
        .filter { f -> f.parameters.any { it.name == Function.THIS_PARAM_NAME } && f.thisStruct() == null }

    /** The non-empty struct [this]'s `this` points at, or null. */
    private fun Function.thisStruct() = parameters.firstOrNull { it.name == Function.THIS_PARAM_NAME }
        ?.let { (it.dataType as? Pointer)?.dataType as? Structure }
        ?.takeUnless { it.isZeroLength || it.numComponents == 0 }

    private fun Function.describe() = "${getName(true)} : ${getParameter(0).dataType.pathName}"

    companion object {
        const val DEFAULT_FIXTURE = "xmltest_gcc421_fullstabs.exe"
    }
}
