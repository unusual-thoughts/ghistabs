package ghistabs.test

import ghidra.app.services.Analyzer
import ghistabs.entrypoints.StabsAnalyzer
import org.junit.jupiter.api.Test
import java.io.File

/** What [AnalysisCache]'s key covers: the analysis pass AFTER mode snapshots, and not the import that follows it. */
class AnalysisCacheTest {
    /** Every analyzer the project builds, as ClassSearcher finds them, without starting Ghidra. */
    private val analyzers = File(StabsAnalyzer::class.java.protectionDomain.codeSource.location.toURI()).let { root ->
        root.walk()
            .filter { it.name.endsWith("Analyzer.class") }
            .map { it.relativeTo(root).path.removeSuffix(".class").replace(File.separatorChar, '.') }
            .map { Class.forName(it, false, javaClass.classLoader) }
            .filter { Analyzer::class.java.isAssignableFrom(it) && !it.isInterface }
            .toList()
    }

    private val code = AnalysisCache.analysisCode(analyzers)

    @Test
    fun `every analyzer but the stabs one runs`() {
        val added = code.methods.filter { ".added(" in it }.map { it.substringBefore('.') }
        val expected = (analyzers - StabsAnalyzer::class.java).map { it.name.replace('.', '/') }
        (expected - added.toSet()).mustBeEmpty("analyzers whose added() the walk missed")
    }

    @Test
    fun `the stabs import is not part of the key`() {
        code.methods.filter { it.startsWith("ghistabs/entrypoints/StabsAnalyzer") && ".import(" in it }
            .mustBeEmpty("the import is reached")
        code.methods.filter { it.startsWith("ghistabs/render/") }.mustBeEmpty("render code is reached")
    }
}
