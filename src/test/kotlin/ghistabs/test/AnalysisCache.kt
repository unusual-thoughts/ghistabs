package ghistabs.test

import ghidra.app.plugin.core.analysis.AutoAnalysisManager
import ghidra.app.services.Analyzer
import ghidra.framework.Application
import ghidra.framework.store.db.PackedDatabase
import ghidra.program.database.ProgramContentHandler
import ghidra.program.database.ProgramDB
import ghidra.program.model.listing.Program
import ghidra.util.Msg
import ghidra.util.classfinder.ClassSearcher
import ghidra.util.task.TaskMonitor
import ghistabs.LoadedProgram
import ghistabs.entrypoints.StabsAnalyzer
import ghistabs.importer.ImportOptions.Companion.disableStabsAnalyzer
import ghistabs.loadPackedProgram
import org.objectweb.asm.Type
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.security.MessageDigest

/**
 * Packed program databases holding a fixture as auto-analysis left it, so a run pays Ghidra's
 * analysis once per binary rather than once per invocation. Analysis is over 90% of an AFTER-mode
 * fixture (90-500s against BEFORE's ~10s), and the snapshot is taken between the analysis and the
 * stabs import, which is a point only AFTER mode has.
 *
 * An entry is named for everything that produced it (see [codeKey]): the fixture's bytes, the Ghidra
 * build, and the bytecode of the analysis it ran. Ghidra's analysis is not alone in that pass: this
 * extension's other analyzers stay enabled in AFTER mode and run inside it, so a change to a method
 * one of them can execute names a new entry and the fixture is re-analyzed. A change to code only the
 * stabs import executes does not, which is what lets CI carry the cache from run to run.
 * Storing an entry deletes the fixture's others. `-PanalysisCache=off` bypasses it entirely, `=refresh`
 * re-analyzes and overwrites.
 *
 * Every failure is soft: an entry that is corrupt is reported and re-analyzed, and a key that cannot be
 * computed turns the cache off.
 */
object AnalysisCache {
    private val policy = System.getProperty("analysisCache").orEmpty().ifEmpty { "auto" }
    private val dir = File(System.getProperty("analysisCacheDir").orEmpty().ifEmpty { "build/analysis-cache" })

    /**
     * What every entry depends on besides its fixture: the Ghidra build, and the bytecode this project
     * built that the analysis can execute (see [ReachableCode]). That is every analyzer Ghidra discovers,
     * as Ghidra drives it, and the recipe in [analyze], but not [StabsAnalyzer.added]: the recipe turns
     * the stabs analyzer off, so the import and everything only it calls stay out of the key, and the
     * import runs after the snapshot anyway. Computed once per JVM, after Ghidra is up.
     */
    private val codeKey: String? by lazy {
        runCatching {
            val ghidra = listOf(
                Application.getApplicationVersion(),
                Application.getBuildDate(),
                Application.getApplicationProperty("application.revision.ghidra").orEmpty(),
            )
            val code = analysisCode(ClassSearcher.getClasses(Analyzer::class.java))
            Msg.info(this, "analysis cache: key covers ${code.classes.size} classes")
            sha256 { digest ->
                ghidra.forEach { digest.update("$it\n".toByteArray()) }
                digest.update(code.text().toByteArray())
            }
        }.onFailure { Msg.warn(this, "analysis cache: cannot fingerprint the analysis, cache off ($it)") }
            .getOrNull()
    }

    /** The code an AFTER-mode analysis with [analyzers] can execute. */
    internal fun analysisCode(analyzers: Collection<Class<*>>): ReachableCode {
        val import = StabsAnalyzer::class.java.methods.filter { it.name == "added" }.map {
            ReachableCode.Ref(Type.getInternalName(StabsAnalyzer::class.java), it.name, Type.getMethodDescriptor(it))
        }
        return ReachableCode(AnalysisCache::class.java.classLoader, import.toSet()).apply {
            analyzers.forEach(::instantiatedExternally)
            calledExternally(AnalysisCache::class.java, "analyze")
        }
    }

    /** [fixture]'s entry under the current code, or null when the cache has no key. */
    private fun entry(fixture: File): File? {
        val code = codeKey ?: return null
        val key = sha256 { digest ->
            digest.update(code.toByteArray())
            digest.update(fixture.readBytes())
        }
        return File(dir, "${fixture.name}.${key.take(KEY_LENGTH)}.gzf")
    }

    /** Every entry [fixture] has, under any key, and the unkeyed one older runs wrote. */
    private fun entries(fixture: File): List<File> {
        val name = Regex("${Regex.escape(fixture.name)}(\\.[0-9a-f]{$KEY_LENGTH})?\\.gzf")
        return dir.listFiles { file -> name.matches(file.name) }.orEmpty().toList()
    }

    /** [fixture] analyzed, or null when there is no usable entry and the caller must analyze it. */
    fun restore(fixture: File, consumer: Any): LoadedProgram? {
        if (policy != "auto") return null
        val file = entry(fixture)?.takeIf(File::exists) ?: return null
        // neverCache (in loadPackedProgram): parallel forks share the packed file, not an unpacking
        // of it that one of them would hold the lock on.
        return runCatching { consumer.loadPackedProgram(file) }
            .onFailure { Msg.warn(this, "analysis cache: cannot open $file, re-analyzing ($it)") }
            .onSuccess {
                Msg.info(this, "analysis cache: restored $file")
            }
            .getOrNull()
    }

    /**
     * Auto-analyze [program], freshly loaded from [fixture], as AFTER mode imports into it: with every
     * analyzer but ours for stabs, so the import that follows is the one under test. Then snapshot it.
     * Lives here rather than with its caller so that it is part of what [codeKey] fingerprints.
     */
    fun analyze(fixture: File, program: Program, monitor: TaskMonitor, timesFile: File) {
        program.disableStabsAnalyzer()
        AutoAnalysisManager.getAnalysisManager(program).initializeOptions()
        program.runAutoAnalysis(monitor, timesFile)
        store(fixture, program)
    }

    /** Snapshot [program] as [fixture]'s entry, before anything under test has touched it. */
    private fun store(fixture: File, program: Program) {
        if (policy == "off") return
        val file = entry(fixture) ?: return
        dir.mkdirs()
        // packDatabase refuses to overwrite, and a sibling fork may be reading the entry: pack to a
        // private name and swap it in.
        val staged = File(dir, "${fixture.name}.${ProcessHandle.current().pid()}.tmp")
        runCatching {
            staged.delete()
            PackedDatabase.packDatabase(
                (program as ProgramDB).dbHandle,
                fixture.name,
                ProgramContentHandler.PROGRAM_CONTENT_TYPE,
                staged,
                TaskMonitor.DUMMY,
            )
            Files.move(staged.toPath(), file.toPath(), REPLACE_EXISTING, ATOMIC_MOVE)
            // Superseded: no run of this code opens them again.
            entries(fixture).filter { it != file }.forEach(File::delete)
            Msg.info(this, "analysis cache: stored $fixture to $file")
        }.onFailure {
            staged.delete()
            Msg.warn(this, "analysis cache: failed to store ${fixture.name} ($it)")
        }
    }

    private const val KEY_LENGTH = 16

    private fun sha256(feed: (MessageDigest) -> Unit) =
        MessageDigest.getInstance("SHA-256").also(feed).digest().joinToString("") { "%02x".format(it) }
}
