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
import ghistabs.importer.ImportOptions.Companion.disableStabsAnalyzer
import ghistabs.loadPackedProgram
import java.io.DataInputStream
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
 * An entry is named for everything that produced it (see [key]): the fixture's bytes, the Ghidra
 * build, and the bytecode of the analysis it ran. Ghidra's analysis is not alone in that pass: this
 * extension's other analyzers stay enabled in AFTER mode and run inside it, so a change to one of them,
 * or to anything they call, names a new entry and the fixture is re-analyzed. Whatever only the stabs
 * import and the rendering reach does not, which is what lets CI carry the cache from run to run.
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
     * What every entry depends on besides its fixture: the Ghidra build, and each class this project
     * built that an analysis can execute. Those are the classes loaded from a directory rather than a
     * jar that the analyzers Ghidra discovers, or this object (which holds the AFTER-mode analysis
     * recipe), reach through their constant pools. Computed once per JVM, after Ghidra is up.
     */
    private val codeKey: String? by lazy {
        runCatching {
            val ghidra = listOf(
                Application.getApplicationVersion(),
                Application.getBuildDate(),
                Application.getApplicationProperty("application.revision.ghidra").orEmpty(),
            )
            val roots = ClassSearcher.getClasses(Analyzer::class.java) + AnalysisCache::class.java
            sha256 { digest ->
                ghidra.forEach { digest.update("$it\n".toByteArray()) }
                reachableClasses(roots).forEach { (name, bytes) ->
                    digest.update("$name\n".toByteArray())
                    digest.update(bytes)
                }
            }
        }.onFailure { Msg.warn(this, "analysis cache: cannot fingerprint the analysis, cache off ($it)") }
            .getOrNull()
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

    /**
     * Bytecode of [roots] and of every class they reach, by internal name, in name order, keeping to
     * classes loaded from a directory: this project's own output, not Ghidra's jars or the JDK.
     */
    private fun reachableClasses(roots: Collection<Class<*>>): Map<String, ByteArray> {
        val loader = AnalysisCache::class.java.classLoader
        val found = sortedMapOf<String, ByteArray>()
        val pending = ArrayDeque(roots.map { it.name.replace('.', '/') })
        val visited = mutableSetOf<String>()
        while (pending.isNotEmpty()) {
            val name = pending.removeFirst()
            if (!visited.add(name)) continue
            val url = loader.getResource("$name.class")?.takeIf { it.protocol == "file" } ?: continue
            val bytes = url.openStream().use { it.readBytes() }
            found[name] = bytes
            pending += referencedClasses(bytes) - visited
        }
        return found
    }

    private val DESCRIPTOR_CLASS = Regex("L([^;<>]+)[;<]")

    /** Bytes after the tag of each fixed-size constant pool entry, by tag (JVMS 4.4). */
    @Suppress("MagicNumber")
    private val CONSTANT_SIZE = mapOf(
        3 to 4, 4 to 4, 5 to 8, 6 to 8, 8 to 2, 9 to 4, 10 to 4, 11 to 4,
        12 to 4, 15 to 3, 16 to 2, 17 to 4, 18 to 4, 19 to 2, 20 to 2,
    )

    /**
     * Internal names a class file's constant pool mentions: its class entries, and every class in its
     * descriptors and signatures. Over-approximates (a name in a string constant counts too), which can
     * only make the key more sensitive.
     */
    @Suppress("MagicNumber")
    private fun referencedClasses(bytes: ByteArray): Set<String> {
        val input = DataInputStream(bytes.inputStream())
        input.skipBytes(8) // magic, minor_version, major_version
        val count = input.readUnsignedShort()
        val utf8 = mutableMapOf<Int, String>()
        val classIndices = mutableListOf<Int>()
        var index = 1
        while (index < count) {
            val tag = input.readUnsignedByte()
            when (tag) {
                1 -> utf8[index] = input.readUTF()
                7 -> classIndices += input.readUnsignedShort()
                else -> input.skipBytes(CONSTANT_SIZE[tag] ?: error("unknown constant pool tag $tag"))
            }
            // Eight-byte constants take two slots.
            index += if (tag == 5 || tag == 6) 2 else 1
        }
        return buildSet {
            classIndices.mapNotNullTo(this) { utf8[it]?.takeUnless { name -> name.startsWith('[') } }
            utf8.values.forEach { value -> DESCRIPTOR_CLASS.findAll(value).mapTo(this) { it.groupValues[1] } }
        }
    }
}
