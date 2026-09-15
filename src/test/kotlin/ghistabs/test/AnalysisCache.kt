package ghistabs.test

import ghidra.framework.store.db.PackedDatabase
import ghidra.program.database.ProgramContentHandler
import ghidra.program.database.ProgramDB
import ghidra.program.model.listing.Program
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import ghistabs.LoadedProgram
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING

/**
 * Packed program databases holding a fixture as auto-analysis left it, so a run pays Ghidra's
 * analysis once per binary rather than once per invocation. Analysis is over 90% of an AFTER-mode
 * fixture (90-500s against BEFORE's ~10s), and the snapshot is taken between the analysis and the
 * stabs import, which is a point only AFTER mode has.
 *
 * What it holds is Ghidra's analysis *plus* this extension's other analyzers, which stay enabled in
 * AFTER mode and run inside the same pass. Nothing keys an entry to the code that produced it, so a
 * restored run reports whatever those analyzers did on the day the entry was written; CONCURRENT
 * mode never touches the cache and is where a change to them is seen. `-PanalysisCache=off` bypasses
 * it entirely, `=refresh` re-analyzes and overwrites.
 *
 * Every failure is soft: an entry that is corrupt, or written by another Ghidra version, is reported
 * and re-analyzed.
 */
object AnalysisCache {
    private val policy = System.getProperty("analysisCache").orEmpty().ifEmpty { "auto" }
    private val dir = File(System.getProperty("analysisCacheDir").orEmpty().ifEmpty { "build/analysis-cache" })

    private fun entry(fixture: File) = File(dir, "${fixture.name}.gzf")

    /** [fixture] analyzed, or null when there is no usable entry and the caller must analyze it. */
    fun restore(fixture: File, consumer: Any): LoadedProgram? {
        val file = entry(fixture)
        if (policy != "auto" || !file.exists()) return null
        // neverCache: parallel forks share the packed file, not an unpacking of it that one of them
        // would hold the lock on.
        val packed = runCatching { PackedDatabase.getPackedDatabase(file, true, TaskMonitor.DUMMY) }
            .onFailure { Msg.warn(this, "analysis cache: cannot unpack $file, re-analyzing ($it)") }
            .getOrNull() ?: return null
        return runCatching { LoadedProgram(openProgramDb(packed.open(TaskMonitor.DUMMY), consumer), consumer) }
            .onFailure {
                packed.dispose()
                Msg.warn(this, "analysis cache: cannot open $file, re-analyzing ($it)")
            }
            .onSuccess {
                Msg.info(this, "analysis cache: restored $file")
            }
            .getOrNull()
    }

    /** Snapshot [program] as [fixture]'s entry, before anything under test has touched it. */
    fun store(fixture: File, program: Program) {
        if (policy == "off") return
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
            val file = entry(fixture)
            Files.move(staged.toPath(), file.toPath(), REPLACE_EXISTING, ATOMIC_MOVE)
            Msg.info(this, "analysis cache: stored $fixture to $file")
        }.onFailure {
            staged.delete()
            Msg.warn(this, "analysis cache: failed to store ${fixture.name} ($it)")
        }
    }
}
