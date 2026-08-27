package ghistabs.diagnose

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Program
import ghistabs.diagnose.BookmarkSink.Companion.toBookmark
import java.io.Writer

enum class Level { DEBUG, INFO, WARN, ERROR }

interface DiagnosticSink {
    /**
     * A diagnostic event. [count] lets one call stand in for a bulk tally (`log(cat, count = n)`
     * replaces the old `inc(cat, n)`); [message] null means a silent counter bump (no output).
     */
    fun log(
        category: String,
        message: String? = null,
        level: Level = Level.INFO,
        address: Address? = null,
        count: Long = 1,
    )

    fun debug(category: String, message: String? = null, address: Address? = null, count: Long = 1) =
        log(category, message, level = Level.DEBUG, address, count)

    fun warn(category: String, message: String? = null, address: Address? = null, count: Long = 1) =
        log(category, message, level = Level.WARN, address, count)

    fun err(category: String, message: String? = null, address: Address? = null, count: Long = 1) =
        log(category, message, level = Level.ERROR, address, count)
}

object DummySink : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {}
}

/** Fan-out sink — tees the [StabsDiagnostics] accumulator alongside a terminal (Bookmark/Capturing). */
class TeeSink(private vararg val sinks: DiagnosticSink?) : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        for (s in sinks) s?.log(category, message, level, address, count)
    }
}

/** Writes message-bearing diagnostics at/above [minLevel] to Ghidra's [MessageLog]. */
class MessageLogSink(private val messageLog: MessageLog, private val minLevel: Level = Level.INFO) : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        if (message == null || level < minLevel) return
        val prefix = "[Stabs][${level.name}]"
        val line = if (address != null) "$prefix $category at $address: $message" else "$prefix $category: $message"
        if (level == Level.ERROR) messageLog.appendMsg("ERROR: $line") else messageLog.appendMsg(line)
    }
}

/**
 * Places a Ghidra bookmark for any addressed diagnostic (function entry, data, vtable). A bookmark
 * is a navigation marker, so it is unconditional — no level gate; the bookmark's type carries the
 * severity ([toBookmark]). Counting and MessageLog output are other tee'd sinks' jobs.
 */
class BookmarkSink(private val program: Program) : DiagnosticSink {
    companion object {
        private fun Level.toBookmark() = when (this) {
            Level.DEBUG -> BookmarkType.ANALYSIS
            Level.INFO -> BookmarkType.INFO
            Level.WARN -> BookmarkType.WARNING
            Level.ERROR -> BookmarkType.ERROR
        }
    }
    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        if (address == null) return
        program.bookmarkManager.setBookmark(
            address,
            level.toBookmark(),
            "Stabs:$category",
            "[Stabs][${level.name}] $category: $message",
        )
    }
}

/** Streams each diagnostic line at or above [minLevel] to [out], flushing so the log is live. */
class WriterSink(private val minLevel: Level, private val out: Writer) : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        if (message == null || level < minLevel) return
        val at = address?.let { "[@$it]" } ?: ""
        out.append("[$level][$category]$at $message\n")
        out.flush()
    }
}
