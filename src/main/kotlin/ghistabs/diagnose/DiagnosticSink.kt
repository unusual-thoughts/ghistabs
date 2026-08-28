package ghistabs.diagnose

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Program
import ghistabs.diagnose.BookmarkSink.Companion.toBookmark
import java.io.Writer

enum class Level { DEBUG, INFO, WARN, ERROR }

/** The one rendering of a diagnostic's text, shared by every terminal. Null when it has none. */
fun diagnosticText(degrades: String?, message: String?) =
    listOfNotNull(degrades, message).joinToString(" :: ").ifEmpty { null }

interface DiagnosticSink {
    /**
     * A diagnostic event. [count] lets one call stand in for a bulk tally (`log(cat, count = n)`
     * replaces the old `inc(cat, n)`); [message] and [degrades] both null means a silent counter bump.
     *
     * A non-null [degrades] names the artifact this event damaged, and *is* what makes the event a
     * **degradation** — see [degradation], which is just this call with that argument filled in.
     * Degradations are otherwise ordinary events: they count, they bookmark, they carry a level, and
     * nothing keys off the category name.
     */
    fun log(
        category: String,
        message: String? = null,
        level: Level = Level.INFO,
        address: Address? = null,
        degrades: String? = null,
        count: Long = 1,
    )

    fun debug(
        category: String,
        message: String? = null,
        address: Address? = null,
        degrades: String? = null,
        count: Long = 1,
    ) = log(category, message, level = Level.DEBUG, address, degrades, count)

    fun warn(
        category: String,
        message: String? = null,
        address: Address? = null,
        degrades: String? = null,
        count: Long = 1,
    ) = log(category, message, level = Level.WARN, address, degrades, count)

    fun err(
        category: String,
        message: String? = null,
        address: Address? = null,
        degrades: String? = null,
        count: Long = 1,
    ) = log(category, message, level = Level.ERROR, address, degrades, count)

    /**
     * Record a materialization degradation: an ordinary [log] carrying a [degrades], which is what
     * marks it. The [StabsDiagnostics] accumulator files every degrades-bearing event as a structured
     * [DegradationRecord] for the per-fixture dumps.
     *
     * A degradation is *an artifact that shipped in worse shape than its input allows* — a struct with
     * a field padded to `Undefined4`, a signature missing its `this`, a skeleton row that lost its
     * line. Ship nothing for the item and it is a plain [warn]; break an invariant or let a Ghidra API
     * throw where we believed it wouldn't and it is an [err] (plus a degradation, if a half-built
     * artifact is left behind). The outcome decides, not the cause: [ghistabs.materialize] `field-dropped`
     * comes from a caught exception and is still a degradation, because the struct went into the DTM
     * one field short.
     *
     * The unit is what a user opens in Ghidra — a DataType, a signature, a rendered file — not the node
     * that failed to resolve. Substituting `Undefined4` for one unresolvable field type degrades the
     * *struct*, which shipped carrying the lie. So every `?: <default>` on an apply path is a
     * degradation site by construction; that is where to look for missing ones.
     *
     * [degrades] must name where — type path, symbol, `source:line` — and [address] should be passed
     * whenever there is one, so the degradation bookmarks where the damage landed. A degradation
     * nobody can navigate to is a warn with extra steps, and this is what keeps the dumps a punch list.
     */
    fun degradation(category: String, degrades: String, detail: String? = null, address: Address? = null) =
        log(category, detail, Level.WARN, address, degrades, 1)
}

object DummySink : DiagnosticSink {
    override fun log(
        category: String,
        message: String?,
        level: Level,
        address: Address?,
        degrades: String?,
        count: Long,
    ) {}
}

/** Fan-out sink — tees the [StabsDiagnostics] accumulator alongside a terminal (Bookmark/Capturing). */
class TeeSink(private vararg val sinks: DiagnosticSink?) : DiagnosticSink {
    override fun log(
        category: String,
        message: String?,
        level: Level,
        address: Address?,
        degrades: String?,
        count: Long,
    ) {
        for (s in sinks) s?.log(category, message, level, address, degrades, count)
    }
}

/** Writes message-bearing diagnostics at/above [minLevel] to Ghidra's [MessageLog]. */
class MessageLogSink(private val messageLog: MessageLog, private val minLevel: Level = Level.INFO) : DiagnosticSink {
    override fun log(
        category: String,
        message: String?,
        level: Level,
        address: Address?,
        degrades: String?,
        count: Long,
    ) {
        val text = diagnosticText(degrades, message)
        if (text == null || level < minLevel) return
        val prefix = "[Stabs][${level.name}]"
        val line = if (address != null) "$prefix $category at $address: $text" else "$prefix $category: $text"
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
    override fun log(
        category: String,
        message: String?,
        level: Level,
        address: Address?,
        degrades: String?,
        count: Long,
    ) {
        if (address == null) return
        program.bookmarkManager.setBookmark(
            address,
            level.toBookmark(),
            "Stabs:$category",
            "[Stabs][${level.name}] $category: ${diagnosticText(degrades, message)}",
        )
    }
}

/** Streams each diagnostic line at or above [minLevel] to [out], flushing so the log is live. */
class WriterSink(private val minLevel: Level, private val out: Writer) : DiagnosticSink {
    override fun log(
        category: String,
        message: String?,
        level: Level,
        address: Address?,
        degrades: String?,
        count: Long,
    ) {
        val text = diagnosticText(degrades, message)
        if (text == null || level < minLevel) return
        val at = address?.let { "[@$it]" } ?: ""
        out.append("[$level][$category]$at $text\n")
        out.flush()
    }
}
