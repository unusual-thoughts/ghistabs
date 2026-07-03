package ghistabs.diagnose

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Program

/**
 * Places a Ghidra bookmark for any addressed diagnostic (function entry, data, vtable). A bookmark
 * is a navigation marker, so it is unconditional — no level gate; the bookmark's type carries the
 * severity ([toBookmark]). Counting and MessageLog output are other tee'd sinks' jobs.
 */
class BookmarkSink(private val program: Program) : DiagnosticSink {
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

/** Writes message-bearing diagnostics at/above [minLevel] to Ghidra's [MessageLog]. */
class MessageLogSink(private val messageLog: MessageLog, private val minLevel: Level = Level.INFO) : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        if (message == null || level < minLevel) return
        val prefix = "[Stabs][${level.name}]"
        val line = if (address != null) "$prefix $category at $address: $message" else "$prefix $category: $message"
        if (level == Level.ERROR) messageLog.appendMsg("ERROR: $line") else messageLog.appendMsg(line)
    }
}

fun Level.toBookmark() = when (this) {
    Level.DEBUG -> BookmarkType.ANALYSIS
    Level.INFO -> BookmarkType.INFO
    Level.WARN -> BookmarkType.WARNING
    Level.ERROR -> BookmarkType.ERROR
}
