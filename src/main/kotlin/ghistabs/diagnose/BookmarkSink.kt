package ghistabs.diagnose

import ghidra.app.util.importer.MessageLog
import ghidra.program.model.address.Address
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Program

/**
 * Emitting terminal: bookmarks diagnostics at intrinsically-meaningful addresses (function entry,
 * data, vtable) and writes them to Ghidra's [MessageLog]. A bookmark is a navigation marker, so it's
 * placed for any addressed log regardless of level; [minLevel] gates only the MessageLog line.
 * Counting is the [StabsDiagnostics] accumulator's job — this sink no longer touches it, so it's
 * tee'd alongside, not chained through.
 */
class BookmarkSink(
    private val program: Program,
    private val messageLog: MessageLog,
    private val minLevel: Level = Level.INFO,
) : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        if (address != null) {
            program.bookmarkManager.setBookmark(
                address,
                BookmarkType.WARNING,
                "Stabs:$category",
                "[Stabs][${level.name}] $category: $message",
            )
        }
        if (message == null || level < minLevel) return
        val prefix = "[Stabs][${level.name}]"
        val line = if (address != null) "$prefix $category at $address: $message" else "$prefix $category: $message"
        if (level == Level.ERROR) messageLog.appendMsg("ERROR: $line") else messageLog.appendMsg(line)
    }
}
