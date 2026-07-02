package ghistabs.diagnose

import ghidra.program.model.address.Address
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Program

/**
 * Emitting terminal: bookmarks diagnostics at intrinsically-meaningful addresses (function entry,
 * data, vtable), then forwards to [parent] (the MessageLog adapter). Suppresses everything below
 * [minLevel]. Counting is the [StabsDiagnostics] accumulator's job — this sink no longer touches it,
 * so it's tee'd alongside, not chained through. Messages are prefixed `[Stabs] <category>: <message>`.
 */
class BookmarkSink(
    private val program: Program,
    private val parent: DiagnosticSink,
    private val minLevel: Level = Level.INFO,
) : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        if (level < minLevel) return
        if (address != null) {
            program.bookmarkManager.setBookmark(
                address,
                BookmarkType.WARNING,
                "Stabs:$category",
                "[Stabs][${level.name}] $category: $message",
            )
        }
        parent.log(category, message, level, address, count)
    }
}
