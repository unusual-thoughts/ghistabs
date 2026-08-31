package ghistabs.render

import ghidra.program.model.listing.Program
import ghidra.program.model.sourcemap.InMemorySourceFileManager
import ghidra.program.model.sourcemap.SourceFileManager

/**
 * `Program.getSourceFileManager()` arrives in 11.3. Declared once per calling package because an
 * extension is only visible unqualified where it is declared — all three reach the same instance.
 */
internal val Program.sourceFileManager: SourceFileManager get() = InMemorySourceFileManager.of(this)
