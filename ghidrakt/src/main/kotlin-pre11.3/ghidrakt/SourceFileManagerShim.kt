package ghidrakt

import ghidra.program.model.listing.Program
import ghidra.program.model.sourcemap.InMemorySourceFileManager
import ghidra.program.model.sourcemap.SourceFileManager

/**
 * `Program.getSourceFileManager()` arrives in 11.3. Callers reach it through `import ghidrakt.*`.
 */
val Program.sourceFileManager: SourceFileManager get() = InMemorySourceFileManager.of(this)
