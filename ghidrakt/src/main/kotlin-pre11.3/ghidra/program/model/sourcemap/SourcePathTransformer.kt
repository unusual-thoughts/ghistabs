package ghidra.program.model.sourcemap

import ghidra.program.database.sourcemap.SourceFile

/** The transform table 11.3 introduced; nothing is recorded and nothing resolves below it. */
interface SourcePathTransformer {
    fun addDirectoryTransform(sourceDirectory: String, transformedDirectory: String)

    fun getTransformedPath(sourceFile: SourceFile, useExistingAsDefault: Boolean): String?
}
