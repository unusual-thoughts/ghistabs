package ghidra.program.database.sourcemap

import ghidra.program.model.listing.Program
import ghidra.program.model.sourcemap.SourcePathTransformer
import java.util.WeakHashMap

/**
 * `UserDataPathTransformer.getPathTransformer` as of 11.3, over a table held in memory rather than in
 * program user data. Registering a source root and reading a local file back through it both work; it
 * is only the persistence, and Ghidra's own "Source Files and Transforms" dialog, that are missing.
 */
object UserDataPathTransformer {
    private val byProgram = WeakHashMap<Program, SourcePathTransformer>()

    @JvmStatic
    fun getPathTransformer(program: Program): SourcePathTransformer =
        synchronized(byProgram) { byProgram.getOrPut(program) { InMemoryPathTransformer() } }
}

private class InMemoryPathTransformer : SourcePathTransformer {
    private val directories = linkedMapOf<String, String>()

    override fun addDirectoryTransform(sourceDirectory: String, transformedDirectory: String) {
        directories[sourceDirectory] = transformedDirectory
    }

    /** Longest matching directory wins, so a transform for a subdirectory beats one for its parent. */
    override fun getTransformedPath(sourceFile: SourceFile, useExistingAsDefault: Boolean): String? =
        directories.entries
            .filter { sourceFile.path.startsWith(it.key) }
            .maxByOrNull { it.key.length }
            ?.let { (recorded, local) -> local + sourceFile.path.removePrefix(recorded) }
            ?: sourceFile.path.takeIf { useExistingAsDefault }
}
