package ghidrakt

import generic.jar.ResourceFile
import ghidra.program.model.data.FileDataTypeManager

/** Before 12.2: a file archive is a [FileDataTypeManager] of its own. */
fun openArchiveReadOnly(file: ResourceFile): OpenArchive {
    val dtm = FileDataTypeManager.openFileArchive(file, false)
    return OpenArchive(dtm) { dtm.close() }
}
