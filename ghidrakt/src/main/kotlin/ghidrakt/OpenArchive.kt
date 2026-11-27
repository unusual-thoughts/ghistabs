package ghidrakt

import generic.jar.ResourceFile
import ghidra.program.model.data.DataTypeManager

/** A data type archive opened by [readOnly]; [close] lets go of it. */
class OpenArchive(val dataTypeManager: DataTypeManager, private val release: () -> Unit) : AutoCloseable {
    override fun close() = release()

    companion object {
        /** The file archive [file], open read-only, however this Ghidra opens one. */
        fun readOnly(file: ResourceFile): OpenArchive = openArchiveReadOnly(file)
    }
}
