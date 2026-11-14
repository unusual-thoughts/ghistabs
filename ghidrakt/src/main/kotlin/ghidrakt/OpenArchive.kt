package ghidrakt

import ghidra.program.model.data.DataTypeManager

/** A data type archive opened by [openArchiveReadOnly]; [close] lets go of it. */
class OpenArchive(val dataTypeManager: DataTypeManager, private val release: () -> Unit) : AutoCloseable {
    override fun close() = release()
}
