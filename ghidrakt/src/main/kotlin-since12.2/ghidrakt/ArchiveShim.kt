package ghidrakt

import generic.jar.ResourceFile
import ghidra.program.database.dtarchive.DataTypeArchiveFactory
import ghidra.util.task.TaskMonitor

/** 12.2+: a file archive is opened through [DataTypeArchiveFactory] and released by its consumer. */
fun openArchiveReadOnly(file: ResourceFile): OpenArchive {
    val consumer = Any()
    val archive = DataTypeArchiveFactory.openReadOnly(file, consumer, TaskMonitor.DUMMY)
    return OpenArchive(archive.dataTypeManager) { archive.release(consumer) }
}
