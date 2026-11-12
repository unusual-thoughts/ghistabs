package ghicpp

import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.util.task.TaskMonitor

/**
 * Pre-12: the test-side twin of `ghistabs.importer`'s shim, which supplies the one-argument `remove`
 * that 12.0 added. That one is declared in its caller's package so that 12.0+, which does not compile
 * it, has no import left pointing at nothing; the `ghicpp` tests need their own copy for the same
 * reason.
 */
fun DataTypeManager.remove(dataType: DataType): Boolean = remove(dataType, TaskMonitor.DUMMY)
