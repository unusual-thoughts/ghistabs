package ghistabs.importer

import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.util.task.TaskMonitor

/**
 * Pre-12: `remove` takes a monitor. 12.0 (GP-5654) added the one-argument form and deprecated this
 * one; 12.3 (GP-7104) deleted it. Call sites use the one-argument form throughout, and below 12.0 no
 * member shadows this, so it supplies it.
 *
 * Declared in the caller's own package rather than `ghistabs`, so that 12.0+ — where this file is not
 * compiled at all — has no import left pointing at nothing.
 *
 * [TaskMonitor.DUMMY] because the only caller removes a handful of empty conflict forks, one at a
 * time: there is nothing to report and nothing worth cancelling between two of them.
 */
fun DataTypeManager.remove(dataType: DataType): Boolean = remove(dataType, TaskMonitor.DUMMY)
