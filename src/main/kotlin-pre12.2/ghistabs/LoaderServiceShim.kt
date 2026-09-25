package ghistabs

import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.opinion.LoaderMap
import ghidra.app.util.opinion.LoaderService
import ghidra.util.task.TaskMonitor

/**
 * Pre-12.2: the monitor-less form, which is all there is — 12.2 (GP-6920) added the monitor so the
 * import dialog can say which loader it is trying, and deprecated this one. A static cannot be
 * backported onto Ghidra's own class, so this is one of the few places where the call site goes
 * through a name of ours rather than the real API.
 */
internal fun ByteProvider.allSupportedLoadSpecs(monitor: TaskMonitor = TaskMonitor.DUMMY): LoaderMap =
    LoaderService.getAllSupportedLoadSpecs(this)
