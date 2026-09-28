package ghistabs

import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.opinion.LoaderMap
import ghidra.app.util.opinion.LoaderService
import ghidra.util.task.TaskMonitor
import kotlin.reflect.KClass

/**
 * Pre-12.2: the monitor-less form, which is all there is — 12.2 (GP-6920) added the monitor so the
 * import dialog can say which loader it is trying, and deprecated this one. A static cannot be
 * backported onto Ghidra's own class, so it hangs off `LoaderService::class` instead, which every
 * release has, and the call site still names the real API.
 */
@Suppress("UNUSED_PARAMETER", "UnusedParameter", "UnusedReceiverParameter")
internal fun KClass<LoaderService>.getAllSupportedLoadSpecs(provider: ByteProvider, monitor: TaskMonitor): LoaderMap =
    LoaderService.getAllSupportedLoadSpecs(provider)
