package ghistabs

import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.opinion.LoaderMap
import ghidra.app.util.opinion.LoaderService
import ghidra.util.task.TaskMonitor
import kotlin.reflect.KClass

/** 12.2+ (GP-6920): the real call. See the pre-12.2 copy for why it hangs off `LoaderService::class`. */
@Suppress("UnusedReceiverParameter")
internal fun KClass<LoaderService>.getAllSupportedLoadSpecs(provider: ByteProvider, monitor: TaskMonitor): LoaderMap =
    LoaderService.getAllSupportedLoadSpecs(provider, monitor)
