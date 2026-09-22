package ghistabs

import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.opinion.LoaderMap
import ghidra.app.util.opinion.LoaderService
import ghidra.util.task.TaskMonitor

/** 12.2+ (GP-6920): the real call. See the pre-12.2 copy for why a name of ours stands in at all. */
internal fun allSupportedLoadSpecs(provider: ByteProvider, monitor: TaskMonitor): LoaderMap =
    LoaderService.getAllSupportedLoadSpecs(provider, monitor)
