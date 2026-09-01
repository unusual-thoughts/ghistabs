package ghistabs

import ghidra.app.util.importer.*
import ghidra.app.util.opinion.LoaderService
import ghidra.util.task.TaskMonitor
import ghistabs.LoadedProgram
import java.io.File

/**
 * Pre-12: `AutoImporter`. Only `importFresh` takes a `LoadSpecChooser`, which is how the compiler hint
 * gets in (`importByUsingBestGuess` hard-codes `CHOOSE_THE_FIRST_PREFERRED`). One consumer, given at
 * import time, covers the program too: `LoadResults` here is not `AutoCloseable` and its
 * `getPrimaryDomainObject()` takes out no reference of its own.
 */
fun Any.loadProgram(binary: File, compiler: String? = "gcc", log: MessageLog? = null, monitor: TaskMonitor? = null) =
    LoadedProgram(
        AutoImporter.importFresh(
            binary,
            null,
            null,
            this,
            log ?: MessageLog(),
            monitor ?: TaskMonitor.DUMMY,
            LoaderService.ACCEPT_ALL,
            compiler?.let { CsHintLoadSpecChooser(it) } ?: LoadSpecChooser.CHOOSE_THE_FIRST_PREFERRED,
            null,
            OptionChooser.DEFAULT_OPTIONS,
        ).primaryDomainObject,
        this,
    )
