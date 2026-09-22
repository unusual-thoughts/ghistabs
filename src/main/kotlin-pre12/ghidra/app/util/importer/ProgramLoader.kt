package ghidra.app.util.importer

import ghidra.app.util.opinion.LoadResults
import ghidra.app.util.opinion.LoaderService
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import java.io.File

/**
 * The builder 12.0 replaced [AutoImporter] with, over [AutoImporter]. Only the settings the call
 * site uses are here; the rest of 12's builder is project placement, library search and loader
 * arguments, none of which a headless import of one file needs.
 *
 * The compiler hint is the one `AutoImporter` never took directly: `importByUsingBestGuess`
 * hard-codes `CHOOSE_THE_FIRST_PREFERRED`, and only `importFresh` takes a [LoadSpecChooser] at all.
 */
object ProgramLoader {
    @JvmStatic
    fun builder() = Builder()

    class Builder internal constructor() {
        private var file: File? = null
        private var compilerSpecId: String? = null
        private var log = MessageLog()
        private var monitor: TaskMonitor = TaskMonitor.DUMMY

        fun source(f: File) = apply { file = f }

        fun compiler(id: String?) = apply { compilerSpecId = id }

        fun log(l: MessageLog?) = apply { log = l ?: MessageLog() }

        fun monitor(m: TaskMonitor?) = apply { monitor = m ?: TaskMonitor.DUMMY }

        /**
         * Loaded with the builder as consumer, which is what 12's `load()` does — it delegates to
         * the consumer-taking form passing `this`. That is the whole of the ownership difference:
         * before 12 the consumer was named here, at import time, and the loaded programs were handed
         * out carrying no reference of their own; see `Loaded.getDomainObject` in [ghistabs].
         */
        fun load(): LoadResults<Program> = AutoImporter.importFresh(
            file,
            null,
            null,
            this,
            log,
            monitor,
            LoaderService.ACCEPT_ALL,
            compilerSpecId?.let { CsHintLoadSpecChooser(it) } ?: LoadSpecChooser.CHOOSE_THE_FIRST_PREFERRED,
            null,
            OptionChooser.DEFAULT_OPTIONS,
        )
    }
}
