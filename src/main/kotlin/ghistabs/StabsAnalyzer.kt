package ghistabs

import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.importer.MessageLog
import ghidra.framework.options.Options
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.importer.ImportContext
import ghistabs.importer.StabsImporter
import ghistabs.importer.StabsOptions

/**
 * Imports STABS debug info (.stab/.stabstr) into Ghidra: types, function signatures,
 * locals, C++ classes, vtables. Targets PE/ELF binaries produced by Cygwin gcc 3.4.4.
 *
 * Auto-runs once per program (gated by [STABS_DONE_OPTION]); re-runnable via the
 * `Tools > Stabs > Re-import` menu action.
 */
class StabsAnalyzer :
    AbstractAnalyzer(
        "Stabs Importer",
        "Imports STABS debug info (.stab/.stabstr) — types, function signatures, locals, C++ classes, vtables.",
        AnalyzerType.BYTE_ANALYZER,
    ) {
    init {
        priority = AnalysisPriority(100) // LATER priority
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun getDefaultEnablement(program: Program?): Boolean = true

    override fun canAnalyze(program: Program?): Boolean {
        if (program == null) return false
        if (isStabsDone(program)) return false
        val mem = program.memory
        return mem.getBlock(".stab") != null && mem.getBlock(".stabstr") != null
    }

    override fun registerOptions(
        options: Options,
        program: Program?,
    ) {
        options.registerOption(
            OPT_PLATE_COMMENTS,
            true,
            null,
            "Apply plate comments at lexical scopes when LBRAC/RBRAC info is present.",
        )
        options.registerOption(
            OPT_VTABLES,
            true,
            null,
            "Synthesise <Class>_vtable structs and apply at _ZTV addresses.",
        )
    }

    override fun added(
        program: Program?,
        set: AddressSetView?,
        monitor: TaskMonitor?,
        log: MessageLog?,
    ): Boolean {
        program ?: return false
        log ?: return false
        monitor ?: return false
        if (isStabsDone(program)) return true // idempotent re-trigger; treat as success.

        val opts = program.getOptions(Program.PROGRAM_INFO).getOptions(name)
        val stabsOptions =
            StabsOptions(
                applyPlateComments = opts.getBoolean(OPT_PLATE_COMMENTS, true),
                applyVtables = opts.getBoolean(OPT_VTABLES, true),
            )
        val ctx = ImportContext(program, log, monitor, stabsOptions)
        val result = StabsImporter(ctx).run()
        log.appendMsg("[Stabs] import complete: $result")
        markStabsDone(program, true)
        return true
    }

    companion object {
        @JvmField
        val STABS_DONE_OPTION: String = "Stabs Imported"

        @JvmField
        val OPT_PLATE_COMMENTS: String = "Apply scope plate comments"

        @JvmField
        val OPT_VTABLES: String = "Synthesise vtable structs"

        @JvmStatic
        fun isStabsDone(program: Program): Boolean = program.getOptions(Program.PROGRAM_INFO).getBoolean(STABS_DONE_OPTION, false)

        @JvmStatic
        fun markStabsDone(
            program: Program,
            value: Boolean,
        ) {
            val tx = program.startTransaction("Stabs: set done flag")
            try {
                program.getOptions(Program.PROGRAM_INFO).setBoolean(STABS_DONE_OPTION, value)
            } finally {
                program.endTransaction(tx, true)
            }
        }
    }
}
