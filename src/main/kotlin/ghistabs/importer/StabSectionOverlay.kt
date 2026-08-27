package ghistabs.importer

import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.CommentType
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghistabs.diagnose.DiagnosticSink
import ghistabs.forceCreateData
import ghistabs.parse.STAB_RECORD_SIZE
import ghistabs.parse.StabReader
import ghistabs.parse.StabRecord
import ghistabs.parse.StabType
import ghistabs.parse.stabRecordDataType
import ghistabs.plus
import ghistabs.runTransaction

/** Stab types whose `n_value` is an absolute address in this image (post-link). */
private val VALUE_IS_ADDRESS = setOf(
    StabType.N_FUN,
    StabType.N_STSYM,
    StabType.N_LCSYM,
    StabType.N_ROSYM,
    StabType.N_SLINE,
    StabType.N_SO,
    StabType.N_SOL,
    StabType.N_BNSYM,
    StabType.N_ENSYM,
    StabType.N_LBRAC,
    StabType.N_RBRAC,
)

/**
 * The subset of [VALUE_IS_ADDRESS] whose `n_value` is relative to the enclosing function in
 * stabs-in-sections (block scopes and line numbers), so it must be rebased onto the function start.
 */
private val VALUE_IS_FUNC_RELATIVE = setOf(StabType.N_SLINE, StabType.N_LBRAC, StabType.N_RBRAC)

/**
 * Overlays a decoded [StabRecord][ghistabs.parse.StabRecord] structure onto every 12-byte record
 * in `.stab`, so the listing view shows named fields instead of raw bytes: `n_strx` references the
 * string it names in `.stabstr`, and address-bearing records (`N_FUN`, `N_STSYM`, …) reference the
 * code/data their `n_value` points at. Idempotent — re-runs reuse the `/stabs/StabRecord` datatype.
 */
class StabSectionOverlay(private val ctx: ImportContext<*>) : DiagnosticSink by ctx {
    private val program = ctx.program

    fun apply(): Int {
        // Whichever blocks the reader used: `.stab`/`.stabstr` on ELF/PE, `.symtab`/`.strtab` on a.out,
        // where the records are entries in the linker symbol table. Record N sits at
        // N * STAB_RECORD_SIZE either way — StabReader indexes every physical entry, including the
        // link-time symbols it skips under SYMTAB.
        val source = StabReader.sourceOf(program) ?: return 0
        val records = StabReader.fromProgram(program)?.physicalRecords()?.toList().orEmpty()
        if (records.isEmpty()) return 0

        ctx.monitor.initialize(records.size.toLong(), "Stabs: overlaying stab records")
        program.runTransaction("Stabs: overlay stab records") {
            var funcStart: Address? = null
            records.forEach { rec ->
                ctx.monitor.increment()
                if (rec.type == StabType.N_FUN) {
                    funcStart = rec.name.ifEmpty { null }?.let { ctx.resolver.buildAddress(rec.value) }
                }
                rec.overlay(source, funcStart)
            }
        }
        return records.size
    }

    private val StabRecord.comment
        get() = if (name.isEmpty()) type.name else "${type.name} \"$name\""

    private fun StabRecord.overlay(source: StabReader.Source, funcStart: Address?) {
        val addr = source.records.start + index.toLong() * STAB_RECORD_SIZE
        val nameAddr = source.strings.start + stabstrOffset

        program.forceCreateData(addr, stabRecordStruct)
        program.listing.setComment(addr, CommentType.EOL, comment)

        // n_strx (field 0) → the string it names in .stabstr; define that string if untouched.
        if (raw.strx != 0u) {
            addRef(addr, nameAddr)
            if (program.listing.getDefinedDataContaining(nameAddr) == null) {
                runCatching {
                    program.forceCreateData(nameAddr, TerminatedStringDataType.dataType, length = -1)
                }.onFailure { warn("stab-string-create-failed", "$nameAddr: ${it.message}", nameAddr) }
            }
        }

        // n_value (field 4, offset 8) → the code/data address it records, rebased onto the
        // enclosing function for the func-relative types (block scopes, line numbers).
        if (type in VALUE_IS_ADDRESS && !(type == StabType.N_FUN && name.isEmpty())) {
            val target = ctx.resolver.stabAddress(value, funcStart.takeIf { type in VALUE_IS_FUNC_RELATIVE })
            if (program.memory.contains(target)) addRef(addr + 8, target)
        }
    }

    private fun addRef(from: Address, to: Address) =
        program.referenceManager.addMemoryReference(from, to, RefType.DATA, SourceType.IMPORTED, 0)

    private val stabRecordStruct by lazy { ctx.dtm.stabRecordDataType() }
}
