package ghistabs.importer

import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.CommentType
import ghidra.program.model.mem.MemoryBlock
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
    val stabBlock: MemoryBlock by lazy { program.memory.getBlock(".stab") }
    val stabstrBlock: MemoryBlock by lazy { program.memory.getBlock(".stabstr") }

    fun apply(): Int {
        val records = StabReader.fromProgram(program)?.physicalRecords()?.toList()
        if (records.isNullOrEmpty()) return 0

        program.runTransaction("Stabs: overlay .stab section") {
            var funcStart: Address? = null
            records.forEach { rec ->
                if (rec.type == StabType.N_FUN) {
                    funcStart = rec.name.ifEmpty { null }?.let { ctx.resolver.buildAddress(rec.value) }
                }
                rec.overlay(funcStart)
            }
        }
        return records.size
    }

    val StabRecord.addr get() = stabBlock.start + index.toLong() * STAB_RECORD_SIZE
    val StabRecord.nameAddr get() = stabstrBlock.start + stabstrOffset
    val StabRecord.comment
        get() = if (name.isEmpty()) type.name else "${type.name} \"$name\""

    private fun StabRecord.overlay(funcStart: Address?) {
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
