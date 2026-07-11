package ghistabs.importer

import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.data.DataUtilities.ClearDataMode
import ghidra.program.model.listing.CommentType
import ghidra.program.model.mem.MemoryBlock
import ghidra.program.model.symbol.RefType
import ghidra.program.model.symbol.SourceType
import ghistabs.diagnose.DiagnosticSink
import ghistabs.parse.PhysicalStab
import ghistabs.parse.StabReader
import ghistabs.parse.StabType
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

private val CATEGORY = CategoryPath("/stabs")

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
        val records = StabReader.fromProgram(program)?.physicalRecords()
        if (records.isNullOrEmpty()) return 0

        program.runTransaction("Stabs: overlay .stab section") {
            records.forEach { it.overlay() }
        }
        return records.size
    }

    val PhysicalStab.addr get() = stabBlock.start + byteOffset
    val PhysicalStab.nameAddr get() = stabstrBlock.start + stabstrOffset
    val PhysicalStab.comment
        get() = if (record.name.isEmpty()) record.type.name else "${record.type.name} \"${record.name}\""

    private fun PhysicalStab.overlay() {
        DataUtilities.createData(
            program,
            addr,
            stabRecordStruct,
            stabRecordStruct.length,
            ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
        )
        program.listing.setComment(addr, CommentType.EOL, comment)

        // n_strx (field 0) → the string it names in .stabstr; define that string if untouched.
        if (strx != 0L) {
            addRef(addr, nameAddr)
            if (program.listing.getDefinedDataContaining(nameAddr) == null) {
                runCatching {
                    DataUtilities.createData(
                        program,
                        nameAddr,
                        TerminatedStringDataType.dataType,
                        -1,
                        ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
                    )
                }.onFailure { warn("stab-string-create-failed", "$nameAddr: ${it.message}", nameAddr) }
            }
        }

        // n_value (field 4, offset 8) → the code/data address it records.
        if (record.type in VALUE_IS_ADDRESS && !(record.type == StabType.N_FUN && record.name.isEmpty())) {
            val target = ctx.resolver.buildAddress(record.value)
            if (program.memory.contains(target)) addRef(addr + 8, target)
        }
    }

    private fun addRef(from: Address, to: Address) =
        program.referenceManager.addMemoryReference(from, to, RefType.DATA, SourceType.IMPORTED, 0)

    private val stabTypeEnum by lazy {
        ctx.dtm.resolve(
            EnumDataType(CATEGORY, "StabType", 1, ctx.dtm).apply {
                StabType.entries.filter { it != StabType.UNKNOWN }.forEach { add(it.name, it.code.toLong()) }
            },
            DataTypeConflictHandler.KEEP_HANDLER,
        )
    }

    private val stabRecordStruct by lazy {
        ctx.dtm.resolve(
            StructureDataType(CATEGORY, "StabRecord", 0, ctx.dtm).apply {
                add(DWordDataType.dataType, "n_strx", "index into .stabstr (per-CU)")
                add(stabTypeEnum, "n_type", "stab type code")
                add(ByteDataType.dataType, "n_other", null)
                add(WordDataType.dataType, "n_desc", "line number")
                add(DWordDataType.dataType, "n_value", "address / offset / register (per type)")
            },
            DataTypeConflictHandler.KEEP_HANDLER,
        )
    }
}
