package ghistabs.importer

import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.data.DataUtilities.ClearDataMode
import ghidra.program.model.data.Enum
import ghidra.program.model.listing.CommentType
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
    StabType.N_FUN, StabType.N_STSYM, StabType.N_LCSYM, StabType.N_ROSYM,
    StabType.N_SLINE, StabType.N_SO, StabType.N_SOL, StabType.N_BNSYM, StabType.N_ENSYM,
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

    fun apply(): Int {
        val records = StabReader.fromProgram(program)?.physicalRecords()
        if (records.isNullOrEmpty()) return 0

        val stabBlock = program.memory.getBlock(".stab") ?: return 0
        val stabstrBlock = program.memory.getBlock(".stabstr") ?: return 0

        program.runTransaction("Stabs: overlay .stab section") {
            val struct = stabRecordStruct(stabTypeEnum())
            records.forEach { overlay(it, struct, stabBlock.start, stabstrBlock.start, stabstrBlock.size) }
        }
        return records.size
    }

    private fun overlay(
        rec: PhysicalStab,
        struct: Structure,
        stabStart: Address,
        stabstrStart: Address,
        stabstrSize: Long,
    ) {
        val recAddr = stabStart + rec.byteOffset
        DataUtilities.createData(program, recAddr, struct, struct.length, ClearDataMode.CLEAR_ALL_CONFLICT_DATA)
        program.listing.setComment(recAddr, CommentType.EOL, comment(rec))

        // n_strx (field 0) → the string it names in .stabstr; define that string if untouched.
        if (rec.strx != 0L && rec.stabstrOffset in 0 until stabstrSize) {
            val nameAddr = stabstrStart + rec.stabstrOffset
            addRef(recAddr, nameAddr)
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
        if (rec.record.type in VALUE_IS_ADDRESS && !(rec.record.type == StabType.N_FUN && rec.record.name.isEmpty())) {
            val target = program.addressFactory.defaultAddressSpace.getAddress(rec.record.value)
            if (program.memory.contains(target)) addRef(recAddr + 8, target)
        }
    }

    private fun addRef(from: Address, to: Address) =
        program.referenceManager.addMemoryReference(from, to, RefType.DATA, SourceType.IMPORTED, 0)

    private fun comment(rec: PhysicalStab) =
        if (rec.record.name.isEmpty()) rec.record.type.name else "${rec.record.type.name} \"${rec.record.name}\""

    private fun stabTypeEnum(): Enum = (ctx.dtm.getDataType(CATEGORY, "StabType") as? Enum) ?: run {
        val e = EnumDataType(CATEGORY, "StabType", 1, ctx.dtm)
        StabType.entries.filter { it != StabType.UNKNOWN }.forEach { e.add(it.name, it.code.toLong()) }
        ctx.dtm.addDataType(e, DataTypeConflictHandler.KEEP_HANDLER) as Enum
    }

    private fun stabRecordStruct(nType: Enum): Structure =
        (ctx.dtm.getDataType(CATEGORY, "StabRecord") as? Structure) ?: run {
            val s = StructureDataType(CATEGORY, "StabRecord", 0, ctx.dtm)
            s.add(DWordDataType.dataType, "n_strx", "index into .stabstr (per-CU)")
            s.add(nType, "n_type", "stab type code")
            s.add(ByteDataType.dataType, "n_other", null)
            s.add(WordDataType.dataType, "n_desc", null)
            s.add(DWordDataType.dataType, "n_value", "address / offset / register (per type)")
            ctx.dtm.addDataType(s, DataTypeConflictHandler.KEEP_HANDLER) as Structure
        }
}
