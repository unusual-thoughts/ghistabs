package ghistabs.cpp.eh

import ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor
import ghidra.app.plugin.exceptionhandlers.gcc.datatype.DwarfEncodingModeDataType
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAActionTable
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDAHeader
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.data.AlignmentDataType
import ghidra.program.model.data.PointerDataType
import ghidra.program.model.data.SignedLeb128DataType
import ghidra.program.model.data.UnsignedLeb128DataType
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.Program
import ghidra.program.model.mem.MemoryAccessException
import ghidra.program.model.symbol.SourceType
import ghidra.program.model.util.CodeUnitInsertionException
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.forceCreateData
import ghistabs.plus
import java.util.*

/**
 * Lays gcc SJLJ LSDAs as typed, commented data, labelled [LABEL] in each storing function's namespace.
 * The header and action table use Ghidra's [LSDAHeader] and [LSDAActionTable] so they match its DWARF
 * tables; the rest comes from [SjljLsda].
 */
class SjljLsdaApplier(val program: Program, private val monitor: TaskMonitor, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    private val listing = program.listing
    private val fm = program.functionManager

    /** Lays every parsed LSDA in [stored], then the unreferenced ones between them; returns how many. */
    fun layAll(stored: Map<Address, StoredLsda>): Int {
        val laid = sortedMapOf<Address, Long>()
        for ((at, found) in stored) {
            monitor.checkCancelled()
            val lsda = found.lsda ?: run {
                warn("lsda-unparsed", "no SJLJ LSDA where ${found.registrations.first().store} stores one", at)
                continue
            }
            if (lsda.lay(at)) {
                label(at, found.registrations)
                laid[at] = lsda.size
            }
        }
        return laid.size + layUnreferenced(laid)
    }

    /**
     * Lays the LSDAs nothing stores, left by COMDAT copies the linker discarded: after each [laid] one,
     * skipping up to 3 bytes of alignment, until the bytes stop parsing.
     */
    private fun layUnreferenced(laid: SortedMap<Address, Long>): Int {
        fun isZero(at: Address) = runCatching { program.memory.getByte(at).toInt() == 0 }.getOrDefault(false)
        val starts = laid.keys.toList()
        var count = 0
        for ((i, start) in starts.withIndex()) {
            monitor.checkCancelled()
            val limit = starts.getOrNull(i + 1)
            var at = start + laid.getValue(start)
            while (limit == null || at < limit) {
                val pad = (0 until ALIGN).takeWhile { isZero(at + it) }.size
                if (pad == ALIGN) break
                val next = at + pad
                if (next == limit) {
                    program.forceCreateData(at, AlignmentDataType(), pad)
                    break
                }
                val lsda = SjljLsda.parse(program, next) ?: break
                if (limit != null && next + lsda.size > limit) break
                if (!lsda.lay(next)) break
                if (pad > 0) program.forceCreateData(at, AlignmentDataType(), pad)
                count += 1
                at = next + lsda.size
            }
        }
        return count
    }

    /**
     * Lays this LSDA at [at]; false if a function body covers it, so it was no registration. Clears the
     * extent first, since Ghidra's classes skip bytes that already hold data.
     */
    private fun SjljLsda.lay(at: Address): Boolean {
        val end = at + (size - 1)
        if (fm.getFunctionsOverlapping(AddressSet(at, end)).hasNext()) {
            warn("lsda-in-function", "LSDA would cover $size bytes of a function", at)
            return false
        }
        listing.clearCodeUnits(at, end, false)
        val headerEnd = try {
            layWithGhidra(at)
        } catch (e: MemoryAccessException) {
            warn("lsda-lay-error", "Ghidra's LSDA classes: $e", at)
            null
        }
        val ours = items.filter {
            headerEnd == null || (it.at >= headerEnd && it.kind != SjljLsda.Kind.SLEB128)
        }
        for ((addr, length, kind, comment) in ours) {
            val dt = when (kind) {
                SjljLsda.Kind.ENCODING -> DwarfEncodingModeDataType.dataType
                SjljLsda.Kind.ULEB128 -> UnsignedLeb128DataType.dataType
                SjljLsda.Kind.SLEB128 -> SignedLeb128DataType.dataType
                SjljLsda.Kind.POINTER -> PointerDataType(program.dataTypeManager)
                SjljLsda.Kind.ALIGNMENT -> AlignmentDataType()
            }
            try {
                program.forceCreateData(addr, dt, length)
            } catch (e: CodeUnitInsertionException) {
                warn("lsda-lay-error", "${dt.name}: $e", addr)
                continue
            }
            listing.setComment(addr, CommentType.EOL, comment)
        }
        return true
    }

    /** Lay [lsda]'s header and action records with Ghidra's classes; returns the address past the header. */
    private fun SjljLsda.layWithGhidra(at: Address): Address {
        val region = RegionDescriptor(program.memory.getBlock(at))
        val header = LSDAHeader(TaskMonitor.DUMMY, program, region)
        header.create(at)
        if (actions.isNotEmpty()) {
            LSDAActionTable(TaskMonitor.DUMMY, program, region)
                .create(actions.first().at, actions.last().at)
        }
        return header.nextAddress
    }

    /** [LABEL] in each storing function's namespace, beside the header's global label. */
    private fun label(at: Address, regs: List<Registration>) {
        regs.mapNotNull { fm.getFunctionContaining(it.store) }.distinct()
            .forEach { program.symbolTable.createLabel(at, LABEL, it, SourceType.ANALYSIS) }
    }

    companion object {
        const val LABEL = "lsda"

        /** The alignment gcc gives an LSDA with a type table, padding with zeros. */
        private const val ALIGN = 4
    }
}
