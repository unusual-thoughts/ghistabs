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
 * Lays gcc SJLJ LSDAs as data: the header, call-site, action and type tables [SjljLsda] reads, each
 * field typed and commented, labelled [LABEL] in the namespace of each function that stores it. The
 * header and action records are laid by Ghidra's own [LSDAHeader] and [LSDAActionTable], so they read
 * as the DWARF tables Ghidra lays do; the rest, which those classes can only reach through DWARF
 * call-site records, from [SjljLsda].
 */
class SjljLsdaApplier(val program: Program, private val monitor: TaskMonitor, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    private val listing = program.listing

    /**
     * Lay every parsed LSDA in [stored], then the unreferenced ones packed after each
     * ([layUnreferenced]); returns how many in all.
     */
    fun layAll(stored: Map<Address, StoredLsda>): Int {
        val laid = sortedMapOf<Address, Long>()
        for ((at, found) in stored) {
            monitor.checkCancelled()
            val lsda = found.lsda ?: run {
                warn("lsda-unparsed", "no SJLJ LSDA where ${found.registrations.first().store} stores one", at)
                continue
            }
            if (lay(at, lsda)) {
                label(at, found.registrations)
                laid[at] = lsda.size
            }
        }
        return laid.size + layUnreferenced(laid)
    }

    /**
     * The linker keeps the `.gcc_except_table` of every COMDAT copy it discards, so the LSDAs the kept
     * functions store are interleaved with ones nothing stores. From the end of each [laid] LSDA up
     * to the next, lay each that parses, after the up-to-3 zero bytes that align one with a type
     * table, until a byte that starts none.
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
                if (!lay(next, lsda)) break
                if (pad > 0) program.forceCreateData(at, AlignmentDataType(), pad)
                count += 1
                at = next + lsda.size
            }
        }
        return count
    }

    /**
     * Lay [lsda]'s fields at [at], unless a function's body covers them: then the pair was not a
     * registration. Ghidra's [LSDAHeader] lays the header, labelled `lsda_exception_table_<address>`,
     * and its [LSDAActionTable] the action records; the call sites, which are not the DWARF records
     * its `LSDACallSiteTable` reads, and the type table and exception specs, which its
     * `LSDATypeTable` can only reach through that call-site parse, are laid from [lsda]. Ghidra's
     * classes skip a field whose bytes already hold data, so the extent is cleared first.
     */
    private fun lay(at: Address, lsda: SjljLsda): Boolean {
        val end = at + (lsda.size - 1)
        if (program.functionManager.getFunctionsOverlapping(AddressSet(at, end)).hasNext()) {
            warn("lsda-in-function", "LSDA would cover ${lsda.size} bytes of a function", at)
            return false
        }
        listing.clearCodeUnits(at, end, false)
        val headerEnd = try {
            layWithGhidra(at, lsda)
        } catch (e: MemoryAccessException) {
            warn("lsda-lay-error", "Ghidra's LSDA classes: $e", at)
            null
        }
        val ours = lsda.items.filter {
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
    private fun layWithGhidra(at: Address, lsda: SjljLsda): Address {
        val region = RegionDescriptor(program.memory.getBlock(at))
        val header = LSDAHeader(TaskMonitor.DUMMY, program, region)
        header.create(at)
        if (lsda.actions.isNotEmpty()) {
            LSDAActionTable(TaskMonitor.DUMMY, program, region)
                .create(lsda.actions.first().at, lsda.actions.last().at)
        }
        return header.nextAddress
    }

    /** [LABEL] in each storing function's namespace, beside the header's global label. */
    private fun label(at: Address, regs: List<Registration>) {
        regs.mapNotNull { program.functionManager.getFunctionContaining(it.store) }.distinct()
            .forEach { program.symbolTable.createLabel(at, LABEL, it, SourceType.ANALYSIS) }
    }

    companion object {
        const val LABEL = "lsda"

        /** The alignment gcc gives an LSDA with a type table, padding with zeros. */
        private const val ALIGN = 4
    }
}
