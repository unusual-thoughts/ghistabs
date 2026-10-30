package ghistabs.cpp

import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghistabs.cpp.ClassHierarchyRecords.Companion.readClassRecord
import ghistabs.cpp.abi.VtableRecord

/**
 * The classes [ClassHierarchyRecords] holds, by namespace id, each with its bases resolved to the others.
 * A base the record knows by id alone is a class with no bases, and one it knows by name alone also has no
 * namespace. The record keeps no vtables, so none has [ClassDecl.vftables].
 */
fun Program.recordedClasses(): Map<Long, ClassDecl> {
    val records = readClassRecord().orEmpty()
    val byId = mutableMapOf<Long, RecordedClass>()
    val byName = mutableMapOf<String, RecordedClass>()
    fun classOf(id: Long): RecordedClass = byId.getOrPut(id) {
        val ns = symbolTable.getSymbol(id)?.`object` as? Namespace
        RecordedClass(ns?.name ?: "?", ns)
    }
    for ((id, entry) in records) {
        classOf(id).bases += entry.bases.map { b ->
            val cls =
                b.namespaceId?.let(::classOf) ?: byName.getOrPut(b.name ?: "?") { RecordedClass(b.name ?: "?", null) }
            ClassBase(cls, b.isVirtual, b.access, b.offset)
        }
    }
    return byId.filterKeys { it in records }
}

private class RecordedClass(override val name: String, override val ns: Namespace?) : ClassDecl {
    override val bases = mutableListOf<ClassBase>()
    override val ancestors by lazy { super.ancestors }
    override val vftables get() = emptyList<VtableRecord>()

    override fun toString() = ns?.getName(true) ?: name
}
