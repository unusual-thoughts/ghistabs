package ghistabs.cpp.abi.itanium

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghistabs.cpp.ClassDecl
import ghistabs.cpp.ClassNaming
import ghistabs.cpp.abi.VtableRecord
import ghistabs.cpp.recover.VirtualBases

/**
 * Classes off their Itanium vtables, for [VirtualBases]: each class a primary `vtable` label is in, its
 * virtual bases where that vtable's vbase offsets put them, and each base off its typeinfo, in the
 * namespace its `typeinfo` label is in. Unlike [ItaniumClasses], it takes a class whose labels the
 * demangler left outside a class namespace, as the stabs import's are.
 */
class VtableClasses(private val program: Program) {
    private val reader = Rtti.Reader(program)

    // Each base seen, by typeinfo.
    private val bases = mutableMapOf<Address, VtableClass>()

    /** A class by its typeinfo, with the [vtable] its labels name where it has one. */
    private inner class VtableClass(
        override val ns: Namespace?,
        override val name: String,
        typeinfo: Address,
        private val vtable: VtableRecord? = null,
    ) : TypeinfoClass(program, reader, typeinfo) {
        override val vftables get() = listOfNotNull(vtable)

        override val primary get() = vtable

        override fun classOf(base: Rtti.Reader.Base) = classAt(base)
    }

    private fun classAt(base: Rtti.Reader.Base) = bases.getOrPut(base.typeinfo) {
        VtableClass(namespaceOfTypeinfo(base.typeinfo), base.className, base.typeinfo)
    }

    /** Every class a primary `vtable` label is in, whose vtable names its typeinfo. */
    fun read(): List<ClassDecl> = program.symbolTable.getSymbols(ClassNaming.VTABLE).iterator().asSequence()
        .distinctBy { it.address }
        .mapNotNull { sym ->
            val name = sym.vtableClass ?: return@mapNotNull null
            val record = runCatching { Itanium.recordAt(program, sym.address) }.getOrNull() ?: return@mapNotNull null
            record.rttiOf(program)?.let { VtableClass(sym.parentNamespace, name, it, record) }
        }
        .toList()

    /** The namespace the demangled `typeinfo` label at [zti] sits in. */
    private fun namespaceOfTypeinfo(zti: Address) = program.symbolTable.getSymbols(zti)
        .firstOrNull { it.name == ClassNaming.TYPEINFO && it.typeinfoClass != null }?.parentNamespace
}
