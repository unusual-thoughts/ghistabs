package ghistabs.cpp.abi.itanium

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghistabs.cpp.ClassBase
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
    private val bases = mutableMapOf<Address, TypeinfoClass>()

    /** A class by its [typeinfo], with the [vtable] its labels name where it has one. */
    private inner class TypeinfoClass(
        override val ns: Namespace?,
        override val name: String,
        private val typeinfo: Address,
        private val vtable: VtableRecord? = null,
    ) : ClassDecl {
        override val bases by lazy {
            reader.basesOf(typeinfo).orEmpty().map { b ->
                // A virtual base's offset is into the vtable, not the class.
                ClassBase(classAt(b), b.isVirtual, b.access, b.offset.takeUnless { b.isVirtual })
            }
        }
        override val vftables get() = listOfNotNull(vtable)

        override val virtualBases by lazy {
            vtable?.let { record ->
                reader.virtualBasesOf(typeinfo).map { b ->
                    ClassBase(classAt(b), isVirtual = true, b.access, record.vbaseOffset(program, b))
                }
            }.orEmpty()
        }
    }

    private fun classAt(base: Rtti.Reader.Base) = bases.getOrPut(base.typeinfo) {
        TypeinfoClass(namespaceOfTypeinfo(base.typeinfo), base.className, base.typeinfo)
    }

    /** Every class a primary `vtable` label is in, whose vtable names its typeinfo. */
    fun read(): List<ClassDecl> = program.symbolTable.getSymbols(ClassNaming.VTABLE).iterator().asSequence()
        .distinctBy { it.address }
        .mapNotNull { sym ->
            val name = sym.vtableClass ?: return@mapNotNull null
            val record = runCatching { Itanium.recordAt(program, sym.address) }.getOrNull() ?: return@mapNotNull null
            record.rttiOf(program)?.let { TypeinfoClass(sym.parentNamespace, name, it, record) }
        }
        .toList()

    /** The namespace the demangled `typeinfo` label at [zti] sits in. */
    private fun namespaceOfTypeinfo(zti: Address) = program.symbolTable.getSymbols(zti)
        .firstOrNull { it.name == ClassNaming.TYPEINFO && it.typeinfoClass != null }?.parentNamespace
}
