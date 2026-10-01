package ghistabs.materialize.cpp.abi

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghidra.program.model.symbol.Symbol
import ghistabs.parse.Access
import ghistabs.readAt
import ghistabs.readPointer

/**
 * Reads a class's direct bases off its Itanium `_ZTI` typeinfo object (ABI §2.9.5): [Rtti]'s
 * layouts, [Rtti.Unresolved] so nothing lands in the DTM, read off memory with [readAt] whether or
 * not anything typed the object.
 *
 * The object's first word is the address point of one of three `__cxxabiv1` vtables, which says the
 * layout that follows: `__class_type_info` (no bases), `__si_class_type_info` (one public non-virtual
 * base at offset 0, then `__base_type`), or `__vmi_class_type_info` (`__flags`, `__base_count`, then
 * one `{__base_type, __offset_flags}` pair per base). In a dynamically linked binary that word is a
 * relocation to libstdc++, so it's named by the reference Ghidra made for it, as is each base's
 * typeinfo when it lives in a shared library (`std::exception`).
 *
 * gcc 2.x has nothing to read: `__ti<class>` sits in .bss, filled at run time by its `__tf<class>`
 * function (`__ti4Base` is `B` in hello_elf_gcc295's symbols), so only the stabs give its bases.
 */
class RttiReader(private val program: Program) {
    data class Base(val className: String, val isVirtual: Boolean, val access: Access)

    private val ptr = program.defaultPointerSize
    private val symtab = program.symbolTable

    private val layouts = Rtti(program.dataTypeManager).Unresolved()

    /** Null when [zti] isn't a class typeinfo this can read, rather than a class with no bases. */
    fun basesOf(zti: Address): List<Base>? = runCatching {
        when (kindOf(zti)) {
            TypeinfoKind.CLASS -> emptyList()

            TypeinfoKind.SI -> program.readAt(zti, layouts.siClassTypeInfo)?.field(Rtti.BASE_TYPE)
                ?.let { classAt(it.address) }
                ?.let { listOf(Base(it, isVirtual = false, access = Access.PUBLIC)) }

            TypeinfoKind.VMI -> vmiBases(zti)

            null -> null
        }
    }.getOrNull()

    private fun vmiBases(zti: Address): List<Base>? {
        val count = program.readAt(zti, layouts.vmiClassTypeInfo(1))?.field(Rtti.NUM_BASES)
            ?.let { (it.value as? Scalar)?.unsignedValue?.toInt() }
        if (count == null || count !in 1..MAX_BASES) return null
        val array = program.readAt(zti, layouts.vmiClassTypeInfo(count))?.field(Rtti.BASES) ?: return null
        return (0 until array.numComponents).map { i ->
            val entry = array.getComponent(i)
            Base(
                entry.field(Rtti.BASE_TYPE_IN_ENTRY)?.let { classAt(it.address) } ?: return null,
                isVirtual = entry.flag(Rtti.IS_VIRTUAL),
                access = if (entry.flag(Rtti.IS_PUBLIC)) Access.PUBLIC else Access.PRIVATE,
            )
        }
    }

    private fun Data.field(name: String): Data? =
        (0 until numComponents).asSequence().mapNotNull { getComponent(it) }.firstOrNull { it.fieldName == name }

    private fun Data.flag(name: String) = (field(name)?.value as? Scalar)?.unsignedValue == 1L

    // The vptr is the vtable's address point, two words past its `_ZTV` label.
    private fun kindOf(zti: Address) =
        pointee(zti, Itanium.vtablePrefixBytes(ptr)) { it.vtableClass?.let(TypeinfoKind::ofVtableClass) }

    /** The class whose typeinfo the pointer at [at] points at. */
    private fun classAt(at: Address) = pointee(at, 0) { it.typeinfoClass }

    /**
     * [of] the first symbol the pointer at [at] refers to that it answers for: an external one by
     * Ghidra's reference to it, else a label at the address the pointer holds or [back] bytes before.
     */
    private fun <T : Any> pointee(at: Address, back: Long, of: (Symbol) -> T?): T? {
        val external = program.referenceManager.getReferencesFrom(at)
            .filter { it.isExternalReference || it.toAddress.isExternalAddress }
            .mapNotNull { symtab.getPrimarySymbol(it.toAddress) }
        val symbols = external.ifEmpty {
            val target = runCatching { program.readPointer(at) }.getOrNull() ?: return null
            val before = runCatching { target.subtract(back) }.getOrNull()?.takeIf { back > 0 }
            symtab.getSymbols(target).toList() + before?.let { symtab.getSymbols(it).toList() }.orEmpty()
        }
        return symbols.firstNotNullOfOrNull(of)
    }

    private companion object {
        // Arbitrary sanity bound: a garbage count must not read megabytes.
        const val MAX_BASES = 256
    }
}
