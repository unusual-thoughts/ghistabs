package ghistabs.materialize.cpp.abi

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Symbol
import ghistabs.parse.Access
import ghistabs.readPointer

/**
 * Reads a class's direct bases off its Itanium `_ZTI` typeinfo object (ABI §2.9.5): [Rtti]'s
 * layouts read rather than laid, straight from memory, since the bytes are the same whether or not
 * anything typed them. A read-only caller can't have [Rtti] resolve its layouts into the DTM.
 *
 * The object's first word is the address point of one of three `__cxxabiv1` vtables, which says the
 * layout that follows: `__class_type_info` (no bases), `__si_class_type_info` (one public non-virtual
 * base at offset 0, then `__base_type`), or `__vmi_class_type_info` (`__flags`, `__base_count`, then
 * one `{__base_type, __offset_flags}` pair per base). In a dynamically linked binary that word is a
 * relocation to libstdc++, so it's named by the reference Ghidra made for it, as is each base's
 * typeinfo when it lives in a shared library (`std::exception`).
 */
/*
 * gcc 2.x has nothing to read: `__ti<class>` sits in .bss, filled at run time by its `__tf<class>`
 * function (`__ti4Base` is `B` in hello_elf_gcc295's symbols), so only the stabs give its bases.
 */
class RttiReader(private val program: Program) {
    data class Base(val className: String, val isVirtual: Boolean, val access: Access)

    private val ptr = program.defaultPointerSize
    private val symtab = program.symbolTable

    private enum class Kind { CLASS, SI, VMI }

    // vptr then the name: what every class typeinfo opens with ([Rtti.classTypeInfoStructure]).
    private val header = 2L * ptr

    /** Null when [zti] isn't a class typeinfo this can read, rather than a class with no bases. */
    fun basesOf(zti: Address): List<Base>? = when (kindOf(zti)) {
        Kind.CLASS -> emptyList()
        Kind.SI -> classAt(zti.add(header))?.let { listOf(Base(it, isVirtual = false, access = Access.PUBLIC)) }
        Kind.VMI -> vmiBases(zti)
        null -> null
    }

    private fun vmiBases(zti: Address): List<Base>? = runCatching {
        // [Rtti.vmiClassTypeInfoStructure]: `flags` and `numBaseClasses` are both `unsigned int`, then
        // the `baseClassPtrArray` of {base typeinfo pointer, `long` offset+flags}.
        val count = program.memory.getInt(zti.add(header + 4))
        if (count !in 1..MAX_BASES) return null
        val first = zti.add(header + 8)
        val stride = 2L * ptr
        (0 until count).map { i ->
            val entry = first.add(i * stride)
            // `long __offset_flags`: the flags are its low byte, wherever that lands.
            val flags = if (ptr == 8 && program.memory.isBigEndian) {
                program.memory.getLong(entry.add(ptr.toLong()))
            } else {
                program.memory.getInt(entry.add(ptr.toLong())).toLong()
            }
            Base(
                classAt(entry) ?: return null,
                isVirtual = flags and Itanium.VIRTUAL_BASE_MASK != 0L,
                access = if (flags and Itanium.PUBLIC_BASE_MASK != 0L) Access.PUBLIC else Access.PRIVATE,
            )
        }
    }.getOrNull()

    private fun kindOf(zti: Address): Kind? {
        val names = namesAt(zti) { target ->
            // The vptr is the vtable's address point, two words past its `_ZTV` label.
            val ztv = runCatching { target.subtract(Itanium.vtablePrefixBytes(ptr)) }.getOrNull()
            symtab.getSymbols(target).toList() + ztv?.let { symtab.getSymbols(it).toList() }.orEmpty()
        }
        return when {
            names.any { VMI in it } -> Kind.VMI
            names.any { SI in it } -> Kind.SI
            names.any { CLASS in it } -> Kind.CLASS
            else -> null
        }
    }

    /** The class whose typeinfo the pointer at [at] points at. */
    private fun classAt(at: Address): String? {
        val labels = mutableListOf<Symbol>()
        val names = namesAt(at) { symtab.getSymbols(it).toList().also(labels::addAll) }
        return names.firstNotNullOfOrNull { Itanium.typeinfoClassOf(it) }
            // Only the demangler's `typeinfo` label left: its namespace is the class.
            ?: labels.firstOrNull { it.name == Itanium.DEMANGLED_TYPEINFO }?.parentNamespace?.getName(true)
    }

    /**
     * The names of whatever the pointer at [at] refers to: an external symbol by its reference, or the
     * labels [labelsAt] finds at the address the pointer holds.
     */
    private fun namesAt(at: Address, labelsAt: (Address) -> List<Symbol>): List<String> {
        val external = program.referenceManager.getReferencesFrom(at)
            .filter { it.isExternalReference || it.toAddress.isExternalAddress }
            .mapNotNull { symtab.getPrimarySymbol(it.toAddress) }
            .flatMap { sym ->
                listOfNotNull(sym.name, program.externalManager.getExternalLocation(sym)?.originalImportedName)
            }
        if (external.isNotEmpty()) return external
        val target = runCatching { program.readPointer(at) }.getOrNull() ?: return emptyList()
        return labelsAt(target).map { it.name }
    }

    private companion object {
        // Arbitrary sanity bound: a garbage count must not read megabytes.
        const val MAX_BASES = 256

        // As they appear in both the mangled `_ZTVN10__cxxabiv120__si_class_type_infoE` and a demangled label.
        const val VMI = Itanium.VMI_CLASS_TYPE_INFO
        const val SI = Itanium.SI_CLASS_TYPE_INFO
        const val CLASS = Itanium.CLASS_TYPE_INFO
    }
}
