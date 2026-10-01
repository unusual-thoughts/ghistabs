package ghistabs.hierarchy

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Symbol
import ghistabs.materialize.cpp.abi.Itanium
import ghistabs.parse.Access
import ghistabs.readPointer

/**
 * Reads a class's direct bases off its Itanium `_ZTI` typeinfo object (ABI §2.9.5), straight from
 * memory: the bytes are the same whether or not anything typed them.
 *
 * The object's first word is the address point of one of three `__cxxabiv1` vtables, which says the
 * layout that follows: `__class_type_info` (no bases), `__si_class_type_info` (one public non-virtual
 * base at offset 0, then `__base_type`), or `__vmi_class_type_info` (`__flags`, `__base_count`, then
 * one `{__base_type, __offset_flags}` pair per base). In a dynamically linked binary that word is a
 * relocation to libstdc++, so it's named by the reference Ghidra made for it, as is each base's
 * typeinfo when it lives in a shared library (`std::exception`).
 */
class ItaniumTypeinfo(private val program: Program) {
    data class Base(val className: String, val isVirtual: Boolean, val access: Access)

    private val ptr = program.defaultPointerSize
    private val symtab = program.symbolTable

    private enum class Kind { CLASS, SI, VMI }

    /** Null when [zti] isn't a class typeinfo this can read, rather than a class with no bases. */
    fun basesOf(zti: Address): List<Base>? = when (kindOf(zti)) {
        Kind.CLASS -> emptyList()
        Kind.SI -> classAt(zti.add(2L * ptr))?.let { listOf(Base(it, isVirtual = false, access = Access.PUBLIC)) }
        Kind.VMI -> vmiBases(zti)
        null -> null
    }

    private fun vmiBases(zti: Address): List<Base>? = runCatching {
        // `__flags` and `__base_count` are both `unsigned int`, then the pointer-aligned array.
        val count = program.memory.getInt(zti.add(2L * ptr + 4))
        if (count !in 1..MAX_BASES) return null
        val first = zti.add(2L * ptr + 8)
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
                isVirtual = flags and VIRTUAL_MASK != 0L,
                access = if (flags and PUBLIC_MASK != 0L) Access.PUBLIC else Access.PRIVATE,
            )
        }
    }.getOrNull()

    private fun kindOf(zti: Address): Kind? {
        val names = namesAt(zti) { target ->
            // The vptr is the vtable's address point, two words past its `_ZTV` label.
            symtab.getSymbols(target).toList() + runCatching { symtab.getSymbols(target.subtract(2L * ptr)).toList() }
                .getOrDefault(emptyList())
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
        const val VIRTUAL_MASK = 0x1L
        const val PUBLIC_MASK = 0x2L

        // Arbitrary sanity bound: a garbage count must not read megabytes.
        const val MAX_BASES = 256

        // As they appear in both the mangled `_ZTVN10__cxxabiv120__si_class_type_infoE` and a demangled label.
        const val VMI = "__vmi_class_type_info"
        const val SI = "__si_class_type_info"
        const val CLASS = "__class_type_info"
    }
}
