package ghicpp.abi.itanium

import ghicpp.Access
import ghicpp.BaseDecl
import ghicpp.abi.itanium.Typeinfo.Companion.BASES
import ghicpp.abi.itanium.Typeinfo.Companion.BASE_OFFSET
import ghicpp.abi.itanium.Typeinfo.Companion.BASE_TYPE
import ghicpp.abi.itanium.Typeinfo.Companion.BASE_TYPE_IN_ENTRY
import ghicpp.abi.itanium.Typeinfo.Companion.IS_PUBLIC
import ghicpp.abi.itanium.Typeinfo.Companion.IS_VIRTUAL
import ghicpp.abi.itanium.Typeinfo.Companion.MAX_BASES
import ghicpp.abi.itanium.Typeinfo.Companion.MAX_BASE_DEPTH
import ghicpp.abi.itanium.Typeinfo.Companion.NUM_BASES
import ghicpp.abi.itanium.Typeinfo.Kind
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Symbol
import ghistabs.*

/**
 * Reads a class's bases off its typeinfo object (ABI §2.9.5), typed or not. Its vptr says which of the
 * three class layouts it has ([Typeinfo.Kind]); a vptr or base into a shared library is named by Ghidra's
 * external reference. gcc 2.x fills its typeinfo in at run time, so has nothing to read.
 */
class TypeinfoReader(val program: Program) {
    /**
     * A direct base, and its own [typeinfo], possibly external. Its [offset] is the subobject's, or for a
     * virtual base where the vtable keeps that, from the address point (negative).
     */
    data class Base(
        val className: String,
        val typeinfo: Address,
        override val isVirtual: Boolean,
        override val access: Access,
        override val offset: Long = 0,
    ) : BaseDecl

    private val ptr = program.defaultPointerSize
    private val symtab = program.symbolTable

    private val layouts = Typeinfo(program.dataTypeManager)

    /** [zti]'s direct bases; null if it isn't a class typeinfo this can read. */
    fun basesOf(zti: Address): List<Base>? = runCatching {
        when (kindOf(zti)) {
            Kind.CLASS -> emptyList()

            Kind.SI -> program.dataAt(zti, layouts.siClassTi)?.get(BASE_TYPE)
                ?.let { classAt(it.address) }
                ?.let { (name, at) -> listOf(Base(name, at, isVirtual = false, access = Access.PUBLIC)) }

            Kind.VMI -> vmiBases(zti)

            null -> null
        }
    }.getOrNull()

    /** The virtual bases whose offsets [zti]'s primary vtable keeps: its own, and its bases' at offset 0. */
    fun virtualBasesOf(zti: Address, depth: Int = 0): List<Base> =
        basesOf(zti).orEmpty().takeIf { depth < MAX_BASE_DEPTH }.orEmpty().flatMap { base ->
            when {
                base.isVirtual -> listOf(base)
                base.offset == 0L -> virtualBasesOf(base.typeinfo, depth + 1)
                else -> emptyList()
            }
        }.distinctBy { it.className }

    fun structFor(zti: Address) = when (kindOf(zti)) {
        Kind.CLASS -> layouts.classTi
        Kind.SI -> layouts.siClassTi
        Kind.VMI -> vmiCount(zti)?.takeIf { it in 1..MAX_BASES }?.let { layouts.vmiClassTypeInfo(it) }
        null -> null
    }

    private fun vmiCount(zti: Address) = program.dataAt(zti, layouts.vmiClassTypeInfo(1))
        ?.getScalar(NUM_BASES)?.unsignedValue?.toInt()

    private fun vmiBases(zti: Address): List<Base>? {
        val array = structFor(zti)?.let { program.dataAt(zti, it)?.get(BASES) } ?: return null
        return (0 until array.numComponents).map { i ->
            val entry = array[i] ?: return null
            val (name, at) = entry[BASE_TYPE_IN_ENTRY]?.let { classAt(it.address) } ?: return null
            Base(
                name,
                at,
                isVirtual = entry.flag(IS_VIRTUAL),
                access = if (entry.flag(IS_PUBLIC)) Access.PUBLIC else Access.PRIVATE,
                offset = entry.getScalar(BASE_OFFSET)?.signedValue ?: return null,
            )
        }
    }

    // The vptr points two words past its vtable's `_ZTV` label.
    internal fun kindOf(zti: Address) =
        pointee(zti, Itanium.vtablePrefixBytes(ptr)) { it.vtableClass?.let(Kind::ofVtableClass) }

    /** The class whose typeinfo the pointer at [at] points at, and where that typeinfo's symbol is. */
    private fun classAt(at: Address) = pointee(at, 0) { sym -> sym.typeinfoClass?.let { it to sym.address } }

    /**
     * [of] the first symbol the pointer at [at] refers to that it answers for: an external one by
     * Ghidra's reference, else one [back] bytes before its target. Not one at the target itself, which
     * in the EXTERNAL block can be the next import's label.
     */
    private fun <T : Any> pointee(at: Address, back: Long, of: (Symbol) -> T?): T? {
        val external = program.referenceManager.getReferencesFrom(at)
            .filter { it.isExternalReference || it.toAddress.isExternalAddress }
            .mapNotNull { symtab.getPrimarySymbol(it.toAddress) }
        val symbols = external.ifEmpty {
            val target = runCatching { program.pointerAt(at) }.getOrNull() ?: return null
            runCatching { symtab.getSymbols(target.subtract(back)).toList() }.getOrNull() ?: return null
        }
        return symbols.firstNotNullOfOrNull(of)
    }
}
