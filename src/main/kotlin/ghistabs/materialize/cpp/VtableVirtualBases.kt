package ghistabs.materialize.cpp

import ghidra.program.database.data.DataTypeUtilities
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghistabs.diagnose.DiagnosticSink
import ghistabs.materialize.componentsOverlapping
import ghistabs.materialize.cpp.abi.*
import ghistabs.parse.leafName
import ghistabs.parse.member

/**
 * Lays the virtual bases a class struct lacks where its Itanium vtable says they are. A class deriving
 * from `basic_ifstream<char>` that no debug info defines has no virtual base in its struct; its typeinfo
 * still says `basic_istream` has `basic_ios` as a virtual base whose offset is 12 bytes behind the
 * vtable's address point, and the class's `_ZTV` holds that offset there. When nothing defines
 * `basic_ios` either, the first base of it that something does is laid instead, where `basic_ios`'s
 * typeinfo puts it: `ios_base`, 4 bytes in, behind `basic_ios`'s own vptr.
 *
 * Needs the labels demangled, so each `vtable` and `typeinfo` sits in its class's namespace, which
 * [DataTypeUtilities.findExistingClassStruct] finds the class's struct by; [fallback] answers, by the
 * class's qualified name, where that finds none. gcc 2.x fills its typeinfo at run time, so has none to
 * read. A struct already holding something where a virtual base goes is taken to have it, and anything
 * that would not fit, or would cover laid bytes, is reported and left.
 */
class VtableVirtualBases(
    private val program: Program,
    sink: DiagnosticSink,
    private val fallback: (String) -> Structure? = { null },
) : DiagnosticSink by sink {
    private val dtm = program.dataTypeManager
    private val reader = Rtti.Reader(program)

    /** Lays every class's; returns how many virtual bases it laid. */
    fun layAll(): Int = program.symbolTable.getSymbols(ClassNaming.VTABLE).iterator().asSequence()
        .distinctBy { it.address }
        .sumOf { sym ->
            val struct = sym.vtableClass?.let { structFor(it, sym.parentNamespace) } ?: return@sumOf 0
            val record = runCatching { program.vtableRecord(sym.address) }.getOrNull() ?: return@sumOf 0
            val vbases = program.rttiOf(record)?.let(::virtualBases).orEmpty()
            val count = struct.definedComponents.count { it.isBaseField() } + vbases.size
            vbases.count { lay(struct, record, it, struct.pathName.member(it.className), count) }
        }

    private fun lay(struct: Structure, record: VtableRecord, vbase: Rtti.Reader.Base, at: String, count: Int): Boolean {
        val vbaseAt = program.vbaseOffset(record, vbase.offset)?.toInt()
        // A nearly-empty virtual base can be the primary base, sharing the class's vptr at 0 (CryptoPP's
        // CryptoMaterial under CryptoParameters): there is nothing of its own to lay.
        when {
            vbaseAt == 0 -> return false.also { debug("vbase-primary-from-vtable") }

            vbaseAt == null || vbaseAt < 0 || vbaseAt >= struct.length -> return false.also {
                degradation("vbase-offset-unreadable", at, "vtable word at ${vbase.offset} reads $vbaseAt")
            }
        }

        val (dt, within) = definedPart(vbase) ?: return false.also {
            degradation("vbase-undefined", at, "nothing defines it or a base of it")
        }
        // Laid already, by the class layout off the stab's own inheritance line, or by an earlier run.
        struct.getComponentAt(vbaseAt)?.takeIf { it.offset == vbaseAt }?.dataType?.name?.let { laid ->
            if (laid == vbase.className.leafName || laid == dt.name) return false
        }

        val offset = vbaseAt + within
        when {
            offset + dt.length > struct.length -> "${dt.name} (${dt.length}b) at +$offset overruns ${struct.length}"
            struct.componentsOverlapping(offset, dt.length).isNotEmpty() -> "${dt.name} at +$offset covers laid fields"
            else -> null
        }?.let { problem -> return false.also { degradation("vbase-layout-failed", at, problem) } }

        val part = "; only its ${dt.name} at +$within is defined"
            .takeUnless { within == 0 && dt.name == vbase.className.leafName }.orEmpty()
        placeBase(
            struct,
            offset,
            dt,
            isVirtual = true,
            "${vbase.access.name.lowercase()} virtual ${vbase.className} at " +
                "+0x${vbaseAt.toString(16)}, by the vtable$part",
            ClassNaming.baseFieldName(true, dt.name, count),
            at,
        )
        return true
    }

    private fun Structure.takeAcceptable() = takeUnless { it.isZeroLength }

    /** [className]'s struct, by the namespace its demangled labels sit in, else by [fallback]. */
    private fun structFor(className: String, namespace: Namespace?): Structure? = when (namespace) {
        is GhidraClass -> DataTypeUtilities.findExistingClassStruct(dtm, namespace)

        else if namespace?.isGlobal == false -> DataTypeUtilities.findDataType(
            dtm,
            namespace.parentNamespace,
            namespace.name,
            Structure::class.java,
        )

        else -> null
    }?.takeAcceptable() ?: fallback(className)?.takeAcceptable()

    /** The namespace the demangled `typeinfo` label at [zti] sits in. */
    private fun namespaceOfTypeinfo(zti: Address) = program.symbolTable.getSymbols(zti)
        .firstOrNull { it.name == ClassNaming.TYPEINFO && it.typeinfoClass != null }?.parentNamespace

    /** [zti]'s virtual bases, its own and those of its primary chain, each with its vtable offset. */
    private fun virtualBases(zti: Address, depth: Int = 0): List<Rtti.Reader.Base> =
        reader.basesOf(zti).orEmpty().takeIf { depth < MAX_DEPTH }.orEmpty().flatMap { base ->
            when {
                base.isVirtual -> listOf(base)
                base.offset == 0L -> virtualBases(base.typeinfo, depth + 1)
                else -> emptyList()
            }
        }.distinctBy { it.className }

    /**
     * [base]'s struct, else the first one down its chain of first non-virtual bases, with where that sits
     * in [base]: `basic_ios` keeps its own vptr in front of `ios_base`, at +4.
     */
    private fun definedPart(base: Rtti.Reader.Base, depth: Int = 0): Pair<DataType, Int>? =
        structFor(base.className, namespaceOfTypeinfo(base.typeinfo))?.let { it to 0 }
            ?: base.typeinfo.takeIf { depth < MAX_DEPTH }?.let(reader::basesOf)
                ?.filterNot { it.isVirtual }?.minByOrNull { it.offset }
                ?.let { next -> definedPart(next, depth + 1)?.let { (dt, at) -> dt to at + next.offset.toInt() } }

    private companion object {
        const val MAX_DEPTH = 16
    }
}
