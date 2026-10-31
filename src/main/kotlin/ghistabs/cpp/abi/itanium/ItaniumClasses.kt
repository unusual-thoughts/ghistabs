package ghistabs.cpp.abi.itanium

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.symbol.SymbolIterator
import ghidra.util.task.TaskMonitor
import ghistabs.cpp.ClassBase
import ghistabs.cpp.ClassDecl
import ghistabs.cpp.ClassNaming
import ghistabs.cpp.abi.VtableRecord
import ghistabs.cpp.recover.AbiClasses
import ghistabs.cpp.recover.ClassRecovery
import ghistabs.diagnose.DiagnosticSink

/**
 * Classes off the Itanium RTTI, for [ClassRecovery]: every class namespace holding a `typeinfo` label, its
 * bases off that typeinfo ([Rtti.Reader.basesOf]), and its vtables off its `vtable` and `internal_vtable`
 * labels, as [GccVftableAnalyzer][ghistabs.entrypoints.GccVftableAnalyzer] lays them. Classes go by their
 * typeinfo's address.
 */
class ItaniumClasses(private val program: Program, sink: DiagnosticSink) : DiagnosticSink by sink {
    private val symbols = program.symbolTable
    private val reader = Rtti.Reader(program)

    // Every class seen, by typeinfo: those labelled in a class namespace, and any base whose typeinfo isn't,
    // as one from a shared library, which is known by nothing more than its name.
    private val classes = mutableMapOf<Address, TypeinfoClass>()

    /** A class the RTTI describes: its namespace, if it has one, and its typeinfo object at [typeinfo]. */
    private inner class TypeinfoClass(
        override val ns: GhidraClass?,
        override val name: String,
        private val typeinfo: Address?,
    ) : ClassDecl {
        override val bases by lazy {
            typeinfo?.let(reader::basesOf).orEmpty().map { b ->
                // A virtual base's offset is into the vtable, not the class.
                ClassBase(classAt(b.typeinfo, b.className), b.isVirtual, b.access, b.offset.takeUnless { b.isVirtual })
            }
        }
        override val ancestors by lazy { super.ancestors }

        override val vftables: List<VtableRecord> by lazy {
            ns?.let(symbols::getSymbols)?.symbols().orEmpty().filter { it.name in VTABLE_LABELS }
                .map { Itanium.recordAt(program, it.address) }.toList()
        }
    }

    private fun classAt(typeinfo: Address, name: String) = classes.getOrPut(typeinfo) {
        TypeinfoClass(null, name, null)
    }

    fun recover(monitor: TaskMonitor = TaskMonitor.DUMMY): ClassRecovery.Result {
        val labelled = readTypeinfos()
        classes += labelled
        // Reading the bases adds the classes known only by name, before anything walks [classes].
        labelled.values.forEach { it.bases }
        val read = AbiClasses(classes.values, labelled.values, readVtables(labelled.values))
        return ClassRecovery(program, Itanium, this).recover(read, monitor)
    }

    private fun readTypeinfos() = symbols.getSymbols(ClassNaming.TYPEINFO).symbols()
        .mapNotNull { sym ->
            (sym.parentNamespace as? GhidraClass)?.let { sym.address to TypeinfoClass(it, it.name, sym.address) }
        }
        .filter { (at, _) -> reader.basesOf(at) != null }
        .toMap()

    /** Each function a vtable slot holds, and the classes whose tables hold it. */
    private fun readVtables(classes: Collection<TypeinfoClass>) = buildMap {
        for (cls in classes) {
            for (record in cls.vftables) {
                for (slot in record.slots(program)) {
                    val func = slotFunction(slot) ?: continue
                    getOrPut(func) { mutableSetOf() } += cls
                }
            }
        }
    } as Map<Function, Set<ClassDecl>>

    /** The function a slot points at, past a jump stub; not an import nor the shared `__cxa_pure_virtual`. */
    private fun slotFunction(at: Address): Function? {
        val func = program.functionManager.getFunctionAt(at) ?: return null
        val target = if (func.isThunk) func.getThunkedFunction(true) else func
        return target?.takeUnless { it.isExternal || "pure_virtual" in it.name }
    }

    // A SymbolIterator is an Iterator and an Iterable, and `asSequence` is on both.
    private fun SymbolIterator.symbols(): Sequence<Symbol> = (this as Iterator<Symbol>).asSequence()

    private companion object {
        val VTABLE_LABELS = setOf(ClassNaming.vtableLabel(internal = false), ClassNaming.vtableLabel(internal = true))
    }
}
