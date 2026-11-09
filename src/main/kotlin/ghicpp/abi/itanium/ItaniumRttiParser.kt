package ghicpp.abi.itanium

import ghicpp.ClassBase
import ghicpp.ClassDecl
import ghicpp.ClassNaming
import ghicpp.ClassPassInput
import ghicpp.abi.RttiParser
import ghicpp.abi.VtableRecord
import ghicpp.abi.slotFunction
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.symbol.SymbolIterator
import ghidra.util.task.TaskMonitor
import ghistabs.diagnose.DiagnosticSink
import ghistabs.toClass

/**
 * A class the Itanium RTTI describes: its [bases] off its typeinfo, its [vftables] off the `vtable` and
 * `internal_vtable` labels in its namespace, and its [virtualBases] where its primary vtable's vbase offsets put
 * them.
 */
class ItaniumClass(
    override val ns: Namespace?,
    override val name: String,
    override val vftables: List<VtableRecord>,
    override val bases: List<ClassBase>,
    override val virtualBases: List<ClassBase>,
) : ClassDecl {
    override val ancestors by lazy { super.ancestors }
}

/**
 * The classes off the Itanium RTTI, each by its typeinfo's address, with its vtables as
 * [VtableSweepAnalyzer][ghicpp.analyzers.VtableSweepAnalyzer] labels them. A base whose typeinfo has no label
 * in a namespace, as a shared library's, is known by its name alone.
 */
class ItaniumRttiParser(private val program: Program, private val sink: DiagnosticSink) : RttiParser {
    override val abi get() = Itanium

    private val symbols = program.symbolTable
    private val reader = TypeinfoReader(program)
    private val classes = mutableMapOf<Address, ItaniumClass>()

    /** The classes [labelled] reaches, with their vtables' slots. */
    override fun parse(monitor: TaskMonitor): ClassPassInput {
        val labelled = labelled()
        return ClassPassInput(classes.values.toList(), labelled, readVtables(labelled))
    }

    /**
     * The class of each class typeinfo labelled in a namespace, made a class one: with no method named, a
     * class only built as a base, as `Up` in `Both` is, has nothing else to make it one.
     */
    fun labelled(): List<ItaniumClass> {
        val namespaces = typeinfoLabels()
            .filter { sym -> !sym.parentNamespace.isGlobal && reader.basesOf(sym.address) != null }
            .mapNotNull { sym -> sym.parentNamespace.toClass()?.let { sym.address to it } }
            .toMap()
        return namespaces.map { (typeinfo, ns) -> classAt(typeinfo, ns.name, ns, namespaces) }
    }

    /**
     * The class of each primary `vtable` label whose vtable names its typeinfo, in the namespace the label is
     * in: unlike [labelled], one the demangler left outside a class namespace too, as the stabs import's are.
     */
    fun withVtables(): List<ItaniumClass> {
        val labels = typeinfoLabels().mapNotNull { sym -> sym.typeinfoClass?.let { sym to it } }.toList()
        val namespaces = labels.associate { (sym, _) -> sym.address to sym.parentNamespace }
        val names = labels.associate { (sym, name) -> sym.address to name }
        return symbols.getSymbols(ClassNaming.VTABLE).symbols()
            .distinctBy { it.address }
            .mapNotNull { sym ->
                val name = sym.vtableClass ?: return@mapNotNull null
                val record = runCatching { Itanium.recordAt(program, sym.address) }.getOrNull()
                // A vtable whose rtti word names another class's typeinfo is no vtable of this one.
                val typeinfo = record?.rttiOf(program)?.takeIf { (names[it] ?: name) == name }
                typeinfo?.let { classAt(it, name, sym.parentNamespace, namespaces) }
            }
            .toList()
    }

    private fun typeinfoLabels() = symbols.getSymbols(ClassNaming.TYPEINFO).symbols()

    /** The class [typeinfo] describes, [name] in [ns], each of its bases in its typeinfo's [namespaces]. */
    private fun classAt(
        typeinfo: Address,
        name: String,
        ns: Namespace?,
        namespaces: Map<Address, Namespace>,
    ): ItaniumClass = classes.getOrPut(typeinfo) {
        fun classOf(b: TypeinfoReader.Base) = classAt(b.typeinfo, b.className, namespaces[b.typeinfo], namespaces)
        val primary = ns?.let { vtableLabels(it, setOf(ClassNaming.VTABLE)).firstOrNull() }
        ItaniumClass(
            ns,
            name,
            vftables = ns?.let { vtableLabels(it, VTABLE_LABELS).toList() }.orEmpty(),
            // A virtual base's offset is into the vtable, not the class.
            bases = reader.basesOf(typeinfo).orEmpty().map { b ->
                ClassBase(classOf(b), b.isVirtual, b.access, b.offset.takeUnless { b.isVirtual })
            },
            virtualBases = primary?.let { record ->
                reader.virtualBasesOf(typeinfo).map { b ->
                    ClassBase(classOf(b), isVirtual = true, b.access, record.vbaseOffset(program, b))
                }
            }.orEmpty(),
        )
    }

    private fun vtableLabels(ns: Namespace, names: Set<String>) = symbols.getSymbols(ns).symbols()
        .filter { it.name in names }.map { Itanium.recordAt(program, it.address) }

    /** Each function a vtable slot holds, and the classes whose tables hold it. */
    private fun readVtables(classes: Collection<ItaniumClass>) = buildMap {
        for (cls in classes) {
            for (record in cls.vftables) {
                for (slot in record.slots(program)) {
                    val func = program.slotFunction(slot, Itanium) ?: continue
                    getOrPut(func) { mutableSetOf() } += cls
                }
            }
        }
    } as Map<Function, Set<ClassDecl>>

    // A SymbolIterator is an Iterator and an Iterable, and `asSequence` is on both.
    private fun SymbolIterator.symbols(): Sequence<Symbol> = (this as Iterator<Symbol>).asSequence()

    private companion object {
        val VTABLE_LABELS = setOf(ClassNaming.vtableLabel(internal = false), ClassNaming.vtableLabel(internal = true))
    }
}
