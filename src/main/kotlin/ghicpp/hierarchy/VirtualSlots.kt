package ghicpp.hierarchy

import ghicpp.ClassNaming
import ghicpp.abi.gcc2.Gcc2Plain
import ghicpp.abi.itanium.Itanium
import ghicpp.abi.msvc.Msvc
import ghicpp.hierarchy.ClassHierarchy.ClassView
import ghidra.program.model.address.Address
import ghidra.program.model.data.FunctionDefinition
import ghidra.program.model.data.Pointer
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType

/** A slot of a class's laid vftable: where the table is, and the slot's place among its function pointers. */
data class VirtualSlot(val table: Address, val index: Int)

/** How many functions and slot fields a rename changed, and what kept its old name, and why. */
data class SlotRenames(val functions: Int, val fields: Int, val skipped: List<String>)

/**
 * The program's classes' laid vftables, construction ones aside, and which base's table each one's slots
 * begin with: the table of the base it is for, by its struct's name (`D_vftable_for_B`), else its
 * primary base's, the first base no other of its tables is for. A slot overrides the slot at its index in
 * that table, while that table has one.
 */
class VirtualSlots(private val program: Program, private val hierarchy: ClassHierarchy) {
    private val tables: Map<Long, List<Data>> =
        hierarchy.classes.associate { c -> c.id to program.resolve(c)?.let(program::laidVftablesOf).orEmpty() }
    private val owner: Map<Address, ClassView> =
        hierarchy.classes.flatMap { c -> tables[c.id].orEmpty().map { it.address to c } }.toMap()
    private val byAddress: Map<Address, Data> = tables.values.flatten().associateBy { it.address }

    /** Every slot of [cls]'s tables. */
    fun slotsOf(cls: ClassView): List<VirtualSlot> =
        tables[cls.id].orEmpty().flatMap { t -> t.functionSlots().indices.map { VirtualSlot(t.address, it) } }

    /** The slots that hold [func], or a thunk to it. */
    fun slotsOf(func: Function): List<VirtualSlot> =
        hierarchy.classes.flatMap(::slotsOf).filter { target(it)?.entryPoint == func.entryPoint }

    /** The function [slot] holds, past a thunk; none for an empty or pure virtual slot, or an import. */
    fun target(slot: VirtualSlot): Function? {
        val at = component(slot)?.value as? Address ?: return null
        val f = program.functionManager.getFunctionAt(at) ?: return null
        return (if (f.isThunk) f.getThunkedFunction(true) else f)
            ?.takeUnless { it.isExternal || PURE_VIRTUAL_ABIS.any { abi -> abi.isPureVirtualStub(it.name) } }
    }

    /** The slot [slot] overrides, up to the base that first declares it. */
    fun root(slot: VirtualSlot): VirtualSlot {
        var s = slot
        val seen = mutableSetOf(s.table)
        while (true) {
            val up = byAddress[s.table]?.let(::extended)?.takeIf { seen.add(it.address) } ?: return s
            if (s.index >= up.functionSlots().size) return s
            s = VirtualSlot(up.address, s.index)
        }
    }

    /** Every slot of the virtual function [func]'s: the slots overriding what its own do, and theirs. */
    fun implementing(func: Function): List<VirtualSlot> {
        val roots = slotsOf(func).map(::root).toSet()
        return hierarchy.classes.flatMap(::slotsOf).filter { root(it) in roots }
    }

    /**
     * Renames [func]'s virtual slot to [newName]: every function its slots hold, [func] with them, and the
     * slot's field in every table, with the definition the field points at, which shares its name.
     */
    fun rename(func: Function, newName: String): SlotRenames {
        val skipped = mutableListOf<String>()
        val slots = implementing(func)
        var functions = 0
        for (f in (slots.mapNotNull(::target) + func).distinct()) {
            if (f.name == newName) continue
            runCatching { f.setName(newName, SourceType.USER_DEFINED) }
                .onSuccess { functions++ }.onFailure { skipped += "${f.getName(true)}: ${it.message}" }
        }
        return SlotRenames(functions, slots.count { nameSlot(it, newName, skipped) }, skipped)
    }

    /** Names each of [slots] after the function it holds, when that function has a name of its own. */
    fun applyNames(slots: Collection<VirtualSlot>): SlotRenames {
        val skipped = mutableListOf<String>()
        val fields = slots.count { s ->
            val name = target(s)?.takeUnless { it.symbol.source == SourceType.DEFAULT }?.name
            name != null && nameSlot(s, name, skipped)
        }
        return SlotRenames(0, fields, skipped)
    }

    /** Names [slot]'s field [name], or `name_1`… if the table has a field so named, and its definition too. */
    private fun nameSlot(slot: VirtualSlot, name: String, skipped: MutableList<String>): Boolean {
        val table = byAddress[slot.table] ?: return false
        val struct = table.dataType as? Structure ?: return false
        val field = component(slot)?.let { struct.getComponent(it.componentIndex) } ?: return false
        if (field.fieldName == name) return false
        val used = struct.definedComponents.filter { it.ordinal != field.ordinal }.mapNotNull { it.fieldName }.toSet()
        val unique = generateSequence(0) { it + 1 }.map { if (it == 0) name else "${name}_$it" }.first { it !in used }
        if (field.fieldName == unique) return false
        return runCatching {
            field.fieldName = unique
            ((field.dataType as? Pointer)?.dataType as? FunctionDefinition)
                ?.let { def -> runCatching { def.name = unique } }
        }.onFailure { skipped += "${struct.name}.${field.fieldName}: ${it.message}" }.isSuccess
    }

    private fun component(slot: VirtualSlot): Data? = byAddress[slot.table]?.functionSlots()?.getOrNull(slot.index)

    /** The table of a base [table]'s slots begin with. */
    private fun extended(table: Data): Data? {
        val cls = owner[table.address] ?: return null
        val named = forBase(table)
        val base = if (named != null) {
            hierarchy.ancestorsOf(cls).firstOrNull { it.name == named }
        } else {
            val others = tables[cls.id].orEmpty().mapNotNull(::forBase).toSet()
            cls.bases.mapNotNull(hierarchy::get).firstOrNull { it.name !in others && primary(it) != null }
        }
        return base?.let(::primary)
    }

    /** [cls]'s primary table: its own, else the one for its first base. */
    private fun primary(cls: ClassView): Data? {
        val ts = tables[cls.id].orEmpty()
        return ts.firstOrNull { forBase(it) == null }
            ?: cls.bases.firstNotNullOfOrNull { b -> ts.firstOrNull { forBase(it) == b.name } }
    }

    private companion object {
        val PURE_VIRTUAL_ABIS = listOf(Itanium, Msvc, Gcc2Plain)

        /** The base a table is for, by its struct's name, `D_vftable_for_B`. */
        fun forBase(table: Data): String? =
            table.dataType.name.substringAfter("_" + ClassNaming.VFTABLE_FOR, "").takeIf { it.isNotEmpty() }
    }
}

/** [cls]'s bases, theirs after them, each once. */
private fun ClassHierarchy.ancestorsOf(cls: ClassView): Sequence<ClassView> = sequence {
    val seen = mutableSetOf(cls.id)
    var level = cls.bases.mapNotNull(::get).filter { seen.add(it.id) }
    while (level.isNotEmpty()) {
        yieldAll(level)
        level = level.flatMap { it.bases.mapNotNull(::get) }.filter { seen.add(it.id) }
    }
}

/** The function pointers of a laid vftable, in order, empty and pure virtual slots among them. */
private fun Data.functionSlots(): List<Data> = (0 until numComponents).map(::getComponent)
    .filter { (it.dataType as? Pointer)?.dataType is FunctionDefinition }

/** Each of [ns]'s laid vftables: at each of its vftable labels, the vftable struct there. */
private fun Program.laidVftablesOf(ns: Namespace): List<Data> = symbolTable.getSymbols(ns).iterator().asSequence()
    .filter { ClassNaming.isClassVftableLabel(it.name) }
    .mapNotNull { vftableDataAt(it.address) }
    .distinctBy { it.address }
    .toList()

/** The vftable struct laid at [at], within a vtable's own struct (an Itanium `_ZTV`) or not. */
private fun Program.vftableDataAt(at: Address): Data? {
    var d = listing.getDataContaining(at)
    while (d != null && d.numComponents > 0) {
        if (d.address == at && (d.dataType as? Structure)?.name?.contains(ClassNaming.VFTABLE) == true) return d
        d = d.getComponentContaining(at.subtract(d.address).toInt())
    }
    return null
}
