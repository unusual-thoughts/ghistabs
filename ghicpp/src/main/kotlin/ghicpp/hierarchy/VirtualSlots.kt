@file:UseSerializers(AddressSerializer::class)

package ghicpp.hierarchy

import ghicpp.ClassNaming
import ghicpp.ClassRecordSource
import ghicpp.abi.CxxAbi
import ghicpp.abi.gcc2.Gcc2Abi
import ghicpp.abi.gcc2.Gcc2Plain
import ghicpp.abi.itanium.Itanium
import ghicpp.abi.itanium.ItaniumStructor
import ghicpp.abi.msvc.Msvc
import ghicpp.abi.msvc.MsvcStructor
import ghicpp.classStruct
import ghicpp.hierarchy.ClassHierarchy.ClassView
import ghicpp.hierarchy.ClassHierarchy.Origin
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidrakt.AddressSerializer
import ghidrakt.components
import ghidrakt.diagnose.DiagnosticSink
import ghidrakt.pointerAt
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers

/** A slot of a class's vftable:
 *  - [table] where the table is,
 *  - [label] its label
 *  - [index] the slot's place among its function pointers.
 */
@Serializable
data class VirtualSlot(val table: Address, val label: String, val index: Int) : Comparable<VirtualSlot> {
    /** like label but null for the primary one */
    val name get() = label.takeUnless { it == ClassNaming.VFTABLE }

    override fun compareTo(other: VirtualSlot) =
        compareValuesBy(this, other, { it.name != null }, { it.name }, { it.index })

    override fun toString() = "slot $index" + name?.let { " of $it" }.orEmpty()
}

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
        tables[cls.id].orEmpty().flatMap { t -> t.functionSlots().indices.map { VirtualSlot(t.address, t.label, it) } }

    /** The slots that hold [func], or a thunk to it. */
    fun slotsOf(func: Function): List<VirtualSlot> =
        hierarchy.classes.flatMap(::slotsOf).filter { target(it)?.entryPoint == func.entryPoint }

    /** The function [slot] holds, past a thunk; none for an empty or pure virtual slot, or an import. */
    fun target(slot: VirtualSlot): Function? {
        val at = component(slot)?.value as? Address ?: return null
        val f = program.functionManager.getFunctionAt(at) ?: return null
        return (if (f.isThunk) f.getThunkedFunction(true) else f)
            ?.takeUnless { it.isExternal || isPureVirtualStub(it.name) }
    }

    /** The slot [slot] overrides, up to the base that first declares it. */
    fun root(slot: VirtualSlot): VirtualSlot = overridden(slot).lastOrNull() ?: slot

    /** The slots [slot] overrides, the nearest base's first, up to the base that first declares it. */
    private fun overridden(slot: VirtualSlot): Sequence<VirtualSlot> = sequence {
        var s = slot
        val seen = mutableSetOf(s.table)
        while (true) {
            val up = byAddress[s.table]?.let(::extended)?.takeIf { seen.add(it.address) } ?: break
            if (s.index >= up.functionSlots().size) break
            s = VirtualSlot(up.address, up.label, s.index)
            yield(s)
        }
    }

    /** Every slot of the virtual function [func]'s: the slots overriding what its own do, and theirs. */
    fun implementing(func: Function): List<VirtualSlot> {
        val roots = slotsOf(func).map(::root).toSet()
        return hierarchy.classes.flatMap(::slotsOf).filter { root(it) in roots }
    }

    /**
     * Renames [func]'s virtual slot to [newName]: every function its slots hold, [func] with them, and the
     * slot's field in every table, with the definition the field points at, which shares its name. A name
     * starting with `~` names a destructor slot instead ([renameDestructor]); any other is refused on one.
     */
    fun rename(func: Function, newName: String): SlotRenames {
        val slots = implementing(func)
        if (newName.startsWith("~")) return renameDestructor(func, slots)
        require(slots.none(::isDestructor)) {
            "${func.name} fills a destructor slot: name it ~ to name every class's destructor after its class"
        }
        val skipped = mutableListOf<String>()
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
        return field.fieldName != unique && runCatching {
            field.fieldName = unique
            ((field.dataType as? Pointer)?.dataType as? FunctionDefinition)
                ?.let { def -> runCatching { def.name = unique } }
        }.onFailure { skipped += "${struct.name}.${field.fieldName}: ${it.message}" }.isSuccess
    }

    /**
     * Types each pure virtual slot still typed as its ABI's stub (`__cxa_pure_virtual`, `_purecall`), in a
     * primary or a secondary table, off an override of it in a class deriving from the table's: that
     * override's signature as its function now has it, named as it is, with `this` the table's class. Of
     * several overrides, the one whose function's signature has the surest source ([SourceType]), then the
     * signature most of them share, then the nearest, then the first class by name ([pickOverride]). A slot
     * typed otherwise, by the stabs or by hand, stays. Returns how many slots it changed.
     */
    fun typePureSlots(): Int {
        val found = mutableMapOf<VirtualSlot, MutableList<Override>>()
        for (slot in hierarchy.classes.flatMap(::slotsOf)) {
            val func = target(slot) ?: continue
            overridden(slot).forEachIndexed { hops, up ->
                if (holdsStub(up)) found.getOrPut(up) { mutableListOf() } += Override(slot, func, hops + 1)
            }
        }
        return found.count { (slot, overrides) -> typeFrom(slot, overrides) }
    }

    /** An override of a pure virtual slot: [slot] holds [func], [hops] tables down from it. */
    private class Override(val slot: VirtualSlot, val func: Function, val hops: Int)

    /**
     * Types the pure virtual [slot] off the best of [overrides]; whether that changed it. A slot typed so
     * before is typed again in place, as the overrides' signatures may have grown since, and their names.
     */
    private fun typeFrom(slot: VirtualSlot, overrides: List<Override>): Boolean {
        val struct = byAddress[slot.table]?.dataType as? Structure ?: return false
        val field = field(slot) ?: return false
        val old = definition(slot) ?: return false
        val dtm = program.dataTypeManager
        val thisType = owner[slot.table]?.let(program::resolve)?.let(program::classStruct)
            ?.let { PointerDataType(it, dtm) }
        val typed = overrides.map { FunctionDefinitionDataType(it.func.signature, dtm).withThis(thisType) }
        val ranks = overrides.mapIndexed { i, o ->
            OverrideRank(
                o.func.signatureSource,
                typed[i].signatureKey(),
                o.hops,
                owner[o.slot.table]?.qualifiedName.orEmpty(),
            )
        }
        val chosen = pickOverride(ranks)
        val from = overrides[chosen].func
        val before = Triple(old.getPrototypeString(true), field.fieldName, field.comment)
        val again = isTypedOff(field)
        // The stub's own folder when it was laid for this table, so the name is free to take there.
        val category = old.categoryPath.takeIf { again || it.isAncestorOrSelf(struct.categoryPath) }
            ?: struct.categoryPath
        val used = struct.definedComponents.filter { it.ordinal != field.ordinal }.mapNotNull { it.fieldName }.toSet()
        // A destructor is named after the table's own class, as [renameDestructor] names one.
        val leaf = owner[slot.table]?.name?.takeIf { isDestructor(overrides[chosen].slot) }?.let(::destructorName)
            ?: from.name
        val name = generateSequence(0) { it + 1 }.map { if (it == 0) leaf else "${leaf}_$it" }
            .first { it !in used && dtm.getDataType(category, it).let { dt -> dt == null || (again && dt == old) } }
        val def = FunctionDefinitionDataType(category, name, typed[chosen], dtm)
        val comment = TYPED_OFF + from.getName(true)
        if (again) {
            if (old.name != name) old.name = name
            old.replaceWith(def)
            field.fieldName = name
            field.comment = comment
        } else {
            val added = dtm.addDataType(def, DataTypeConflictHandler.DEFAULT_HANDLER)
            struct.replace(field.ordinal, PointerDataType(added, dtm), field.length, name, comment)
        }
        val now = field(slot) ?: return true
        return before != Triple(definition(slot)?.getPrototypeString(true), now.fieldName, now.comment)
    }

    /**
     * Whether [slot] holds its ABI's pure virtual stub, typed as the stub is, taking nothing
     * ([ghicpp.abi.VftableBuilder.addSlot]), or as [typePureSlots] typed it before: the stabs give a pure
     * virtual they declare its `this`.
     */
    private fun holdsStub(slot: VirtualSlot): Boolean {
        val def = definition(slot) ?: return false
        if (def.arguments.isNotEmpty() && field(slot)?.let(::isTypedOff) != true) return false
        val at = component(slot)?.value as? Address ?: return false
        val func = program.functionManager.getFunctionAt(at)?.let {
            if (it.isThunk) it.getThunkedFunction(true) else it
        }
        return (func?.name ?: program.symbolTable.getPrimarySymbol(at)?.name)?.let(::isPureVirtualStub) == true
    }

    private fun isTypedOff(field: DataTypeComponent) = field.comment?.startsWith(TYPED_OFF) == true

    /** [slot]'s field in its table's struct. */
    private fun field(slot: VirtualSlot): DataTypeComponent? =
        component(slot)?.let { (byAddress[slot.table]?.dataType as? Structure)?.getComponent(it.componentIndex) }

    private fun definition(slot: VirtualSlot) = (component(slot)?.dataType as? Pointer)?.dataType as? FunctionDefinition

    private fun component(slot: VirtualSlot): Data? = byAddress[slot.table]?.functionSlots()?.getOrNull(slot.index)

    /**
     * The table of a base [table]'s slots begin with. For a table for a base `B`, the nearest ancestor's
     * table for `B` where one has it, as an abstract class's does for a base whose pure virtuals it leaves
     * pure, else `B`'s own.
     */
    private fun extended(table: Data): Data? {
        val cls = owner[table.address] ?: return null
        val named = forBase(table)
        if (named != null) {
            val ancestors = hierarchy.ancestorsOf(cls)
            return ancestors.firstNotNullOfOrNull { a -> tables[a.id].orEmpty().firstOrNull { forBase(it) == named } }
                ?: ancestors.firstOrNull { it.name == named }?.let(::primary)
        }
        val others = tables[cls.id].orEmpty().mapNotNull(::forBase).toSet()
        return cls.bases.mapNotNull(hierarchy::get).firstOrNull { it.name !in others && primary(it) != null }
            ?.let(::primary)
    }

    /** [cls]'s primary table: its own, else the one for its first base. */
    private fun primary(cls: ClassView): Data? {
        val ts = tables[cls.id].orEmpty()
        return ts.firstOrNull { forBase(it) == null }
            ?: cls.bases.firstNotNullOfOrNull { b -> ts.firstOrNull { forBase(it) == b.name } }
    }

    /**
     * Names the destructor slot [func] fills, with [slots], those of every class's override of it: each
     * function after its own class, as its ABI spells the function a vftable holds, and each table's field
     * the same. Itanium's destructor takes two slots, complete then deleting, so the other one of the pair
     * is named with it: off [func]'s variant where its mangled name says, else the pair is taken to start
     * at an even slot, destructors being declared first. MSVC's slot holds the scalar deleting destructor,
     * gcc 2.x's the destructor itself.
     */
    internal fun renameDestructor(func: Function, slots: List<VirtualSlot>): SlotRenames {
        val abi = destructorAbi()
        val all = if (abi == Itanium) slots + pairedWith(func) else slots
        val skipped = mutableListOf<String>()
        var functions = 0
        var fields = 0
        for (slot in all.distinct()) {
            val f = target(slot)
            val cls = (f?.parentNamespace as? GhidraClass)?.name ?: owner[slot.table]?.name ?: continue
            val name = destructorName(cls, abi)
            if (f != null && f.name != name) {
                runCatching { f.setName(name, SourceType.USER_DEFINED) }
                    .onSuccess { functions++ }.onFailure { skipped += "${f.getName(true)}: ${it.message}" }
            }
            if (nameSlot(slot, name, skipped)) fields++
        }
        return SlotRenames(functions, fields, skipped)
    }

    /** [cls]'s destructor as its ABI spells the function a vftable holds ([renameDestructor]). */
    private fun destructorName(cls: String, abi: CxxAbi = vtableAbi) =
        if (abi == Msvc) MsvcStructor.SCALAR_DELETING_DESTRUCTOR.displayName(cls) else "~$cls"

    private val vtableAbi by lazy { destructorAbi() }

    /** Whether [slot] holds a destructor, by its name or its mangled one: `~Foo`, a deleting one, a `D` variant. */
    internal fun isDestructor(slot: VirtualSlot): Boolean {
        val f = target(slot) ?: return false
        return f.program.symbolTable.getSymbols(f.entryPoint).map { it.name }.any { n ->
            n.startsWith("~") || MsvcStructor.ofName(n, f.parentNamespace.name)?.isDestructor == true ||
                MsvcStructor.ofMangled(n)?.isDestructor == true || ItaniumStructor.of(n)?.isDestructor == true
        }
    }

    /** The ABI the program's vtables are laid by: gcc 2.x's by their labels, MSVC's by its RTTI, else Itanium. */
    private fun destructorAbi(): CxxAbi {
        val labels = owner.keys.asSequence().flatMap { program.symbolTable.getSymbols(it).asSequence() }
        return when {
            labels.any { CxxAbi.ofVtableSymbol(it.name) is Gcc2Abi } -> Gcc2Plain
            hierarchy.classes.any { it.origin == Origin.MSVC_RTTI } -> Msvc
            else -> Itanium
        }
    }

    /** The slots of the other half of the Itanium destructor pair [func] is one of: complete first, deleting next. */
    private fun pairedWith(func: Function): List<VirtualSlot> {
        val own = slotsOf(func).firstOrNull() ?: return emptyList()
        val variant = program.symbolTable.getSymbols(func.entryPoint).firstNotNullOfOrNull {
            ItaniumStructor.of(it.name)
        }
        val deleting = variant?.isDeleting ?: (own.index % 2 == 1)
        val partner = VirtualSlot(own.table, own.label, if (deleting) own.index - 1 else own.index + 1)
        if (partner.index < 0 || owner[own.table]?.let(::slotsOf)?.contains(partner) != true) return emptyList()
        val root = root(partner)
        return hierarchy.classes.flatMap(::slotsOf).filter { root(it) == root }
    }

    private companion object {
        val PURE_VIRTUAL_ABIS = listOf(Itanium, Msvc, Gcc2Plain)

        /** How the comment of a pure virtual slot [typePureSlots] typed begins. */
        const val TYPED_OFF = "pure virtual, typed off "

        fun isPureVirtualStub(name: String) = PURE_VIRTUAL_ABIS.any { it.isPureVirtualStub(name) }

        /** The base a table is for, by its struct's name, `D_vftable_for_B`. */
        fun forBase(table: Data): String? =
            table.dataType.name.substringAfter("_" + ClassNaming.VFTABLE_FOR, "").takeIf { it.isNotEmpty() }
    }
}

/** Types [this]'s pure virtual slots off their overrides ([VirtualSlots.typePureSlots]), counted to [sink]. */
fun Program.typePureSlots(sink: DiagnosticSink) {
    val typed = VirtualSlots(this, ClassHierarchy.of(this, ClassRecordSource.describedElsewhere(this))).typePureSlots()
    if (typed > 0) sink.debug("vftable-pure-slot-typed", count = typed.toLong())
}

/** Every function [ns]'s vtables hold, a thunk's target with it, by its first slot, the primary table's first. */
internal fun Program.slotsOf(ns: Namespace): Map<Address, VirtualSlot> = buildMap {
    val slots = vftablesOf(ns).flatMap { (at, label) ->
        slotTargets(at).mapIndexed { i, target -> target to VirtualSlot(target, label, i) }.toList()
    }.sortedBy { it.second }
    for ((target, slot) in slots) {
        putIfAbsent(target, slot)
        functionManager.getFunctionAt(target)?.getThunkedFunction(true)?.let { putIfAbsent(it.entryPoint, slot) }
    }
}

/**
 * Read off memory by the ABI's slot geometry rather than the laid struct's components: a gcc
 * 2.x slot is `{delta, index, pfn}`, and gcc 2.7's own stab types the pfn as a union a short
 * shows through. Only a gcc 2.x table carries its ABI's symbol at the label; an Itanium
 * `vftable` sits at the address point, past `_ZTV`.
 */
internal fun Program.slotTargets(vftable: Address): Sequence<Address> {
    val length = listing.getDataAt(vftable)?.length ?: return emptySequence()
    val abi = CxxAbi.ofVftable(this, vftable)
    val end = vftable.add(length.toLong())
    return abi.slotOffsets(defaultPointerSize).map(vftable::add).takeWhile { it < end }
        .mapNotNull { runCatching { pointerAt(it) }.getOrNull() }
}

/** The function pointers of a laid vftable, in order, empty and pure virtual slots among them. */
private fun Data.functionSlots(): List<Data> = components.filter {
    (it.dataType as? Pointer)?.dataType is FunctionDefinition
}

/** Where each of [ns]'s vftables sits: the primary and every `internal_vftable`, or each `vftable_for_<Base>`. */
internal fun Program.vftablesOf(ns: Namespace): Sequence<Pair<Address, String>> =
    symbolTable.getSymbols(ns).iterator().asSequence()
        .filter { ClassNaming.isClassVftableLabel(it.name) }
        .map { it.address to it.name }

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

/** What [pickOverride] ranks an override of a pure virtual slot by. */
internal data class OverrideRank(val source: SourceType, val signature: String, val hops: Int, val cls: String)

/**
 * The index of the override among [ranks] a pure virtual slot is typed off: the surest signature source
 * first, then the signature the most of them share, then the fewest tables down, then the class first by name.
 */
internal fun pickOverride(ranks: List<OverrideRank>): Int {
    val shared = ranks.groupingBy { it.signature }.eachCount()
    return ranks.indices.sortedWith(
        compareByDescending<Int> { ranks[it].source.ordinal() }
            .thenByDescending { shared.getValue(ranks[it].signature) }
            .thenBy { ranks[it].hops }
            .thenBy { ranks[it].cls },
    ).first()
}

/** How sure a source is, `USER_DEFINED` the surest, as [SourceType.isHigherPriorityThan] orders them. */
private fun SourceType.ordinal() = SourceType.entries.count { isHigherPriorityThan(it) }

/** [this], `this` retyped to [thisType] where its first parameter is `this` and there is one. */
private fun FunctionDefinition.withThis(thisType: DataType?): FunctionDefinition = apply {
    val args = arguments
    if (thisType != null && args.firstOrNull()?.name == "this") {
        setArguments(
            *args.mapIndexed { i, a ->
                if (i == 0) ParameterDefinitionImpl(a.name, thisType, a.comment) else a
            }.toTypedArray(),
        )
    }
}

/** [this]'s signature, its name aside: what two overrides of a slot agree on. */
private fun FunctionDefinition.signatureKey() =
    (listOf(returnType) + arguments.map { it.dataType }).joinToString(",") { it.pathName } +
        "|$callingConventionName|${hasVarArgs()}"
