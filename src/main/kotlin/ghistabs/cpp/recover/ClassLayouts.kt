package ghistabs.cpp.recover

import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.*
import ghistabs.cpp.*
import ghistabs.cpp.abi.CxxAbi
import ghistabs.cpp.abi.VtableRecord
import ghistabs.diagnose.DiagnosticSink

/**
 * Lays each class struct a class pass sized but left empty, off what the pass knows of the class: each
 * non-virtual base at its offset, then a `{vfptr}` at each of its vptrs, typed to that vftable's struct. A
 * vptr inside a base subobject replaces the base's, which is split around it as [BaseSplitter] splits a
 * stabs class's primary base. In between, the virtual bases ([VirtualBases]), so their vptrs split them
 * too. A vftable no analysis typed gets a struct, a slot per function, as `RecoverClassesFromRTTIScript`
 * makes one. Bases go first, so a class embeds its bases laid: a base with virtual bases as its
 * non-virtual part alone, its "self-base", which the deriving class's own virtual bases follow.
 */
class ClassLayouts(private val program: Program, private val abi: CxxAbi, sink: DiagnosticSink) :
    DiagnosticSink by sink {
    private val dtm = program.dataTypeManager
    private val registry = DtmRegistry(dtm)
    private val vfptrs = BaseSplitter(registry, sink)
    private val slots = VtableSweeper(registry, program, TaskMonitor.DUMMY, sink)
    private val vbases = VirtualBases(program, abi, sink)

    /**
     * The slot definitions of the tables laid, a base's first, the bases going first, as
     * `RecoverClassesFromRTTIScript` files an inherited slot's in the ancestor's folder, so that its
     * `ApplyClassFunctionSignatureUpdatesScript` edits the one definition every table points at.
     */
    private val defined = SlotDefinitions()

    /**
     * Lays [classes]' empty structs, a base before the classes deriving from it, each with the fields its
     * constructors [stores] ([Structors.constructorStores]); returns how many it laid.
     */
    fun layAll(classes: Collection<ClassDecl>, stores: Map<ClassDecl, Map<Int, Int>>): Int =
        classes.sortedBy { it.ancestors.size }.count { it.lay(stores[it].orEmpty()) }

    /** Lays [this]'s struct, with the bytes its constructors [store] at each offset as its own fields. */
    private fun ClassDecl.lay(store: Map<Int, Int>): Boolean {
        val ns = ns?.toClass() ?: return false
        // Any struct with fields is another's: the stabs import's, the script's, a PDB's.
        val struct = program.classStruct(ns)?.takeIf { it.numDefinedComponents == 0 && !it.isZeroLength }
            ?: return false
        val bases = bases.filterNot { it.isVirtual }
        for (base in bases) struct.placeBase(base, bases.size, ns)
        for (at in vbptrs) struct.placeVbptr(at.toInt(), ns)
        vbases.placeAll(listOf(this))
        val records = vftables.mapNotNull { r ->
            r.vfptrOffset(program)?.let { r to it.toInt() }
        }.sortedBy { it.second }
        records.forEachIndexed { i, (record, at) ->
            val vftable = vftableStruct(ns, record, i, records.size)
            struct.placeVfptr(at, PointerDataType(vftable, dtm), ns)
        }
        struct.placeData(store, ns)
        return true
    }

    private fun Structure.placeBase(base: ClassBase, count: Int, ns: GhidraClass) {
        val at = base.offset?.toInt() ?: return
        val qualified = ns.getName(true)
        val whole = base.cls.ns?.toClass()?.let(program::classStruct)?.takeUnless { it.isZeroLength }
        if (whole == null) return degradation("base-undefined", qualified.member(base.cls.name), "no struct for it")
        val dt = nonVirtualSize(base.cls)?.takeIf { it < whole.length }?.let { selfBaseOf(whole, it) } ?: whole
        when {
            at + dt.length > length -> "${dt.name} (${dt.length}b) at +$at overruns $length"
            componentsOverlapping(at, dt.length).isNotEmpty() -> "${dt.name} at +$at covers laid fields"
            else -> null
        }?.let { return degradation("base-layout-failed", qualified.member(dt.name), it) }
        placeBase(
            this,
            at,
            dt,
            isVirtual = false,
            "${base.access.name.lowercase()} ${base.cls.qualifiedName}",
            ClassNaming.baseFieldName(false, dt.name, count),
            qualified,
        )
    }

    /** Where [cls]'s first virtual base sits, which its non-virtual part ends before; null without one. */
    private fun nonVirtualSize(cls: ClassDecl) = cls.virtualBases.mapNotNull { it.offset?.toInt() }.minOrNull()

    /**
     * [cls]'s first [size] bytes as a struct of their own, filed where Ghidra's PDB importer files a class's
     * self-base ([ClassUtils.getBaseClassDataTypePath]): its fields but its virtual bases.
     */
    private fun selfBaseOf(cls: Structure, size: Int): Structure {
        val path = ClassUtils.getBaseClassDataTypePath(cls)
        return registry.getOrRegister<Structure>(path) {
            StructureDataType(path.categoryPath, path.dataTypeName, size, dtm).apply {
                description = "${cls.name} as a base subobject"
                cls.definedComponents.filter { it.offset + it.length <= size && !it.isVirtualBaseField() }.forEach {
                    replaceAtOffset(it.offset, it.dataType, it.length, it.fieldName, it.comment)
                }
            }
        }
    }

    private fun DataTypeComponent.isVirtualBaseField() = fieldName.orEmpty().startsWith(ClassNaming.VBASE_PREFIX)

    /**
     * The fields [store] puts where nothing is laid yet, the class's own, gathered in a `<Class>_data` struct
     * per run of them between what is, as `RecoverClassesFromRTTIScript` gathers them.
     */
    private fun Structure.placeData(store: Map<Int, Int>, ns: GhidraClass) {
        buildList<MutableList<Pair<Int, Int>>> {
            val own = store.filter { (at, size) ->
                at >= 0 && at + size <= length && componentsOverlapping(at, size).isEmpty()
            }
            for ((at, size) in own.toSortedMap()) {
                val run = lastOrNull()?.takeIf { r ->
                    componentsOverlapping(r.first().first..at + size).isEmpty()
                }
                if (run != null && run.last().let { (a, s) -> a + s <= at }) {
                    run += at to size
                } else {
                    this += mutableListOf(at to size)
                }
            }
        }.forEachIndexed { i, run ->
            val start = run.first().first
            val end = run.last().let { (at, size) -> at + size }
            val name = "${ns.name}${ClassNaming.DATA}" + "_$i".takeIf { i > 0 }.orEmpty()
            val data = registry.getOrRegister<Structure>(ClassNaming.vftableCategory(ns).at(name)) {
                StructureDataType(ClassNaming.vftableCategory(ns), name, end - start, dtm).apply {
                    description = "${ns.name}'s own fields, where its constructors store them"
                    for ((at, size) in run) {
                        replaceAtOffset(
                            at - start,
                            Undefined.getUndefinedDataType(size),
                            size,
                            "field_0x${at.toString(16)}",
                            null,
                        )
                    }
                }
            }
            runCatching { replaceAtOffset(start, data, data.length, name, "own fields") }
                .onFailure { degradation("class-data-unlaid", "${ns.getName(true)}::$name", it.message) }
        }
    }

    /** A `{vbptr}` at [at], where no base subobject holds it already. */
    private fun Structure.placeVbptr(at: Int, ns: GhidraClass) {
        val vbptr = PointerDataType(IntegerDataType.dataType, dtm)
        if (at < 0 || getComponentContaining(at)?.isBaseField() == true) return
        if (componentsOverlapping(at, vbptr.length).isNotEmpty() || at + vbptr.length > length) {
            return degradation("vbptr-collision", ns.getName(true), "cannot place {vbptr} at +$at")
        }
        replaceAtOffset(at, vbptr, vbptr.length, ClassNaming.VBPTR, "vbtable pointer: its virtual bases' offsets")
    }

    /** A `{vfptr}` of type [vfptr] at [at], in place of the one a base subobject there has. */
    private fun Structure.placeVfptr(at: Int, vfptr: DataType, ns: GhidraClass) {
        val holder = getComponentContaining(at)?.takeIf { it.isBaseField() }
        if (holder != null) {
            if (!vfptrs.splitBase(this, ns.getPathList(true).toList(), at, holder, vfptr)) {
                debug("vfptr-inherited-from-base", ns.getName(true))
            }
            return
        }
        if (componentsOverlapping(at, vfptr.length).isNotEmpty() || at + vfptr.length > length) {
            return degradation("vfptr-collision", ns.getName(true), "cannot place {vfptr} at +$at")
        }
        replaceAtOffset(at, vfptr, vfptr.length, ClassUtils.VFPTR, "vtable pointer")
    }

    /**
     * The struct of [this]'s vftable [record], table [index] of [count] by vptr offset: the one laid at its
     * address point, else one made off its slots and laid there, named for the base it serves.
     */
    private fun ClassDecl.vftableStruct(ns: GhidraClass, record: VtableRecord, index: Int, count: Int): Structure {
        val laid = program.listing.getDataAt(record.addressPoint)
        (laid?.dataType as? Structure)?.takeIf { "_${ClassNaming.VFTABLE}" in it.name }?.let {
            defined.addLaid(laid)
            return it
        }
        val label = program.symbolTable.getSymbols(record.addressPoint)
            .firstOrNull { it.parentNamespace == ns && ClassNaming.isClassVftableLabel(it.name) }

        val primary = ClassNaming.vftablePath(ns)
        // The class's own table, at the front of its object, is its plain `_vftable` whatever else it has.
        val served = servedBase(record, program)?.name
        val name = if (served == null && record.vfptrOffset(program) == 0L) {
            primary.dataTypeName
        } else {
            ClassNaming.vftableName(primary, index, count, served)
        }
        val category = if (index == 0) primary.categoryPath else ClassNaming.internalSlotCategory(primary, index)
        val vftable = registry.getOrRegister<Structure>(primary.categoryPath.at(name)) {
            StructureDataType(primary.categoryPath, name, 0, dtm)
        }
        if (vftable.numComponents == 0) {
            record.slots(program).forEach { slots.addSweptSlot(vftable, category, it, abi, defined = defined) }
        }
        vftable.describeVxTable(ns.name, label?.name ?: ClassNaming.VFTABLE, record.vfptrOffset(program))
        runCatching { program.forceCreateData(record.addressPoint, vftable) }
            .onSuccess(defined::addLaid)
            .onFailure { degradation("vftable-unlaid", "${ns.getName(true)}::$name", it.message, record.addressPoint) }
        return vftable
    }

    /**
     * Each slot target's definition, by the first vftable defining it, so every table pointing at a function
     * shares the one definition, as `RecoverClassesFromRTTIScript` shares an inherited slot's.
     */
    internal class SlotDefinitions(private val byTarget: MutableMap<Address, DataType> = mutableMapOf()) :
        Map<Address, DataType> by byTarget {

        /** Keeps [definition] for [target] unless one came first. */
        fun add(target: Address, definition: DataType) {
            byTarget.putIfAbsent(target, definition)
        }

        /** Keeps the definitions of a vftable laid as [table], by the function each slot points at. */
        fun addLaid(table: Data) {
            for (slot in table.components) {
                val target = slot.value as? Address ?: continue
                val definition = (slot.dataType as? Pointer)?.dataType as? FunctionDefinition ?: continue
                add(target, definition)
            }
        }
    }
}
