package ghicpp.recover

import ghicpp.*
import ghicpp.abi.CxxAbi
import ghicpp.abi.SlotDefinitions
import ghicpp.abi.VftableBuilder
import ghicpp.abi.VtableRecord
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor
import ghistabs.*
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink

/**
 * Fills each class struct a class pass sized but left empty, off what the pass knows of the class: each
 * non-virtual base at its offset, then a `{vfptr}` at each of its vptrs, typed to that vftable's struct. A
 * vptr inside a base subobject replaces the base's, which is split around it as [BaseSplitter] splits a
 * stabs class's primary base. In between, the virtual bases ([VirtualBasePass]), so their vptrs split them
 * too. A vftable no analysis typed gets a struct, a slot per function, as `RecoverClassesFromRTTIScript`
 * makes one. Bases go first, so a class embeds its bases filled: a base with virtual bases as its
 * non-virtual part alone, its "self-base", which the deriving class's own virtual bases follow.
 *
 * The split is [VfptrModel.SPLIT_BASE]'s, as for the stabs import. Under [VfptrModel.INHERITED] a base
 * subobject keeps its own `{vfptr}`, typed to the base's vftable, and the class adds one only where no
 * base holds its vptr.
 */
class ClassStructFiller(
    private val program: Program,
    private val abi: CxxAbi,
    sink: DiagnosticSink,
    private val vfptrModel: VfptrModel = VfptrModel.OPTION.default,
) : DiagnosticSink by sink {
    private val dtm = program.dataTypeManager
    private val registry = DtmRegistry(dtm)
    private val vfptrs = BaseSplitter(registry, sink)
    private val slots = VftableBuilder(registry, program, sink)
    private val vbases = VirtualBasePass(program, abi, sink)

    /**
     * The slot definitions of the tables laid, a base's first, the bases going first, as
     * `RecoverClassesFromRTTIScript` files an inherited slot's in the ancestor's folder, so that its
     * `ApplyClassFunctionSignatureUpdatesScript` edits the one definition every table points at.
     */
    private val defined = SlotDefinitions()

    /**
     * Fills [classes]' empty structs, a base before the classes deriving from it, each with the fields its
     * constructors [stores] ([FoundStructors.constructorStores]); returns how many it filled.
     */
    fun fillAll(classes: Collection<ClassDecl>, stores: Map<ClassDecl, Map<Int, DataType>>): Int =
        classes.sortedBy { it.ancestors.size }.count { it.fillStruct(stores[it].orEmpty()) }

    /**
     * Fills [this]'s struct, with the fields its constructors [store] at each offset as its own. A struct filled
     * already only has its `<Class>_data` fields refilled, so that running the pass again once the reverser has
     * typed more of the constructors types more of the fields.
     */
    private fun ClassDecl.fillStruct(store: Map<Int, DataType>): Boolean {
        val ns = ns?.toClass() ?: return false
        val struct = program.classStruct(ns) ?: return false
        // Any struct with fields is another's, the stabs import's, the script's, a PDB's, or an earlier pass's.
        if (struct.numDefinedComponents > 0 || struct.isZeroLength) return false.also { struct.fillData(store, ns) }
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
        struct.fillData(store, ns)
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
            componentsOverlapping(at, dt.length).isNotEmpty() -> "${dt.name} at +$at covers existing fields"
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
     * The fields [store] puts where no field is yet, the class's own, gathered in a `<Class>_data` struct
     * per gap between what is, as `RecoverClassesFromRTTIScript` gathers them: the fields a gap holds are those
     * the same existing field, or none, comes after.
     */
    private fun Structure.placeData(store: Map<Int, DataType>, ns: GhidraClass) {
        val own = store.filter { (at, dt) -> at >= 0 && componentsOverlapping(at, dt.length).isEmpty() }
        own.toSortedMap().entries.groupBy { (at, _) -> getDefinedComponentAtOrAfterOffset(at)?.offset }
            .values.forEachIndexed { i, run -> placeDataRun(run.associate { it.toPair() }, ns, i) }
    }

    /** A `<Class>_data` struct, the [index]th of [ns]'s, of the [fields] in one gap, by offset into the class. */
    private fun Structure.placeDataRun(fields: Map<Int, DataType>, ns: GhidraClass, index: Int) {
        val start = fields.keys.first()
        val end = fields.maxOf { (at, dt) -> at + dt.length }
        if (end > length) return
        val name = "${ns.name}${ClassNaming.DATA}" + "_$index".takeIf { index > 0 }.orEmpty()
        val data = registry.getOrRegister<Structure>(ClassNaming.vftableCategory(ns).at(name)) {
            StructureDataType(ClassNaming.vftableCategory(ns), name, end - start, dtm).apply {
                description = "${ns.name}'s own fields, where its constructors store them"
            }
        }
        runCatching { replaceAtOffset(start, data, data.length, name, "own fields") }
            .onFailure { degradation("class-data-unlaid", "${ns.getName(true)}::$name", it.message) }
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
            val split = vfptrModel == VfptrModel.SPLIT_BASE && vfptrs.splitBase(this, ns.path, at, holder, vfptr)
            if (!split) {
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
            record.slots(program).forEach { slots.addSlot(vftable, category, it, abi, defined = defined) }
        }
        vftable.describeVxTable(ns.name, label?.name ?: ClassNaming.VFTABLE, record.vfptrOffset(program))
        runCatching { program.forceCreateData(record.addressPoint, vftable) }
            .onSuccess(defined::addLaid)
            .onFailure { degradation("vftable-unlaid", "${ns.getName(true)}::$name", it.message, record.addressPoint) }
        return vftable
    }
}

/**
 * Fills each `<Class>_data` struct placed in this with the fields of [store] it holds, as Auto Fill in Structure
 * fills one: where a field is there already, [NoisyStructureBuilder] keeps the more specific type,
 * and the field keeps its name
 */
private fun Structure.fillData(store: Map<Int, DataType>, ns: GhidraClass) {
    for (part in definedComponents) {
        val data = part.dataType as? Structure ?: continue
        if (data.categoryPath != categoryPath || !data.name.startsWith(ns.name + ClassNaming.DATA)) continue
        val inside = store.filter { (at, dt) -> at >= part.offset && at + dt.length <= part.endOffset + 1 }
        val merged = NoisyStructureBuilder().also { it.populateOriginalStructure(data) }
        for ((at, dt) in inside) merged.addDataType(at.toLong() - part.offset, dt)
        for ((at, dt) in merged.iterator()) {
            val old = data.getComponentAt(at.toInt())
            if (at + dt.length > data.length || old?.dataType?.isEquivalent(dt) == true) continue
            val name = old?.fieldName ?: "field_0x${(part.offset + at).toString(16)}"
            data.replaceAtOffset(at.toInt(), dt, dt.length, name, old?.comment)
        }
    }
}

/**
 * Retypes [ns]'s own fields off what [methods] load and store through `this`, decompiled again, as the class pass
 * fills them: the `<Class>_data` structs its struct holds take the more specific type, and keep names and comments.
 */
fun Program.updateFieldTypes(ns: GhidraClass, methods: Collection<Function>, monitor: TaskMonitor) {
    val struct = classStruct(ns) ?: return
    struct.fillData(
        mergedStores(StructorInspector(this, emptyList(), DummySink).thisFields(methods, monitor).values),
        ns,
    )
}
