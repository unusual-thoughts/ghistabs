package ghicpp.abi

import ghicpp.*
import ghicpp.abi.gcc2.Gcc2
import ghicpp.abi.itanium.TypeinfoReader
import ghicpp.abi.itanium.secondaryVtables
import ghidra.app.util.demangler.DemangledDataType
import ghidra.app.util.demangler.DemangledFunction
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.Data
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidrakt.*
import ghidrakt.diagnose.DiagnosticSink
import ghidrakt.diagnose.DummySink

/**
 * Lays vtables and their slots, typed off the functions the slots point at: the toolkit the stabs import
 * ([ghistabs.importer.ClassApplier]), the class pass ([ghicpp.recover.ClassStructFiller]) and the sweep
 * ([ghicpp.recover.VtableSweepPass]) share. [importedType] gives a demangled parameter's type as the stabs
 * import made it, before Ghidra's lookup, which misses `std::_Ios_Openmode` filed under no namespace; null
 * for none.
 */
class VftableBuilder(
    internal val registry: DtmRegistry,
    internal val program: Program,
    private val sink: DiagnosticSink = DummySink,
    private val importedType: (DemangledDataType) -> DataType? = { null },
) : DiagnosticSink by sink {
    internal val symtab = program.symbolTable
    val dtm = program.dataTypeManager

    fun DemangledDataType.slotParameterType(category: String, degrades: String) = importedType(this)
        ?: parameterType(dtm)
        ?: Undefined4DataType.dataType.also { degradation(category, degrades, "demangler gave no type for $this") }

    /**
     * gcc 2.x secondary vtables (`_vt.<class>.<base>`) by class, each with its base, one per record though
     * a.out labels each twice.
     */
    internal val gcc2SecondaryVtables: Map<String, List<Pair<String, VtableRecord>>> by lazy {
        buildMap {
            for (sym in symtab.symbolIterator) {
                val (cls, base) = Gcc2.secondaryVtableClasses(sym.name) ?: continue
                val abi = CxxAbi.ofVtableSymbol(sym.name) ?: continue
                getOrPut(cls) { mutableListOf() } +=
                    base to abi.recordAt(program, sym.address).copy(internal = true)
            }
        }.mapValues { (_, tables) -> tables.distinctBy { it.second.address }.sortedBy { it.second.address } }
    }

    /**
     * Lays the secondary vtables behind [primary], found off memory, as the stabs may declare fewer
     * virtuals than the table holds. Once there are several, each table, [primaryVftable] included, is
     * named after the base whose vptr points into it, as Ghidra's `RTTIGccClassRecoverer` does
     * ([ClassNaming.vftableName]); a construction group's labels stay as they are.
     */
    fun laySecondaries(
        primary: VtableRecord,
        primaryVftable: Structure?,
        leaf: String,
        ns: Namespace,
        source: SourceType = SourceType.IMPORTED,
    ) {
        val abi = primary.abi
        val construction = primary.construction
        val rtti = primary.rttiOf(program) ?: return
        val ptr = program.defaultPointerSize.toLong()
        val slots = primary.slots(program).size
        // A record without slots has nothing to lay a struct over.
        val subs = program.secondaryVtables(primary.addressPoint.add(slots * ptr), rtti, construction)
            .filter { it.targets.isNotEmpty() }
        val offsets = listOfNotNull(primaryVftable?.let { 0L }) +
            subs.map { it.record.vfptrOffset(program) }
        val bases = if (offsets.size < 2) emptyList() else baseNames(offsets, baseSubobjects(primary, rtti))
        val path = ClassNaming.vftablePath(ns, leaf)
        primaryVftable?.let {
            val label = ClassNaming.vftableLabel(internal = false, construction, bases.firstOrNull())
            nameTable(it, ClassNaming.vftableName(path, 0, offsets.size, bases.firstOrNull()), label, leaf, 0L)
            program.renameVtableLabel(primary.addressPoint, ClassNaming.vftableLabel(false, construction), label, ns)
        }
        val first = offsets.size - subs.size
        subs.forEachIndexed { i, sub ->
            val index = first + i
            val base = bases.getOrNull(index)
            val at = path.categoryPath.at(ClassNaming.vftableName(path, index, offsets.size, base))
            val vftable = internalVftable(at, ClassNaming.internalSlotCategory(path, i), sub.targets, abi)
            vftable.describeVxTable(leaf, ClassNaming.vftableLabel(internal = true, construction, base), offsets[index])
            val laidAt = sub.record.lay(registry, program, vftable, ns, base, source = source)
            debug("vtable-secondary", "class=$leaf index=$index base=$base slots=${sub.targets.size}", address = laidAt)
        }
    }

    /**
     * Lays [className]'s gcc 2.x secondaries, each a record with its own symbol (`_vt$9TeeStream$3ios`),
     * named as [laySecondaries] names an Itanium group, and tagged with its base's vptr offset in
     * [classStruct] where there is one. Records already laid are skipped, but still count towards the
     * names: a re-import lays the primary afresh, and naming it again, as [laySecondaries] does an
     * Itanium group's, puts it in place of the table the earlier import laid.
     */
    fun layGcc2Secondaries(
        className: String,
        leaf: String,
        ns: Namespace,
        classStruct: Structure?,
        source: SourceType = SourceType.IMPORTED,
    ) {
        val records = gcc2Secondaries(className)
        if (records.isEmpty()) return
        val path = ClassNaming.vftablePath(ns, leaf)
        val primaryAt = symtab.getSymbols(ClassNaming.VFTABLE, ns).firstOrNull()?.address
        // A struct the stabs filled stays `<leaf>_vftable` even with no primary record.
        val primaryVftable = dtm.getDataType(path) as? Structure
        val count = records.size + if (primaryVftable != null) 1 else 0
        val names = when {
            count >= 2 -> baseNames(
                listOfNotNull(primaryVftable?.let { 0L }) + records.indices.map { it + 1L },
                records.mapIndexed { i, (r, _) -> i + 1L to r.first }.plus(
                    listOfNotNull(classStruct?.primaryBase()?.let { 0L to it }),
                ).toMap(),
            )

            else -> emptyList()
        }
        if (primaryVftable != null && primaryAt != null) {
            val label = ClassNaming.vftableLabel(internal = false, base = names.first())
            val vfptrAt = classStruct?.vfptrOffset()?.toLong()
            nameTable(primaryVftable, ClassNaming.vftableName(path, 0, count, names.first()), label, leaf, vfptrAt)
            program.renameVtableLabel(primaryAt, ClassNaming.VFTABLE, label, ns)
        }
        val first = count - records.size
        records.forEachIndexed { i, (key, targets) ->
            val (base, record) = key
            if (targets == null) return@forEachIndexed
            val index = first + i
            val name = names.getOrNull(index)
            val at = path.categoryPath.at(ClassNaming.vftableName(path, index, count, name))
            val vftable = internalVftable(at, ClassNaming.internalSlotCategory(path, i), targets, record.abi)
            val vfptrAt = classStruct?.vfptrOffsetOfBase(base)?.toLong()
            vftable.describeVxTable(leaf, ClassNaming.vftableLabel(internal = true, base = name), vfptrAt)
            record.lay(registry, program, vftable, ns, name, source = source)
            debug(
                "vtable-secondary",
                "class=$className index=$index base=$base slots=${targets.size}",
                address = record.address,
            )
        }
    }

    /**
     * [className]'s gcc 2.x secondaries, less any without slots, each with the slots to lay, or none when
     * a class already laid it.
     */
    private fun gcc2Secondaries(className: String) =
        gcc2SecondaryVtables[className].orEmpty().mapNotNull { (base, record) ->
            if (program.isVtableClaimed(record)) return@mapNotNull (base to record) to null
            record.slots(program).ifEmpty {
                degradation("vtable-secondary-empty", className, "no slots read for base $base", record.address)
                null
            }?.let { (base to record) to it }
        }

    /** The bases of [primary]'s class by subobject offset, direct and virtual, as its typeinfo [rtti] says. */
    private fun baseSubobjects(primary: VtableRecord, rtti: Address): Map<Long, String> = TypeinfoReader(program).run {
        basesOf(rtti).orEmpty() + virtualBasesOf(rtti)
    }.mapNotNull { base ->
        // A virtual base's typeinfo offset locates its vbase offset in the vtable.
        when {
            base.isVirtual -> primary.vbaseOffset(program, base)
            else -> base.offset
        }?.let { it to base.className }
    }.distinctBy { it.first }.toMap()

    /** The base each table at [offsets] is for, its template arguments dropped unless that makes two alike. */
    private fun baseNames(offsets: List<Long?>, subobjects: Map<Long, String>): List<String?> {
        val whole = offsets.map { off -> off?.let(subobjects::get)?.let { canonTemplateName(it.leafName) } }
        val short = whole.map { it?.substringBefore('<') }
        return whole.indices.map { i ->
            short[i]?.takeIf { s -> short.count { it == s } == 1 }
                ?: whole[i]?.takeIf { w -> whole.count { it == w } == 1 }
        }
    }

    /** Renames a primary table to [name], replacing an earlier table of that name rather than forking a `.conflict`. */
    private fun nameTable(vftable: Structure, name: String, label: String, leaf: String, vfptrAt: Long?) {
        if (vftable.name != name) {
            dtm.getDataType(vftable.categoryPath, name)?.takeIf { it != vftable }
                ?.let { dtm.replaceDataType(it, vftable, false) }
            runCatching { vftable.name = name }
                .onFailure { degradation("vftable-rename-failed", leaf, "${vftable.name} -> $name: ${it.message}") }
        }
        vftable.describeVxTable(leaf, label, vfptrAt)
    }

    /**
     * The secondary table at [at], typed off its [targets]. Its slot definitions go in their own
     * [slotCategory], or a thunk named like its target would fork a `.conflict`.
     */
    private fun internalVftable(
        at: DataTypePath,
        slotCategory: CategoryPath,
        targets: List<Address>,
        abi: CxxAbi,
    ): Structure {
        val vftable = registry.getOrRegister<Structure>(at) {
            StructureDataType(at.categoryPath, at.dataTypeName, 0, dtm)
        }
        if (vftable.numComponents == 0) addSlots(vftable, slotCategory, targets, abi)
        return vftable
    }

    /** Fills [vftable] off [targets]: [abi]'s reserved entry, then each slot with its adjustment. */
    internal fun addSlots(vftable: Structure, category: CategoryPath, targets: List<Address>, abi: CxxAbi) {
        val used = mutableSetOf<String>()
        with(abi) {
            vftable.addReservedHeader()
            targets.forEachIndexed { slot, target ->
                vftable.addEntryAdjustment(slot)
                addSlot(vftable, category, target, abi, used)
            }
        }
    }

    /**
     * Adds a slot pointing at [target], always as a function definition pointer, even to
     * `__cxa_pure_virtual`. The field and the definition share a name, as Ghidra's class recovery expects,
     * so an overload gets a `_1` suffix; [used] holds the names this table spent. A target [defined]
     * already, in another table, keeps its definition and its name, so an edit to it reaches every table.
     * Code at [target] with no function becomes one ([functionAtOrCreate]).
     */
    fun addSlot(
        vftable: Structure,
        category: CategoryPath,
        target: Address,
        abi: CxxAbi,
        used: MutableSet<String> = mutableSetOf(),
        defined: SlotDefinitions? = null,
    ) {
        val reused = defined?.get(target)
        // Code nothing reached but this pointer becomes a function first, so the slot is typed and named off it.
        val func = if (reused == null) program.functionAtOrCreate(target) else null
        val linkage = symtab.getSymbols(target).map { it.name }.firstOrNull(abi::isProbablyMangled)
            ?: symtab.getPrimarySymbol(target)?.name
            ?: "slot"
        val leaf = reused?.name ?: Demangler.of(linkage)?.name ?: linkage
        val name = generateSequence(0) { it + 1 }
            .map { if (it == 0) leaf else "${leaf}_$it" }
            .first(used::add)

        val funcDef = reused ?: func
            ?.let { FunctionDefinitionDataType(category, name, it.signature, dtm) }
            .let { it ?: demangledDefinition(category, name, linkage) }
            .let(registry::registerAgain)
        defined?.add(target, funcDef)
        vftable.add(PointerDataType(funcDef, dtm), name, "$target")
    }

    /** The definition [name] for a target with only its [linkage] name to go by; untyped if that isn't mangled. */
    private fun demangledDefinition(category: CategoryPath, name: String, linkage: String) =
        FunctionDefinitionDataType(category, name, dtm).apply {
            fun DemangledDataType.dt() = slotParameterType("vftable-demangled-untyped", "$category/$name")
            (Demangler.of(linkage) as? DemangledFunction)?.let { df ->
                // `void` has no size either, but a return may be one.
                df.returnType?.let { t -> returnType = runCatching { t.getDataType(dtm) }.getOrNull() ?: t.dt() }
                setArguments(
                    *df.formals.mapIndexed { i, t -> ParameterDefinitionImpl("arg$i", t.dt(), null) }.toTypedArray(),
                )
            }
        }
}

/**
 * Each slot target's definition, by the first vftable defining it, so every table pointing at a function
 * shares the one definition, as `RecoverClassesFromRTTIScript` shares an inherited slot's.
 */
class SlotDefinitions(private val byTarget: MutableMap<Address, DataType> = mutableMapOf()) :
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
