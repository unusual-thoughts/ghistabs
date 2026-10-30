package ghistabs.cpp.recover

import ghidra.app.util.demangler.DemangledDataType
import ghidra.app.util.demangler.DemangledFunction
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.*
import ghistabs.cpp.*
import ghistabs.cpp.abi.*
import ghistabs.cpp.abi.gcc2.Gcc2
import ghistabs.cpp.abi.itanium.*
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink

/**
 * Lays the vtables no class claimed ([isVtableClaimed]), Itanium's and gcc 2.x's, typed off the functions
 * their slots point at. Needs only symbols and memory, so [ghistabs.entrypoints.GccVftableAnalyzer] sweeps
 * with or without stabs. [ghistabs.importer.ClassApplier] uses only its table-laying helpers.
 */
open class VtableSweeper(
    internal open val registry: DtmRegistry,
    internal val program: Program,
    internal val monitor: TaskMonitor,
    private val sink: DiagnosticSink = DummySink,
) : DiagnosticSink by sink {
    internal val symtab = program.symbolTable
    internal val dtm = program.dataTypeManager

    /**
     * A demangled parameter's type as the stabs import made it, before Ghidra's lookup, which misses
     * `std::_Ios_Openmode` filed under no namespace. Null for none.
     */
    protected open fun importedType(t: DemangledDataType): DataType? = null

    internal fun DemangledDataType.slotParameterType(category: String, degrades: String) = importedType(this)
        ?: parameterType(dtm)
        ?: Undefined4DataType.dataType.also { degradation(category, degrades, "demangler gave no type for $this") }

    companion object {
        /** A swept table's label source, below the import's, so a class can still claim it ([isVtableClaimed]). */
        private val SWEPT = SourceType.ANALYSIS

        /** How the demangler spells a construction vtable's owner: `Left-in-Diamond`. */
        private const val CONSTRUCTION_INFIX = "-in-"

        val VTABLES_SWEPT = BoolOption("Vtables Swept", "Vtables no class claimed already laid.", false)

        /** Whether a sweep ran since a class pass last claimed tables. */
        val Program.isVtablesSwept get() = this[VTABLES_SWEPT]

        /** Set [value] false once a class pass claims tables, so the next sweep looks again. */
        fun Program.markVtablesSwept(value: Boolean = true) {
            this[VTABLES_SWEPT] = value
        }
    }

    /**
     * gcc 2.x secondary vtables (`_vt.<class>.<base>`) by class, each with its base, one per record though
     * a.out labels each twice.
     */
    private val gcc2SecondaryVtables: Map<String, List<Pair<String, VtableRecord>>> by lazy {
        buildMap {
            for (sym in symtab.symbolIterator) {
                val (cls, base) = Gcc2.secondaryVtableClasses(sym.name) ?: continue
                val abi = CxxAbi.ofVtableSymbol(sym.name) ?: continue
                getOrPut(cls) { mutableListOf() } +=
                    base to program.vtableRecord(sym.address, abi).copy(internal = true)
            }
        }.mapValues { (_, tables) -> tables.distinctBy { it.second.address }.sortedBy { it.second.address } }
    }

    /**
     * Lays every vtable no class claimed, mostly those of libraries linked without stabs, then the gcc 2.x
     * secondaries, construction vtables and VTTs. The slots are named and typed after their targets alone,
     * and no class struct is made. Returns how many primary vtables it laid, and marks the program swept.
     */
    internal fun sweepUnclaimedVtables(): Int {
        val unclaimed = symtab.symbolIterator
            .mapNotNull { sym ->
                primaryVtableOf(sym)?.let { (cls, abi) ->
                    program.definedVtableRecord(sym.address, abi)?.let { cls to it }
                }
            }
            .distinctBy { (_, record) -> record.address }
            .filterNot { (_, record) -> program.isVtableClaimed(record) }
            .toList()

        monitor.initialize(unclaimed.size.toLong(), "Laying vtables no class claimed")
        var laid = 0
        for ((qualified, record) in unclaimed) {
            monitor.increment()
            val abi = record.abi
            val targets = record.slots(program)
            if (targets.isEmpty()) {
                degradation("vtable-swept-empty", qualified, "no function pointers", record.addressPoint)
                continue
            }
            // The class of its demangled `vtable` label, which a stabs import may have given a shortened name.
            val labelled = labelledClass(record.address)
            val leaf = labelled?.name ?: canonTemplateName(qualified.leafName)
            val ns = labelled ?: symtab.buildClassNamespaces(qualified.nameSegments)
            val path = ClassNaming.vftablePath(ns, leaf)
            val vftable = registry.getOrRegister<Structure>(path) {
                StructureDataType(path.categoryPath, path.dataTypeName, 0, dtm)
            }
            // Slots the stabs typed, for a class whose vtable they couldn't place, beat any read off targets.
            if (vftable.numComponents == 0) {
                addSweptSlots(vftable, path.categoryPath, targets, abi)
                vftable.describeVxTable(leaf, ClassNaming.VFTABLE, abi.primaryVptrOffset)
            }

            val addressPoint = record.lay(registry, program, vftable, ns, source = SWEPT)
            debug("vtable-reconstructed", "${targets.size} slot(s) typed from targets", addressPoint, qualified)
            laid++
            // Itanium's secondaries follow the primary; gcc 2.x's have symbols of their own, laid below.
            if (record.header != null) laySecondaryVtables(record, vftable, leaf, ns, SWEPT)
        }
        // gcc 2.x secondaries of classes without stabs, untagged: there is no class struct to find a vptr in.
        for (cls in gcc2SecondaryVtables.keys) {
            layGcc2SecondaryVtables(
                cls,
                canonTemplateName(cls.leafName),
                symtab.buildClassNamespaces(cls.nameSegments),
                null,
                SWEPT,
            )
        }
        layConstructionVtables()
        layVtts()
        layTypeinfoClassStubs()
        program.markVtablesSwept()
        return laid
    }

    /**
     * Replaces the empty structs Ghidra made for the `this` of the `__cxxabiv1` typeinfo classes' methods
     * with their layouts ([Rtti.typeInfoLayout]).
     */
    private fun layTypeinfoClassStubs() {
        val rtti = Rtti(dtm)
        val stubs = dtm.allStructures.asSequence()
            .filter { it.isZeroLength || it.numComponents == 0 }
            .mapNotNull { stub -> rtti.typeInfoLayout(stub.name)?.let { stub to it } }
            .toList()
        for ((stub, layout) in stubs) {
            dtm.replaceDataType(stub, registry.resolveLayout(layout), false)
            debug("vtable-typeinfo-stub-laid", stub.pathName)
        }
    }

    /** The class namespace the demangled `vtable` label at [addr] sits in, if any. */
    private fun labelledClass(addr: Address): Namespace? = symtab.getSymbols(addr)
        .firstOrNull { it.name == ClassNaming.VTABLE && it.parentNamespace is GhidraClass }?.parentNamespace

    /**
     * Lays every construction vtable group (`_ZTC`, ABI §2.6.4), the vtables a base's constructor uses inside
     * a class with virtual bases: `_ZTC7Diamond0_4Left` is Left's in a Diamond. It is laid like a swept
     * `_ZTV` group, its labels in a `Left-in-Diamond` namespace beside Diamond, which is no class.
     */
    private fun layConstructionVtables() {
        val groups = symtab.symbolIterator.filter { looksLikeZtc(it.name) }.distinctBy { it.address }
        for (sym in groups) {
            val ns = constructionNamespace(sym.name) ?: continue
            val name = ns.getName(true)
            val record = program.vtableRecord(sym.address).copy(construction = true)
            val targets = record.slots(program)
            val path = ClassNaming.vftablePath(ns)
            // A base with no virtuals of its own (`Left`) has a header and no slots: nothing to type.
            val vftable = targets.takeIf { it.isNotEmpty() }?.let {
                registry.getOrRegister<Structure>(path) {
                    StructureDataType(path.categoryPath, path.dataTypeName, 0, dtm)
                }.also { vftable ->
                    if (vftable.numComponents == 0) {
                        addSweptSlots(vftable, path.categoryPath, targets, Itanium)
                        vftable.describeVxTable(ns.name, ClassNaming.vftableLabel(false, construction = true), 0L)
                    }
                }
            }
            val at = record.lay(registry, program, vftable, ns, source = SWEPT)
            debug("vtable-construction", "$name: ${targets.size} slot(s)", at)
            laySecondaryVtables(record, vftable, ns.name, ns, SWEPT)
        }
    }

    /**
     * Lays every VTT (`_ZTT`, ABI §2.6.2) as pointers, each commented with the vtable it points into
     * ([VttReader]): `construction vtable for Left-in-Diamond`. One that doesn't match its typeinfo is left
     * alone, and so is a word already covered, which a stab-typed vftable running long can do.
     */
    private fun layVtts() {
        val symbols = symtab.symbolIterator.toList()
        val names = symbols.mapNotNull { sym -> typeinfoTypeOf(sym.name)?.let { sym.address to it } }.toMap()
        val dynamic = symbols.filter { Itanium.looksLikeVtable(it.name) || looksLikeZtc(it.name) }
            .mapNotNullTo(HashSet()) { program.vtableRecord(it.address).rttiOf(program) }
        val reader = VttReader(program, Rtti.Reader(program), names, dynamic)
        for (sym in symbols.filter { looksLikeZtt(it.name) }.distinctBy { it.address }) {
            val vtt = reader.vttAt(sym.address) ?: run {
                debug("vtt-unread", sym.name, sym.address)
                continue
            }
            for (word in vtt.words) {
                val laid = program.listing.getDefinedDataContaining(word.address)
                if (laid == null || (laid.isPointer && laid.address == word.address)) {
                    program.forceCreateData(word.address, PointerDataType(dtm))
                } else {
                    degradation("vtt-overlapped", sym.name, "${laid.dataType.name} at ${laid.address}", word.address)
                }
                program.listing.setComment(word.address, CommentType.EOL, word.comment)
            }
            debug("vtt-laid", "${sym.name}: ${vtt.words.size} word(s)", sym.address)
        }
    }

    /**
     * The `<Base>-in-<Derived>` namespace beside the derived class that [ztc]'s labels go in. Not the
     * demangler's, which splits `A::B-in-A::C` at every `::`.
     */
    private fun constructionNamespace(ztc: String): Namespace? {
        val text = Demangler.of(ztc)?.namespace?.namespaceString ?: return null
        val (base, derived) = text.split(CONSTRUCTION_INFIX, limit = 2).takeIf { it.size == 2 } ?: return null
        val cls = symtab.buildClassNamespaces(derived.nameSegments, SWEPT)
        val name = "${canonTemplateName(base.leafName)}$CONSTRUCTION_INFIX${cls.name}"
        return symtab.getNamespace(name, cls.parentNamespace)
            ?: symtab.createNameSpace(cls.parentNamespace, name, SWEPT)
    }

    /**
     * Lays the secondary vtables behind [primary], found off memory, as the stabs may declare fewer
     * virtuals than the table holds. Once there are several, each table, [primaryVftable] included, is
     * named after the base whose vptr points into it, as Ghidra's `RTTIGccClassRecoverer` does
     * ([ClassNaming.vftableName]); a construction group's labels stay as they are.
     */
    internal fun laySecondaryVtables(
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
            subs.map { with(abi) { it.record.vfptrOffset(program) } }
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
     * named as [laySecondaryVtables] names an Itanium group, and tagged with its base's vptr offset in
     * [classStruct] where there is one. Records already laid are skipped.
     */
    internal fun layGcc2SecondaryVtables(
        className: String,
        leaf: String,
        ns: Namespace,
        classStruct: Structure?,
        source: SourceType = SourceType.IMPORTED,
    ) {
        val records = unlaidGcc2Secondaries(className)
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

    /** [className]'s gcc 2.x secondaries no class laid, with their slots, less any without. */
    private fun unlaidGcc2Secondaries(className: String) =
        gcc2SecondaryVtables[className].orEmpty().mapNotNull { (base, record) ->
            if (program.isVtableClaimed(record)) return@mapNotNull null
            record.slots(program).ifEmpty {
                degradation("vtable-secondary-empty", className, "no slots read for base $base", record.address)
                null
            }?.let { (base to record) to it }
        }

    /** The bases of [primary]'s class by subobject offset, direct and virtual, as its typeinfo [rtti] says. */
    private fun baseSubobjects(primary: VtableRecord, rtti: Address): Map<Long, String> = Rtti.Reader(program).run {
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
        if (vftable.numComponents == 0) addSweptSlots(vftable, slotCategory, targets, abi)
        return vftable
    }

    /** Fills [vftable] off [targets]: [abi]'s reserved entry, then each slot with its adjustment. */
    private fun addSweptSlots(vftable: Structure, category: CategoryPath, targets: List<Address>, abi: CxxAbi) {
        val used = mutableSetOf<String>()
        with(abi) {
            vftable.addReservedHeader()
            targets.forEachIndexed { slot, target ->
                vftable.addEntryAdjustment(slot)
                addSweptSlot(vftable, category, target, used, abi)
            }
        }
    }

    /**
     * Adds a slot pointing at [target], always as a function definition pointer, even to
     * `__cxa_pure_virtual`. The field and the definition share a name, as Ghidra's class recovery expects,
     * so an overload gets a `_1` suffix; [used] holds the names this table spent.
     */
    internal fun addSweptSlot(
        vftable: Structure,
        category: CategoryPath,
        target: Address,
        used: MutableSet<String>,
        abi: CxxAbi,
    ) {
        val linkage = symtab.getSymbols(target).map { it.name }.firstOrNull(abi::isProbablyMangled)
            ?: symtab.getPrimarySymbol(target)?.name
            ?: "slot"
        val leaf = Demangler.of(linkage)?.name ?: linkage
        val name = generateSequence(0) { it + 1 }
            .map { if (it == 0) leaf else "${leaf}_$it" }
            .first(used::add)

        val funcDef = program.functionManager.getFunctionAt(target)
            ?.let { FunctionDefinitionDataType(category, name, it.signature, dtm) }
            ?: demangledDefinition(category, name, linkage)
        vftable.add(PointerDataType(registry.registerAgain(funcDef), dtm), name, "$target")
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
