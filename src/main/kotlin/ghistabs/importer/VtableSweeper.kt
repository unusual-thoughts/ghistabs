package ghistabs.importer

import ghidra.app.util.demangler.DemangledDataType
import ghidra.app.util.demangler.DemangledFunction
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.Program
import ghidra.program.model.scalar.Scalar
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.*
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.materialize.DtmRegistry
import ghistabs.materialize.cpp.ClassNaming
import ghistabs.materialize.cpp.abi.*
import ghistabs.materialize.cpp.describeVxTable
import ghistabs.materialize.cpp.isBaseField
import ghistabs.materialize.cpp.vfptrOffset
import ghistabs.materialize.cpp.vfptrOffsetOfBase
import ghistabs.parse.canonTemplateName
import ghistabs.parse.leafName
import ghistabs.parse.nameSegments

/** One gcc 2.x secondary vtable record: its symbol's [base] and ABI, and where it sits. */
internal data class Gcc2SecondaryVtable(val base: String, val address: Address, val abi: CxxAbi)

/**
 * Lays the vtables of classes nothing describes: every `_ZTV…` (and gcc 2.x `_vt…`) symbol whose record
 * no class has claimed ([isVtableClaimed]), typed off whatever sits at the addresses its slots hold.
 * Needs only the symbol table and memory: [ghistabs.entrypoints.GccVftableAnalyzer] runs the sweep,
 * on a binary with no stabs at all as much as after a stabs import. [ClassApplier] extends it only for
 * the table-laying helpers, which it uses on the classes the stabs describe, and never sweeps.
 */
open class VtableSweeper(
    internal open val registry: DtmRegistry,
    internal val program: Program,
    internal val monitor: TaskMonitor,
    private val sink: DiagnosticSink = DummySink,
) : DiagnosticSink by sink {
    internal val symtab = program.symbolTable
    internal val dtm = program.dataTypeManager

    companion object {
        /** What a swept table's labels carry, so a class laying it later claims it ([isVtableClaimed]). */
        private val SWEPT = SourceType.ANALYSIS

        /** How the demangler spells a construction vtable's owner: `Left-in-Diamond`. */
        private const val CONSTRUCTION_INFIX = "-in-"

        val VTABLES_SWEPT = BoolOption("Vtables Swept", "Unclaimed vtables already swept.", false)

        /** Whether a sweep already ran here: the stabs import's, or [ghistabs.entrypoints.GccVftableAnalyzer]'s. */
        val Program.isVtablesSwept get() = this[VTABLES_SWEPT]

        fun Program.markVtablesSwept() {
            this[VTABLES_SWEPT] = true
        }
    }

    /**
     * gcc 2.x secondary vtables (`_vt.<class>.<base>`) by the qualified class they belong to, one per
     * record in address order: a.out keeps both `_vt$` and its user-label-prefixed `__vt$` at one
     * address. Empty for any other ABI.
     */
    private val gcc2SecondaryVtables: Map<String, List<Gcc2SecondaryVtable>> by lazy {
        buildMap {
            for (sym in symtab.symbolIterator) {
                val (cls, base) = Gcc2.secondaryVtableClasses(sym.name) ?: continue
                val abi = CxxAbi.ofVtableSymbol(sym.name) ?: continue
                getOrPut(cls) { mutableListOf() } += Gcc2SecondaryVtable(base, sym.address, abi)
            }
        }.mapValues { (_, tables) -> tables.distinctBy { it.address }.sortedBy { it.address } }
    }

    /**
     * Lay every `_ZTV…` symbol no class claimed. `buildAndApplyVtable` runs per group, i.e.
     * only for a class we have a `T`-stab body for; libsupc++ and libstdc++ link without stabs, so
     * their polymorphic classes (`__cxxabiv1::__si_class_type_info`, `std::basic_filebuf<char,…>`)
     * own a real vtable that nothing ever visits — 53 of unbouniaf's 58 `_ZTV` symbols.
     *
     * Lossy by nature: with no method list the slots can only be named and typed from whatever sits
     * at the addresses they point to, and the array's length is inferred (see [vtableSlotTargets]).
     * The class struct is *not* synthesised — this is the vtable level only; §24 covers the same
     * classes at the typeinfo-record level.
     *
     * Returns the number of primary vtables laid, and marks the program [isVtablesSwept].
     */
    internal fun sweepUnclaimedVtables(): Int {
        val unclaimed = symtab.symbolIterator
            .mapNotNull { sym -> ResolvedVtable.fromSymbol(sym) }
            .distinctBy { it.address }
            .filterNot { (_, addr, abi) -> program.isVtableClaimed(program.vtableRecord(addr, abi)) }
            .toList()

        monitor.initialize(unclaimed.size.toLong(), "Sweeping unclaimed vtables")
        var laid = 0
        for ((qualified, addr, abi) in unclaimed) {
            monitor.increment()
            val record = program.vtableRecord(addr, abi)
            val targets = program.vtableSlotTargets(record.addressPoint, abi)
            if (targets.isEmpty()) {
                degradation("vtable-swept-empty", qualified, "no function pointers", record.addressPoint)
                continue
            }
            val leaf = canonTemplateName(qualified.leafName)
            val ns = symtab.buildClassNamespaces(qualified.nameSegments)
            val path = ClassNaming.vftablePath(ns, leaf)
            val vftable = registry.getOrRegister<Structure>(path) {
                StructureDataType(path.categoryPath, path.dataTypeName, 0, dtm)
            }
            // A class whose own group failed to resolve its vtable left its stab-typed slots here;
            // those beat anything read back off the target addresses.
            if (vftable.numComponents == 0) {
                addSweptSlots(vftable, path.categoryPath, targets, abi)
                // Itanium puts a primary vptr at 0. gcc 2.x puts it after the fields, and with no class
                // struct here to read that off, it gets no tag.
                vftable.describeVxTable(leaf, ClassNaming.VFTABLE, 0L.takeIf { abi.hasRttiHeader })
            }

            val addressPoint = program.layVtable(registry, record, vftable, qualified, ns, source = SWEPT)
            debug("vtable-reconstructed", "${targets.size} slot(s) typed from targets", addressPoint, qualified)
            laid++
            // Itanium packs a class's secondaries into the same record, walkable from the primary's
            // end by their shared rtti word. gcc 2.x gives each its own `_vt.<derived>.<base>` symbol,
            // laid below whether or not the class has a primary at all.
            if (abi.hasRttiHeader) laySecondaryVtables(record, vftable, leaf, ns, abi, SWEPT)
        }
        // What the class pass left: gcc 2.x secondaries of classes linked without stabs. No class struct
        // to find the base's vptr in, so these go untagged.
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
        program.markVtablesSwept()
        return laid
    }

    /**
     * Lay every construction vtable group (`_ZTC`, ABI §2.6.4): a base's vtables as its constructor runs
     * them inside a class with virtual bases, `_ZTC7Diamond0_4Left` being Left's while a Diamond is built.
     * Its records are a `_ZTV` group's (the rtti word names the base, `_ZTI4Left`), so they are laid as a
     * swept group, typed off their targets: the slots hold the base's functions and thunks into the
     * derived object. The labels go in a `Left-in-Diamond` namespace beside the derived class, an ordinary
     * namespace rather than a class, so the Class Hierarchy doesn't list it.
     */
    private fun layConstructionVtables() {
        val groups = symtab.symbolIterator.filter { looksLikeZtc(it.name) }.distinctBy { it.address }
        for (sym in groups) {
            val ns = constructionNamespace(sym.name) ?: continue
            val name = ns.getName(true)
            val record = program.vtableRecord(sym.address)
            val targets = program.vtableSlotTargets(record.addressPoint)
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
            val at = program.layVtable(registry, record, vftable, ns.name, ns, source = SWEPT, construction = true)
            debug("vtable-construction", "$name: ${targets.size} slot(s)", at)
            laySecondaryVtables(record, vftable, ns.name, ns, Itanium, SWEPT, construction = true)
        }
    }

    /**
     * Where [ztc]'s labels go: `<Base>-in-<Derived>`, one namespace beside the derived class, both leaves.
     * Not the demangler's own namespace chain: it splits `CryptoPP::GeneratableCryptoMaterial-in-CryptoPP::
     * DL_PrivateKey_GFP<…>` at every `::`, inventing a `GeneratableCryptoMaterial-in-CryptoPP` namespace.
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
     * Lay the sub-vtables that follow the primary record [primary] (§54). A secondary holds
     * `_ZTv0_n…`/`_ZThn…` thunks, which are their own symbols with their own names.
     *
     * Where the primary ends is read off memory, not off the vftable laid there — `CryptoPP::Base`
     * declares fewer virtuals than its table holds, which put the walk inside the function array.
     *
     * Named as `RTTIGccClassRecoverer` names a class's tables ([ClassNaming.vftableName]): once the group
     * has more than one, each one, [primaryVftable] included, is named after the direct base whose
     * subobject its `{vfptr}` sits at, read off the rtti. A [construction] group keeps its
     * `construction-vftable` labels, as Ghidra's do; only its structs are named that way.
     */
    internal fun laySecondaryVtables(
        primary: VtableRecord,
        primaryVftable: Structure?,
        leaf: String,
        ns: Namespace,
        abi: CxxAbi,
        source: SourceType = SourceType.IMPORTED,
        construction: Boolean = false,
    ) {
        val rtti = program.rttiOf(primary) ?: return
        val ptr = program.defaultPointerSize.toLong()
        val slots = program.vtableSlotTargets(primary.addressPoint).size
        // Only a record with slots is laid: an empty one has no function array to put a struct over.
        val subs = program.secondaryVtables(primary.addressPoint.add(slots * ptr), rtti)
            .filter { it.targets.isNotEmpty() }
        val offsets = listOfNotNull(primaryVftable?.let { 0L }) +
            subs.map { with(abi) { it.record.vfptrOffset(program) } }
        val bases = if (offsets.size < 2) emptyList() else baseNames(offsets, baseSubobjects(primary, rtti))
        val path = ClassNaming.vftablePath(ns, leaf)
        primaryVftable?.let {
            val label = ClassNaming.vftableLabel(internal = false, construction, bases.firstOrNull())
            nameTable(it, ClassNaming.vftableName(path, 0, offsets.size, bases.firstOrNull()), label, leaf, 0L)
            program.renameVtableLabel(primary.vptrTarget, ClassNaming.vftableLabel(false, construction), label, ns)
        }
        val first = offsets.size - subs.size
        subs.forEachIndexed { i, sub ->
            val index = first + i
            val base = bases.getOrNull(index)
            val at = path.categoryPath.at(ClassNaming.vftableName(path, index, offsets.size, base))
            val vftable = internalVftable(at, ClassNaming.internalSlotCategory(path, i), sub.targets, abi)
            val label = ClassNaming.vftableLabel(internal = true, construction, base)
            vftable.describeVxTable(leaf, label, offsets[index])
            val laidAt = program.layVtable(
                registry, sub.record, vftable, leaf, ns,
                internal = true, source = source, construction = construction, base = base,
            )
            debug("vtable-secondary", "class=$leaf index=$index base=$base slots=${sub.targets.size}", address = laidAt)
        }
    }

    /**
     * [className]'s gcc 2.x secondaries, which are not packed behind a primary: each is its own record
     * under its own symbol, `_vt<m><class><m><base>` — `_vt$9TeeStream$3ios`, the table TeeStream's
     * virtual `ios` base points at. A class whose polymorphic bases are all virtual has no primary at
     * all, only these. The label goes at the record start, which is what a gcc 2.x vptr holds: named
     * after the base, with the primary (if any) renamed after the base it shares its vptr with, as
     * [laySecondaryVtables] names an Itanium group.
     *
     * Tagged at that base's vptr in [classStruct], when there is one to look in: the vptr the table is
     * for belongs to the base, wherever the class lays it. A record a class already laid is skipped.
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
        // A class with no primary record can still have the struct its stab virtuals filled, which
        // stays `<leaf>_vftable`: the secondaries are named around it, never into it.
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
            val (base, record, abi) = key
            val index = first + i
            val name = names.getOrNull(index)
            val at = path.categoryPath.at(ClassNaming.vftableName(path, index, count, name))
            val vftable = internalVftable(at, ClassNaming.internalSlotCategory(path, i), targets, abi)
            val vfptrAt = classStruct?.vfptrOffsetOfBase(base)?.toLong()
            val label = ClassNaming.vftableLabel(internal = true, base = name)
            vftable.describeVxTable(leaf, label, vfptrAt)
            program.layVtable(
                registry,
                record,
                vftable,
                leaf,
                ns,
                internal = true,
                source = source,
                base = name,
            )
            debug(
                "vtable-secondary",
                "class=$className index=$index base=$base slots=${targets.size}",
                address = record.address,
            )
        }
    }

    /** [className]'s gcc 2.x secondaries no class laid yet, with their slots; one with none is skipped. */
    private fun unlaidGcc2Secondaries(className: String) =
        gcc2SecondaryVtables[className].orEmpty().mapNotNull { (base, at, abi) ->
            val record = program.vtableRecord(at, abi)
            if (program.isVtableClaimed(record)) return@mapNotNull null
            val targets = program.vtableSlotTargets(record.addressPoint, abi)
            if (targets.isEmpty()) {
                degradation("vtable-secondary-empty", className, "no slots read for base $base", at)
                return@mapNotNull null
            }
            Triple(base, record, abi) to targets
        }

    /** What [Rtti] says sits where in the class [primary] is the primary of: a direct base per subobject offset. */
    private fun baseSubobjects(primary: VtableRecord, rtti: Address): Map<Long, String> =
        Itanium.offsetToTopType(program.defaultPointerSize).let { word ->
            Rtti.Reader(program).basesOf(rtti).orEmpty().mapNotNull { base ->
                when {
                    // A virtual base's offset is where the vtable keeps its vbase offset, behind the address point.
                    base.isVirtual -> runCatching {
                        program.readAs<Scalar>(primary.addressPoint.add(base.offset), word)
                    }.getOrNull()?.signedValue

                    else -> base.offset
                }?.let { it to base.className }
            }.distinctBy { it.first }.toMap()
        }

    /**
     * The base each table at [offsets] serves, by [subobjects]' name for it shortened as Ghidra shortens
     * a template (`Base<int>` to `Base`), or whole where that would leave two alike; null when unknown.
     */
    private fun baseNames(offsets: List<Long?>, subobjects: Map<Long, String>): List<String?> {
        val whole = offsets.map { off -> off?.let(subobjects::get)?.let { canonTemplateName(it.leafName) } }
        val short = whole.map { it?.substringBefore('<') }
        return whole.indices.map { i ->
            short[i]?.takeIf { s -> short.count { it == s } == 1 }
                ?: whole[i]?.takeIf { w -> whole.count { it == w } == 1 }
        }
    }

    /**
     * Rename a class's primary table to [name] once it has company. An earlier import's table by that
     * name gives way to it, references and all, rather than forking a `.conflict`.
     */
    private fun nameTable(vftable: Structure, name: String, label: String, leaf: String, vfptrAt: Long?) {
        if (vftable.name != name) {
            dtm.getDataType(vftable.categoryPath, name)?.takeIf { it != vftable }
                ?.let { dtm.replaceDataType(it, vftable, false) }
            runCatching { vftable.name = name }
                .onFailure { degradation("vftable-rename-failed", leaf, "${vftable.name} -> $name: ${it.message}") }
        }
        vftable.describeVxTable(leaf, label, vfptrAt)
    }

    /** The direct base whose `{vfptr}` the class's own is, when it shares one. */
    private fun Structure.primaryBase(): String? {
        val vfptr = vfptrOffset() ?: return null
        return definedComponents.firstOrNull { c ->
            c.isBaseField() && (c.dataType as? Structure)?.vfptrOffset()?.let { c.offset + it } == vfptr
        }?.dataType?.name
    }

    /**
     * The secondary table at [at], typed off its [targets] like a swept table. The table sits beside the
     * primary, where shift-D finds the class it belongs to. Its slot definitions each get their own
     * [slotCategory], or a thunk sharing its target's leaf name forks a `.conflict` per slot (1874 on
     * crypto_mi).
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

    /** Fill [vftable] off [targets] alone: [abi]'s reserved header, then each slot with its adjustment. */
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
     * Add the swept slot pointing at [target]. Always `Pointer→FunctionDefinition`, never a bare
     * `void*`: an abstract class's slots point at `__cxa_pure_virtual`, a real function that honestly
     * has no signature to recover, and a `void*` there reads as a failure to type it.
     *
     * One name serves as both the field name and the definition's — `atLeastOneVtableStructApplied`
     * requires they agree (RecoveredClassHelper / shift-S round-trip) — so it has to be unique in the
     * category too: `std::num_get` has six `do_get` overloads and `std::ctype` two of each `do_is`/
     * `do_widen`/…, and one name across all of them forks a `.conflict` per slot (32 on unbouniaf).
     * [used] carries the names already spent on this table.
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

    /** FunctionDefinition [name] carrying what [linkage] declares — the only type source for a slot
     *  target that has a linkage name and nothing else. Names but does not type an unmangled one. */
    private fun demangledDefinition(category: CategoryPath, name: String, linkage: String) =
        FunctionDefinitionDataType(category, name, dtm).apply {
            fun DemangledDataType.dt() = runCatching { getDataType(dtm) }.getOrNull()
                ?: Undefined4DataType.dataType.also {
                    degradation("vftable-demangled-untyped", "$category/$name", "demangler gave no type for $this")
                }
            (Demangler.of(linkage) as? DemangledFunction)?.let { df ->
                df.returnType?.let { returnType = it.dt() }
                setArguments(
                    *df.parameters
                        .filterNot { it.type.isVoid && it.type.pointerLevels == 0 && !it.type.isReference }
                        .mapIndexed { i, p -> ParameterDefinitionImpl("arg$i", p.type.dt(), null) }
                        .toTypedArray(),
                )
            }
        }
}
