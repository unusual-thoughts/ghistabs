package ghicpp.recover

import ghicpp.*
import ghicpp.abi.*
import ghicpp.abi.VftableBuilder
import ghicpp.abi.itanium.*
import ghidra.program.model.address.Address
import ghidra.program.model.data.*
import ghidra.program.model.listing.CommentType
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghistabs.*
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink

/**
 * Lays the vtables no class claimed ([isVtableClaimed]), Itanium's and gcc 2.x's, typed off the functions
 * their slots point at, through a [VftableBuilder]. Needs only symbols and memory, so
 * [ghicpp.entrypoints.VtableSweepAnalyzer] sweeps with or without stabs.
 */
class VtableSweepPass(
    private val registry: DtmRegistry,
    private val program: Program,
    sink: DiagnosticSink = DummySink,
) : DiagnosticSink by sink {
    private val builder = VftableBuilder(registry, program, sink)
    private val symtab = program.symbolTable
    private val dtm = program.dataTypeManager

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
     * Lays every vtable no class claimed, mostly those of libraries linked without stabs, then the gcc 2.x
     * secondaries, construction vtables and VTTs. The slots are named and typed after their targets alone,
     * and no class struct is made. Returns how many primary vtables it laid, and marks the program swept.
     */
    fun run(monitor: TaskMonitor): Int {
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
                builder.addSlots(vftable, path.categoryPath, targets, record.abi)
                vftable.describeVxTable(leaf, ClassNaming.VFTABLE, record.abi.primaryVptrOffset)
            }

            val addressPoint = record.lay(registry, program, vftable, ns, source = SWEPT)
            debug("vtable-reconstructed", "${targets.size} slot(s) typed from targets", addressPoint, qualified)
            laid++
            // Itanium's secondaries follow the primary; gcc 2.x's have symbols of their own, laid below.
            if (record.header != null) builder.laySecondaries(record, vftable, leaf, ns, SWEPT)
        }
        // gcc 2.x secondaries of classes without stabs, untagged: there is no class struct to find a vptr in.
        for (cls in builder.gcc2SecondaryVtables.keys) {
            builder.layGcc2Secondaries(
                cls,
                canonTemplateName(cls.leafName),
                symtab.buildClassNamespaces(cls.nameSegments),
                null,
                SWEPT,
            )
        }
        layConstructionVtables()
        layVtts()
        program.markVtablesSwept()
        return laid
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
            val record = Itanium.recordAt(program, sym.address).copy(construction = true)
            val targets = record.slots(program)
            val path = ClassNaming.vftablePath(ns)
            // A base with no virtuals of its own (`Left`) has a header and no slots: nothing to type.
            val vftable = targets.takeIf { it.isNotEmpty() }?.let {
                registry.getOrRegister<Structure>(path) {
                    StructureDataType(path.categoryPath, path.dataTypeName, 0, dtm)
                }.also { vftable ->
                    if (vftable.numComponents == 0) {
                        builder.addSlots(vftable, path.categoryPath, targets, Itanium)
                        vftable.describeVxTable(ns.name, ClassNaming.vftableLabel(false, construction = true), 0L)
                    }
                }
            }
            val at = record.lay(registry, program, vftable, ns, source = SWEPT)
            debug("vtable-construction", "$name: ${targets.size} slot(s)", at)
            builder.laySecondaries(record, vftable, ns.name, ns, SWEPT)
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
            .mapNotNullTo(HashSet()) { Itanium.recordAt(program, it.address).rttiOf(program) }
        val reader = VttReader(program, TypeinfoReader(program), names, dynamic)
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
}
