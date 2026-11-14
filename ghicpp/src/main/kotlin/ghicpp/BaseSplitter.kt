package ghicpp

import ghidra.program.model.data.*
import ghidra.program.model.gclass.ClassUtils
import ghidrakt.*
import ghidrakt.diagnose.DiagnosticSink

/**
 * Splits a polymorphic base subobject around the vptr a deriving class takes over, whatever laid the
 * class: the stabs import's vfptr placement, or a class pass off the RTTI and the constructors.
 */
class BaseSplitter(private val registry: DtmRegistry, sink: DiagnosticSink) : DiagnosticSink by sink {
    private val dtm = registry.dtm

    /** {vfptr} points at the function-pointer array at the vtable's address point, not at the record. */
    private fun ownVfptr(classPath: List<String>) = PointerDataType.getPointer(registry.vftableOf(classPath), dtm)

    /**
     * Give this class its own `{vfptr}` where a polymorphic base subobject would otherwise own it:
     * the pointer goes at the vptr offset and the base is re-embedded as its *fields*, the same
     * bytes minus the vptr it no longer holds ([VfptrModel.SPLIT_BASE]).
     *
     * What matters is the pointer's static type. A shared `{vfptr}` is typed with whichever class
     * declares it, so every derived slot indexes past the end of that class's vftable and the
     * decompiler falls back to `vfptr[4].~TiXmlBase`. The `_base_` component survives, so the
     * subobject still models the inheritance.
     *
     * False when the base cannot be split, leaving the caller to report the inherited case. [vfptr] is the
     * pointer put in, to the class's own vftable unless a secondary's.
     */
    fun splitBase(
        structDt: Structure,
        classPath: List<String>,
        vptrOffset: Int,
        baseComp: DataTypeComponent?,
        vfptr: DataType = ownVfptr(classPath),
    ): Boolean {
        val className = classPath.last()
        val baseDt = baseComp?.dataType as? Structure ?: return false
        val ptr = dtm.dataOrganization.pointerSize
        // Where the vptr sits *within* the base, read off the base itself rather than assumed: the
        // Itanium ABI puts it at 0, gcc 2.x appends it after the class's own fields. Classes are
        // built bases-first, so a polymorphic base already carries its own placed {vfptr}. A base
        // that carries none — reached through the base-field branch of chooseVfptrAction, where
        // polymorphism was never proven — falls back to where this class says its vptr is.
        val vptrInBase = baseDt.definedComponents.firstOrNull { it.fieldName == ClassUtils.VFPTR }?.offset
            ?: (vptrOffset - baseComp.offset)
        val split = splitAround(baseDt.length, vptrInBase, ptr) ?: return false
        val baseOff = baseComp.offset
        val tailFrom = vptrInBase + ptr

        // The base's own fields first, so the runs below hold them by reference rather than a copy.
        val layouts = layoutsOf(baseDt)
        listOfNotNull(split.head, split.tail)
            .mapNotNull { ownSpan(baseDt, it) }
            .forEachIndexed { i, own ->
                val name = ClassNaming.FIELDS + "_tail".takeIf { i > 0 }.orEmpty()
                val run = own.baseFieldsRun(baseDt) ?: return@forEachIndexed
                // A runtime's layout stays as the archive has it: its deriving classes hold a copy.
                layouts.filterNot { it.isKnownLayout() }.forEach { embed(it, own, run, name) }
            }

        val head = split.head?.baseFieldsRun(baseDt)
        val tail = split.tail?.baseFieldsRun(baseDt)
        return (head != null || tail != null) && runCatching {
            head?.let { structDt.replaceAtOffset(baseOff, it, it.length, baseComp.fieldName, baseComp.comment) }
            structDt.replaceAtOffset(baseOff + vptrInBase, vfptr, vfptr.length, ClassUtils.VFPTR, "vtable pointer")
            tail?.let {
                val name = if (head == null) baseComp.fieldName else "${baseComp.fieldName}_tail"
                structDt.replaceAtOffset(baseOff + tailFrom, it, it.length, name, baseComp.comment)
            }
        }.onFailure {
            degradation("vfptr-split-failed", className, "${baseDt.name} at +$baseOff: ${it.message}")
        }.isSuccess
    }

    /**
     * [base] and, when it is a self-base ([ClassUtils.getBaseClassDataTypePath], `<Class>/!internal/<Class>`),
     * the class it copies: every struct that holds its fields.
     */
    private fun layoutsOf(base: Structure): List<Structure> = listOfNotNull(
        base,
        base.categoryPath.parent?.parent
            ?.let { dtm.getDataType(it, base.name) as? Structure }
            ?.takeIf { ClassUtils.getBaseClassDataTypePath(it) == base.dataTypePath },
    )

    /**
     * The span of [run] holding [baseDt]'s own data members: everything in it but `{vfptr}` and the
     * base subobjects, which stay where the class's inheritance is read off. The whole run when it
     * holds no base subobject, so the base and its deriving classes hold one struct. Null when there
     * are no own members, or when a base subobject sits between two of them and no one struct can
     * hold them alone.
     */
    private fun ownSpan(baseDt: Structure, run: IntRange): IntRange? {
        val inRun = baseDt.definedComponents.filter(run::holds)
        val own = inRun.filterNot { it.isBaseField() || it.fieldName == ClassUtils.VFPTR }.ifEmpty { return null }
        if (inRun.none { it.isBaseField() }) return run
        val span = own.minOf { it.offset }..<own.maxOf { it.offset + it.length }
        return span.takeUnless { inRun.any { it.isBaseField() && span.overlaps(it) } }
    }

    /**
     * Put [run] in [layout] over [span], in place of the fields it copies: the base then reads its own
     * fields through the struct every deriving class embeds, so an edit to one is an edit to all of
     * them and they cannot drift. A span whose edge falls inside a component of [layout] is left alone,
     * since embedding over it would drop that component, and so is a packed [layout], which clearing
     * a component shrinks (Ghidra's own `ClassTypeInfoStructure`).
     */
    private fun embed(layout: Structure, span: IntRange, run: Structure, name: String) {
        if (layout.isPackingEnabled) return
        if (layout.getComponentAt(span.first)?.dataType?.dataTypePath == run.dataTypePath) return
        val (inside, crossing) = layout.definedComponents.filter(span::overlaps).partition(span::holds)
        if (crossing.isNotEmpty()) {
            degradation(
                "fields-run-unshared",
                layout.name,
                "${run.name}: ${crossing.first().fieldName} crosses its edge",
            )
            return
        }
        runCatching {
            inside.forEach { layout.clearAtOffset(it.offset) }
            layout.replaceAtOffset(span.first, run, run.length, name, "own fields, shared with deriving classes")
        }.onFailure { degradation("fields-run-unshared", layout.name, "${run.name}: ${it.message}") }
    }

    /**
     * One contiguous run of [baseDt]'s bytes, in this range, as a struct: the base subobject's
     * fields with the vptr word taken out. Null when empty. Shared by every class deriving from
     * that base, so one extra type per polymorphic class rather than one per inheritance edge. A run
     * that is exactly the base's own fields is also the struct the base holds them in ([embed]).
     *
     * The bounds are in the name: the registry caches on (category, name) alone, so two runs of one
     * base differing only in extent would collide.
     */
    private fun IntRange.baseFieldsRun(baseDt: Structure): Structure? {
        if (isEmpty()) return null
        val name = "${baseDt.name}${ClassNaming.FIELDS}_${first}_${last + 1}"
        return registry.getOrRegister<Structure>(baseDt.categoryPath.at(name)) {
            StructureDataType(baseDt.categoryPath, name, length, dtm).apply {
                description = "${baseDt.name} as a base subobject (+$first..${last + 1}): its fields " +
                    "without the vptr the deriving class now owns"
                for (it in baseDt.definedComponents.filter(::holds)) {
                    runCatching {
                        replaceAtOffset(it.offset - first, it.dataType, it.length, it.fieldName, it.comment)
                    }
                }
            }
        }
    }
}

/**
 * `<Class>_vftable` under `/ClassDataTypes/<ns>/<Class>/`, the function-pointer array `{vfptr}` points
 * at, where `RecoveredClassHelper` and shift-S round-trip expect it. [classPath] is the class's
 * namespace path, the class itself last. Empty until the class pass fills it.
 */
fun DtmRegistry.vftableOf(classPath: List<String>) = ClassNaming.vftablePath(classPath).let { dtPath ->
    getOrRegister<Structure>(dtPath) {
        StructureDataType(dtPath.categoryPath, dtPath.dataTypeName, 0, dtm)
    }
}

/** What a vptr leaves of a base subobject: the fields before it and the fields after it. */
data class BaseSplit(val head: IntRange?, val tail: IntRange?)

/**
 * The runs a vptr at [vptrInBase] leaves of a [baseLength]-byte base. Null when the pointer does not
 * fit inside the base, or when it covers the base whole and there is nothing left to embed.
 *
 * One run is empty whenever the vptr is at the start (Itanium) or the end (gcc 2.x at depth 1),
 * which keeps the subobject a single `_base_` component. Deeper in a gcc 2.x chain both are real:
 * `TiXmlElement` inherits `location`/`userData` before the vptr and `value` after.
 */
fun splitAround(baseLength: Int, vptrInBase: Int, ptrSize: Int): BaseSplit? {
    if (vptrInBase < 0 || vptrInBase + ptrSize > baseLength) return null
    val head = (0..<vptrInBase).takeUnless { it.isEmpty() }
    val tail = (vptrInBase + ptrSize..<baseLength).takeUnless { it.isEmpty() }
    return if (head == null && tail == null) null else BaseSplit(head, tail)
}

/**
 * Where a polymorphic class's `{vfptr}` comes from, which decides whether a virtual call resolves to
 * a named slot or overruns into `vfptr[N]`. Whatever laid the class: the stabs import, or a class pass
 * off the RTTI ([ghicpp.recover.ClassStructFiller]).
 *
 * The vptr sits inside a base subobject, so a derived class can only carry a pointer to
 * its **own** vftable if something gives way, and the static type of that field is what the
 * decompiler indexes. With one shared field typed `<Root>_vftable *`, every derived slot lands past
 * the end of the root's table: `xmltest_gcc421` renders 31 of its 40 virtual calls as
 * `vfptr[4].~TiXmlBase` and never mentions a derived vftable type at all.
 *
 * A third shape exists: Ghidra's own `RecoveredClassHelper` expands the base subobject away
 * entirely and puts `vftablePtr` at offset 0, trading the `_base_` component for the pointer.
 */
enum class VfptrModel {
    /** One `{vfptr}` on the root of each hierarchy, inherited through `_base_`. Derived slots overrun. */
    INHERITED,

    /**
     * Each polymorphic class owns a `{vfptr}` typed to its own vftable, and embeds the base holding the
     * vptr as that base's fields *without* it — one extra struct per polymorphic base, shared by every
     * class that derives from it. Keeps the `_base_` subobject component that [ClassNaming.baseFieldName]
     * models inheritance with.
     */
    SPLIT_BASE,

    ;

    companion object {
        /** The option choosing the model, under one name and default for the stabs import and each class pass. */
        val OPTION = EnumOption(
            "Virtual function pointer model",
            "Where a polymorphic class's {vfptr} comes from. INHERITED keeps one on the root of each " +
                "hierarchy, shared through the base subobject — derived slots then sit past the end of " +
                "the root's vftable and virtual calls render as vfptr[N].field. SPLIT_BASE gives every " +
                "polymorphic class its own {vfptr} typed to its own vftable, embedding the base that holds " +
                "the vptr as that base's fields without it, so virtual calls resolve to named slots.",
            SPLIT_BASE,
        )
    }
}
