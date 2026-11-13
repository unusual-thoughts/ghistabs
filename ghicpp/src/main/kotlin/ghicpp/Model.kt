package ghicpp

import ghicpp.abi.StructorRole
import ghicpp.abi.VtableRecord
import ghidra.framework.options.CustomOption
import ghidra.framework.options.GProperties
import ghidra.program.model.address.Address
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.symbol.SourceType
import ghidra.util.ObjectStorage
import ghidra.util.Saveable
import ghidrakt.*
import kotlinx.serialization.Serializable

/** A C++ member's or base's access, as a stab's visibility marker or an RTTI base flag states it. */
enum class Access { PRIVATE, PROTECTED, PUBLIC }

/**
 * A class's direct base, from stabs, Itanium typeinfo, an MSVC Base Class Array or the class record.
 * [offset] is in bytes: a non-virtual base's place in the class, for a virtual one whatever its source
 * keeps instead (Itanium's vbase offset slot, MSVC's offset into the virtual base), or null if unknown.
 */
interface BaseDecl {
    val isVirtual: Boolean
    val access: Access
    val offset: Long?
}

/** A direct base of a class a recovery pass knows: the base's [cls], and how the class holds it. */
data class ClassBase(
    val cls: ClassDecl,
    override val isVirtual: Boolean,
    override val access: Access,
    override val offset: Long?,
    /** Where a virtual base's [offset] is from: IMPORTED its ABI record, ANALYSIS its vtables, DEFAULT nowhere. */
    val offsetSource: SourceType = SourceType.IMPORTED,
) : BaseDecl

/**
 * A class as a recovery pass knows it: its name, the namespace built for it if any, and its direct bases.
 * Equal by identity, so each source keeps one per class.
 */
interface ClassDecl {
    val name: String
    val ns: Namespace?

    /** Its direct bases, in declaration order. */
    val bases: List<ClassBase>

    /** Every class this one derives from, directly or not. */
    val ancestors: Set<ClassDecl> get() = buildSet {
        val todo = ArrayDeque(bases)
        while (todo.isNotEmpty()) {
            val base = todo.removeFirst().cls
            if (add(base)) todo += base.bases
        }
    }

    /** Its own vtables; empty when none was emitted, as for an abstract base. */
    val vftables: List<VtableRecord>

    /**
     * The virtual bases of its complete object, direct or not, each at its offset in it where the ABI's
     * records say: Itanium's vtable, MSVC's vbtable. Null where they don't.
     */
    val virtualBases: List<ClassBase> get() = emptyList()

    /**
     * Where its complete object's virtual bases start, as its records state them: [virtualBases]' offsets, and
     * those of virtual bases no record names, such as a plain Itanium vtable's vbase offsets.
     */
    val vbaseOffsets: Set<Long> get() = virtualBases.mapNotNullTo(mutableSetOf()) { it.offset }

    /** Where its vbptrs sit, MSVC's, which point at its vbtables; Itanium keeps vbase offsets in the vtable. */
    val vbptrs: Set<Long> get() = emptySet()

    /** Whether this class derives from [other], directly or not. */
    fun derivesFrom(other: ClassDecl) = other in ancestors
}

/** Method kind from the stabs method-block trailer: `.` normal, `?` static, `*` virtual. */
enum class VirtKind { NORMAL, STATIC, VIRTUAL }

/** What a class member's declaration states, which is all [ghicpp.abi.CxxMemberNaming] spells its symbol from. */
interface MemberDecl {
    val name: String

    /** The stated physname, if any; not always a whole symbol (see `Gcc2Plain.physnameCandidates`). */
    val mangled: String?
    val access: Access
    val virt: VirtKind
    val isConst: Boolean
    val isVolatile: Boolean
}

/**
 * Each class's struct and direct bases ([Entry]), keyed by the namespace id of its [GhidraClass] and
 * stored in program option [CLASSES]. Needed because the struct alone loses bases (empty and virtual
 * ones take no bytes in it, and its description names bases only by leaf), and goes by id because
 * typedef shortening or per-CU categories can move a struct away from its class's name.
 */
@Serializable
data class ClassHierarchyRecords(var classes: Map<Long, Entry> = emptyMap()) : CustomOption {
    /** A direct base: its class's [namespaceId], or only [name] if none was built, and its [offset] if known. */
    @Serializable
    data class Base(
        val namespaceId: Long?,
        val name: String?,
        override val isVirtual: Boolean,
        override val access: Access,
        override val offset: Long? = null,
    ) : BaseDecl

    /** A class's struct by datatype id, and its direct bases in order. */
    @Serializable
    data class Entry(val structId: Long?, val bases: List<Base>)

    override fun readState(properties: GProperties) {
        classes = GPropertiesFormat.decode<ClassHierarchyRecords>(properties).classes
    }

    override fun writeState(properties: GProperties) = GPropertiesFormat.encode(this, properties)

    companion object {
        /** The program options category, so the record doesn't crowd Program Information. */
        const val CATEGORY = "Stabs"
        const val CLASSES = "Classes"

        /** Replaces every class's entry with [record]'s, by namespace id. */
        fun Program.writeClassRecord(record: Map<Long, Entry>) =
            getOptions(CATEGORY).setCustomOption(CLASSES, ClassHierarchyRecords(record))

        /** Null when no stabs import wrote a record. */
        fun Program.readClassRecord(): Map<Long, Entry>? =
            (getOptions(CATEGORY).getCustomOption(CLASSES, null) as? ClassHierarchyRecords)?.classes

        /**
         * [cls]'s entry, by its namespace's id, with its struct's [structId]; null if it has no namespace. A
         * base with no namespace goes by name.
         */
        fun entryOf(cls: ClassDecl, structId: Long?): Pair<Long, Entry>? {
            val ns = cls.ns?.toClass() ?: return null
            val bases = cls.bases.map { b ->
                val baseNs = b.cls.ns?.toClass()
                Base(baseNs?.id, if (baseNs == null) b.cls.name else null, b.isVirtual, b.access, b.offset)
            }
            return ns.id to Entry(structId, bases)
        }

        fun Program.areClassesRecorded() = getOptions(CATEGORY).contains(CLASSES)

        /** Bases set by hand in the Class Hierarchy window, kept apart so a re-import doesn't drop them. */
        const val EDITS = "Edited classes"

        /** Each class whose bases were set by hand, by namespace id; empty when none was. */
        fun Program.readClassEdits(): Map<Long, Entry> =
            (getOptions(CATEGORY).getCustomOption(EDITS, null) as? ClassHierarchyRecords)?.classes.orEmpty()

        /** Sets class [id]'s bases by hand, over what the record or its typeinfo says. */
        fun Program.writeClassEdit(id: Long, entry: Entry) =
            getOptions(CATEGORY).setCustomOption(EDITS, ClassHierarchyRecords(readClassEdits() + (id to entry)))
    }
}

/**
 * A member function's or static data member's access, virtuality and cv-qualifiers, who stated them
 * ([source]: [SourceType.IMPORTED] the stabs, [SourceType.ANALYSIS] a class pass, [SourceType.USER_DEFINED] the
 * user), and the constructor or destructor it is where a class pass found it one ([structor]). Stabs give
 * all of the first; otherwise cv comes from the mangled name, virtuality from the vtables, and access stays null.
 */
@Serializable
data class MemberAttrs(
    var access: Access? = null,
    var virt: VirtKind? = null,
    var isConst: Boolean = false,
    var isVolatile: Boolean = false,
    var source: SourceType? = null,
    var structor: StructorRole? = null,
) : Saveable {
    constructor(method: MemberDecl) :
        this(method.access, method.virt, method.isConst, method.isVolatile, SourceType.IMPORTED)

    override fun getObjectStorageFields(): Array<Class<*>> = arrayOf(INT, INT, BOOLEAN, BOOLEAN, STRING, INT)

    override fun save(objStorage: ObjectStorage) {
        objStorage.putInt(access?.ordinal ?: -1)
        objStorage.putInt(virt?.ordinal ?: -1)
        objStorage.putBoolean(isConst)
        objStorage.putBoolean(isVolatile)
        objStorage.putString(source?.name.orEmpty())
        objStorage.putInt(structor?.ordinal ?: -1)
    }

    override fun restore(objStorage: ObjectStorage) {
        access = Access.entries.getOrNull(objStorage.int)
        virt = VirtKind.entries.getOrNull(objStorage.int)
        isConst = objStorage.boolean
        isVolatile = objStorage.boolean
        source = objStorage.string.let { name -> SourceType.entries.firstOrNull { it.name == name } }
        structor = StructorRole.entries.getOrNull(objStorage.int)
    }

    override fun getSchemaVersion() = 2
    override fun isUpgradeable(oldSchemaVersion: Int) = oldSchemaVersion == 1

    /**
     * Version 1 had no [source] nor [structor]. The stabs give a member its access, so one with an access came
     * from them; one without may have been a class pass's virtual function, whose class pass tags a rerun of
     * the pass turns into these.
     */
    override fun upgrade(
        oldObjStorage: ObjectStorage,
        oldSchemaVersion: Int,
        currentObjStorage: ObjectStorage,
    ): Boolean {
        if (oldSchemaVersion != 1) return false
        val access = oldObjStorage.int
        currentObjStorage.putInt(access)
        currentObjStorage.putInt(oldObjStorage.int)
        currentObjStorage.putBoolean(oldObjStorage.boolean)
        currentObjStorage.putBoolean(oldObjStorage.boolean)
        currentObjStorage.putString(if (access >= 0) SourceType.IMPORTED.name else "")
        currentObjStorage.putInt(-1)
        return true
    }

    override fun isPrivate() = false
    companion object {
        const val MEMBERS = "Stabs Member Attributes"

        /** Stores [attrs] on the code unit at [at]; dropped if no code unit starts there. */
        fun Program.writeMember(at: Address, attrs: MemberAttrs) =
            listing.getCodeUnitAt(at)?.setProperty(MEMBERS, attrs)

        /** The attributes stated for the member at an address, if any: by the stabs, a class pass or the user. */
        fun Program.memberAttrs(at: Address): MemberAttrs? =
            listing.getCodeUnitAt(at)?.getObjectProperty(MEMBERS) as? MemberAttrs

        /**
         * Records that a class pass moved [func] into its class, a [structor] where it found it one, and [virtual]
         * where a vtable holds it, unless the stabs or the user stated its attributes already.
         */
        fun Program.recordPlaced(func: Function, structor: StructorRole?, virtual: Boolean) {
            val old = memberAttrs(func.entryPoint)
            if (old?.source == SourceType.IMPORTED || old?.source == SourceType.USER_DEFINED) return
            val virt = VirtKind.VIRTUAL.takeIf { virtual } ?: old?.virt
            writeMember(
                func.entryPoint,
                MemberAttrs(virt = virt, source = SourceType.ANALYSIS, structor = structor ?: old?.structor),
            )
        }

        /** Whether a class pass moved [func] into its class ([recordPlaced]). */
        fun Program.isPlacedByClassPass(func: Function) = memberAttrs(func.entryPoint)?.source == SourceType.ANALYSIS
    }
}

private val INT = Int::class.javaObjectType
private val BOOLEAN = Boolean::class.javaObjectType
private val STRING = String::class.java

/**
 * The class a virtual function belongs to: the lowest common ancestor of the classes whose vftables
 * hold it ([holders]). That class may have no vftable, as an abstract base's is often not emitted; one
 * that has one and doesn't hold it means the linker folded separate overrides into one body
 * (`/OPT:ICF`). Null for those, and where no class is common.
 */
fun introducingClass(holders: Set<ClassDecl>): ClassDecl? {
    val common = holders.map { it.ancestors + it }.reduce { a, b -> a intersect b }
    return common.singleOrNull { c -> common.none { it != c && it.derivesFrom(c) } }
        ?.takeIf { it in holders || it.vftables.isEmpty() }
}

/**
 * The classes an ABI's own records describe, as its [ghicpp.abi.RttiParser] read them for the class
 * pass: [classes], every one seen; those whose bases it knows, to record ([recorded]); and each function a
 * vftable slot holds, with the classes whose tables hold it ([holders]).
 */
class ClassPassInput(
    val classes: Collection<ClassDecl>,
    val recorded: Collection<ClassDecl>,
    val holders: Map<Function, Set<ClassDecl>>,
)

/**
 * The base of this class whose subobject [record]'s vptr sits in: the first direct non-virtual base at its
 * offset, else the virtual base there.
 */
fun ClassDecl.servedBase(record: VtableRecord, program: Program): ClassDecl? {
    val at = record.vfptrOffset(program) ?: return null
    return bases.firstOrNull { !it.isVirtual && (it.offset ?: 0L) == at }?.cls
        ?: virtualBases.firstOrNull { it.offset == at }?.cls
}

/** A class's name with its enclosing namespaces: its namespace's where it has one. */
val ClassDecl.qualifiedName: String get() = ns?.takeUnless { it.isGlobal }?.getName(true) ?: name
