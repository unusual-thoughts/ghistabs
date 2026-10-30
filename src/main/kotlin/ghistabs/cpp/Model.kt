package ghistabs.cpp

import ghidra.framework.options.CustomOption
import ghidra.framework.options.GProperties
import ghidra.program.model.address.Address
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.util.ObjectStorage
import ghidra.util.Saveable
import ghistabs.GPropertiesFormat
import ghistabs.cpp.abi.VtableRecord
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

/**
 * A class as a recovery pass knows it: its name, the namespace built for it if any, and every class it
 * derives from. Equal by identity, so each source keeps one per class.
 */
interface ClassDecl {
    val name: String
    val ns: Namespace?

    /** Every class this one derives from, directly or not. */
    val ancestors: Set<ClassDecl>

    /** Its own vtables; empty when none was emitted, as for an abstract base. */
    val vftables: List<VtableRecord>

    /** Whether this class derives from [other], directly or not. */
    fun derivesFrom(other: ClassDecl) = other in ancestors
}

/** Method kind from the stabs method-block trailer: `.` normal, `?` static, `*` virtual. */
enum class VirtKind { NORMAL, STATIC, VIRTUAL }

/** What a class member's declaration states, which is all [ghistabs.cpp.abi.CxxMemberNaming] spells its symbol from. */
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

    /** A class's struct by datatype id, its direct bases in order, and [size]: exact if [exactSize], else a minimum. */
    @Serializable
    data class Entry(
        val structId: Long?,
        val bases: List<Base>,
        val size: Long? = null,
        val exactSize: Boolean = false,
    )

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

        fun Program.areClassesRecorded() = getOptions(CATEGORY).contains(CLASSES)
    }
}

/**
 * A member function's or static data member's access, virtuality and cv-qualifiers. Stabs give all of
 * them; otherwise cv comes from the mangled name, virtuality from the vtables, and access stays null.
 */
@Serializable
data class MemberAttrs(
    var access: Access? = null,
    var virt: VirtKind? = null,
    var isConst: Boolean = false,
    var isVolatile: Boolean = false,
) : Saveable {
    constructor(method: MemberDecl) :
        this(method.access, method.virt, method.isConst, method.isVolatile)

    override fun getObjectStorageFields(): Array<Class<*>> = arrayOf(INT, INT, BOOLEAN, BOOLEAN)

    override fun save(objStorage: ObjectStorage) {
        objStorage.putInt(access?.ordinal ?: -1)
        objStorage.putInt(virt?.ordinal ?: -1)
        objStorage.putBoolean(isConst)
        objStorage.putBoolean(isVolatile)
    }

    override fun restore(objStorage: ObjectStorage) {
        access = Access.entries.getOrNull(objStorage.int)
        virt = VirtKind.entries.getOrNull(objStorage.int)
        isConst = objStorage.boolean
        isVolatile = objStorage.boolean
    }

    override fun getSchemaVersion() = 1
    override fun isUpgradeable(oldSchemaVersion: Int) = false
    override fun upgrade(oldObjStorage: ObjectStorage, oldSchemaVersion: Int, currentObjStorage: ObjectStorage) = false
    override fun isPrivate() = false
    companion object {
        const val MEMBERS = "Stabs Member Attributes"

        /** Stores [attrs] on the code unit at [at]; dropped if no code unit starts there. */
        fun Program.writeMember(at: Address, attrs: MemberAttrs) =
            listing.getCodeUnitAt(at)?.setProperty(MEMBERS, attrs)

        /** The attributes the stabs gave the member at an address, if any. */
        fun Program.memberAttrs(at: Address): MemberAttrs? =
            listing.getCodeUnitAt(at)?.getObjectProperty(MEMBERS) as? MemberAttrs
    }
}

private val INT = Int::class.javaObjectType
private val BOOLEAN = Boolean::class.javaObjectType
