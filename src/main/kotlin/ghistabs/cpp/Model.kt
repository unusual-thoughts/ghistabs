package ghistabs.cpp

import ghidra.framework.options.CustomOption
import ghidra.framework.options.GProperties
import ghidra.program.model.address.Address
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.util.ObjectStorage
import ghidra.util.Saveable
import ghistabs.GPropertiesFormat
import kotlinx.serialization.Serializable

/** A C++ member's or base's access, as a stab's visibility marker or an RTTI base flag states it. */
enum class Access { PRIVATE, PROTECTED, PUBLIC }

/**
 * A class's direct base as any source states it: the stabs ([ghistabs.parse.TypeDecl.Aggregate.Base]),
 * Itanium typeinfo ([ghistabs.cpp.abi.itanium.Rtti.Reader.Base]), an MSVC Base Class Array
 * ([ghistabs.cpp.abi.msvc.BaseEntry]) or the class record ([ClassHierarchyRecords.Base]). How it is inherited,
 * and [offset], in bytes: where a non-virtual base sits in the class, and for a virtual one whatever its
 * source keeps there instead (Itanium's vbase offset slot, MSVC's offset into the virtual base), or
 * null when it says nothing.
 */
interface BaseDecl {
    val isVirtual: Boolean
    val access: Access
    val offset: Long?
}

/** Method kind from the stabs method-block trailer: `.` normal, `?` static, `*` virtual. */
enum class VirtKind { NORMAL, STATIC, VIRTUAL }

/** What a class member's declaration states, which is all [ghistabs.cpp.abi.CxxMemberNaming] spells its symbol from. */
interface MemberDecl {
    val name: String

    /** The physname the declaration states, if any.
     *  Not always a whole symbol ([ghistabs.cpp.abi.Gcc2Plain.physnameCandidates]). */
    val mangled: String?
    val access: Access
    val virt: VirtKind
    val isConst: Boolean
    val isVolatile: Boolean
}

/**
 * A map of each class's struct and direct bases ([Entry]) stored to program option [CLASSES], by
 * the namespace id of the [GhidraClass] the class pass built for it. A class struct holds only the base
 * subobjects it could lay (an empty base takes no bytes, a virtual one sits wherever the most-derived
 * class puts it), and its description names each base by its leaf, which five `…::Base` classes on
 * crypto_mi share. The struct goes by id: typedef shortening may rename it, and a class the CUs define
 * differently is filed under a CU's category (`/dll.cpp/multi/ECP`), so neither is found by the
 * class's name and scope. A base is named by namespace id too: the very class built for it, whatever
 * its name spells. Laid out in its [GProperties] by [GPropertiesFormat].
 */
@Serializable
data class ClassHierarchyRecords(var classes: Map<Long, Entry> = emptyMap()) : CustomOption {
    /**
     * A direct base: the class built for it ([namespaceId]), or only its [name] when none was, and
     * where it sits in the class ([offset], in bytes), when it is not virtual and its source says.
     */
    @Serializable
    data class Base(
        val namespaceId: Long?,
        val name: String?,
        override val isVirtual: Boolean,
        override val access: Access,
        override val offset: Long? = null,
    ) : BaseDecl

    /**
     * A class's struct, by datatype id, its direct bases in declaration order, and its [size] where
     * something says: the class's `sizeof` if [exactSize], else as large as it is sure to be.
     */
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

        /** Null when no stabs import recorded them: a program imported before the record existed, or with none. */
        fun Program.readClassRecord(): Map<Long, Entry>? =
            (getOptions(CATEGORY).getCustomOption(CLASSES, null) as? ClassHierarchyRecords)?.classes

        fun Program.areClassesRecorded() = getOptions(CATEGORY).contains(CLASSES)
    }
}

/**
 * A member function's or static data member's access, virtuality and cv-qualifiers. The stabs state them
 * all; for a member they don't describe, the hierarchy derives what it can (cv off the mangled name,
 * virtual off the vtables) and leaves the rest null: no mangling or typeinfo records a member's access.
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

        /** On the code unit at [at], which creates [MEMBERS] the first time. None there (mid-instruction): not kept. */
        fun Program.writeMember(at: Address, attrs: MemberAttrs) =
            listing.getCodeUnitAt(at)?.setProperty(MEMBERS, attrs)

        /** The attributes the stabs gave the member at an address, if any. */
        fun Program.memberAttrs(at: Address): MemberAttrs? =
            listing.getCodeUnitAt(at)?.getObjectProperty(MEMBERS) as? MemberAttrs
    }
}

private val INT = Int::class.javaObjectType
private val BOOLEAN = Boolean::class.javaObjectType
