package ghistabs.importer

import ghidra.framework.options.CustomOption
import ghidra.framework.options.GProperties
import ghidra.program.model.address.Address
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.util.ObjectStorage
import ghidra.util.Saveable
import ghistabs.GPropertiesFormat
import ghistabs.parse.Access
import ghistabs.parse.TypeDecl
import ghistabs.parse.VirtKind
import kotlinx.serialization.Serializable

/**
 * What the stabs say of classes and their members that nothing else in the program keeps, recorded for
 * the Class Hierarchy window ([ghistabs.browse.ClassHierarchy]), which runs long after the stabs are
 * gone from memory. Ghidra stores, versions and undoes both:
 *
 * - [MEMBERS]: a user property map of each member function's and static data member's [MemberAttrs], at
 *   its address.
 * - [CLASSES]: a program option ([ClassRecords]) of each class's struct and direct bases ([Entry]), by
 *   the namespace id of the [GhidraClass] the class pass built for it. A class struct holds only the base
 *   subobjects it could lay (an empty base takes no bytes, a virtual one sits wherever the most-derived
 *   class puts it), and its description names each base by its leaf, which five `…::Base` classes on
 *   crypto_mi share. The struct goes by id: typedef shortening may rename it, and a class the CUs define
 *   differently is filed under a CU's category (`/dll.cpp/multi/ECP`), so neither is found by the
 *   class's name and scope. A base is named by namespace id too: the very class built for it, whatever
 *   its name spells.
 */
object ClassHierarchyRecord {
    /** The program options category, so the record doesn't crowd Program Information. */
    const val CATEGORY = "Stabs"
    const val CLASSES = "Classes"
    const val MEMBERS = "Stabs Member Attributes"

    /** A direct base: the class built for it ([namespaceId]), or only its [name] when none was. */
    @Serializable
    data class Base(val namespaceId: Long?, val name: String?, val isVirtual: Boolean, val access: Access)

    /** A class's struct, by datatype id, and its direct bases in declaration order. */
    @Serializable
    data class Entry(val structId: Long?, val bases: List<Base>)

    /** Replaces every class's entry with [record]'s, by namespace id. */
    fun write(program: Program, record: Map<Long, Entry>) =
        program.getOptions(CATEGORY).setCustomOption(CLASSES, ClassRecords(record))

    /** Null when no stabs import recorded them: a program imported before the record existed, or with none. */
    fun read(program: Program): Map<Long, Entry>? =
        (program.getOptions(CATEGORY).getCustomOption(CLASSES, null) as? ClassRecords)?.classes

    fun isRecorded(program: Program) = program.getOptions(CATEGORY).contains(CLASSES)

    /** On the code unit at [at], which creates [MEMBERS] the first time. None there (mid-instruction): not kept. */
    fun writeMember(program: Program, at: Address, attrs: MemberAttrs) {
        program.listing.getCodeUnitAt(at)?.setProperty(MEMBERS, attrs)
    }

    /** The attributes the stabs gave the member at an address, if any. */
    fun memberAttrs(program: Program): (Address) -> MemberAttrs? =
        { at -> program.listing.getCodeUnitAt(at)?.getObjectProperty(MEMBERS) as? MemberAttrs }
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
    constructor(method: TypeDecl.Aggregate.Method<*>) :
        this(method.access, method.virt, method.isConst, method.isVolatile)

    constructor(field: TypeDecl.Aggregate.Field<*>) :
        this(field.access, if (field.isStatic) VirtKind.STATIC else VirtKind.NORMAL)

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
}

/**
 * Every class's [ClassHierarchyRecord.Entry], by namespace id, as one custom program option. Laid out in
 * its [GProperties] by [GPropertiesFormat].
 */
@Serializable
class ClassRecords(var classes: Map<Long, ClassHierarchyRecord.Entry> = emptyMap()) : CustomOption {
    override fun readState(properties: GProperties) {
        classes = GPropertiesFormat.decode<ClassRecords>(properties).classes
    }

    override fun writeState(properties: GProperties) = GPropertiesFormat.encode(this, properties)

    override fun equals(other: Any?) = other is ClassRecords && other.classes == classes
    override fun hashCode() = classes.hashCode()
    override fun toString() = "${classes.size} classes"
}

private val INT = Int::class.javaObjectType
private val BOOLEAN = Boolean::class.javaObjectType
