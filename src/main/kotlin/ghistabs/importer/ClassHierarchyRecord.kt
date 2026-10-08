package ghistabs.importer

import ghidra.program.model.address.Address
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.Namespace
import ghidra.program.model.util.ObjectPropertyMap
import ghidra.util.ObjectStorage
import ghidra.util.Saveable
import ghistabs.parse.Access
import ghistabs.parse.TypeDecl
import ghistabs.parse.VirtKind
import kotlinx.serialization.Serializable

/**
 * What the stabs say of classes and their members that nothing else in the program keeps, recorded for
 * the Class Hierarchy window ([ghistabs.hierarchy.ClassHierarchy]), which runs long after the stabs are
 * gone from memory. Two user property maps, so Ghidra stores, versions and undoes them:
 *
 * - [MEMBERS]: each member function's and static data member's [MemberAttrs], at its address.
 * - [CLASSES]: each class's struct and direct bases ([Entry]). A class struct holds only the base
 *   subobjects it could lay (an empty base takes no bytes, a virtual one sits wherever the most-derived
 *   class puts it), and its description names each base by its leaf, which five `…::Base` classes on
 *   crypto_mi share. The struct goes by id: typedef shortening may rename it, and a class the CUs define
 *   differently is filed under a CU's category (`/dll.cpp/multi/ECP`), so neither is found by the
 *   class's name and scope. A namespace has no address, so [ClassRecords] sit at the addresses of the
 *   classes' symbols, each at one
 *   no other class took, and name their classes by namespace id: a base is the very [GhidraClass] the
 *   class pass built for it, whatever its name spells. A class with no symbol at an address (one with
 *   no methods, every member inlined, say) still matters as a base, so it joins another's entry.
 */
object ClassHierarchyRecord {
    const val CLASSES = "Stabs Classes"
    const val MEMBERS = "Stabs Member Attributes"

    /** A direct base: the class built for it ([namespaceId]), or only its [name] when none was. */
    data class Base(val namespaceId: Long?, val name: String?, val isVirtual: Boolean, val access: Access)

    /** A class's struct, by datatype id, and its direct bases in declaration order. */
    data class Entry(val structId: Long?, val bases: List<Base>)

    /**
     * Replaces every class's entry with [record]'s, by namespace id: each class at a free address of its
     * own, the classes with none in one entry alongside another's.
     */
    fun write(program: Program, record: Map<Long, Entry>) {
        val maps = program.usrPropertyManager
        maps.removePropertyMap(CLASSES)
        val map = maps.createObjectPropertyMap(CLASSES, ClassRecords::class.java)
        val symtab = program.symbolTable
        val entries = LinkedHashMap<Address, MutableMap<Long, Entry>>()
        val homeless = mutableMapOf<Long, Entry>()
        for ((id, entry) in record) {
            val ns = symtab.getSymbol(id)?.`object` as? Namespace
            val at = ns?.let { symtab.getSymbols(it) }?.iterator()?.asSequence()?.map { it.address }
                ?.firstOrNull { it.isMemoryAddress && it !in entries }
            (at?.let { entries.getOrPut(it, ::mutableMapOf) } ?: homeless)[id] = entry
        }
        if (homeless.isNotEmpty()) {
            val at = entries.keys.firstOrNull() ?: program.minAddress ?: return
            entries.getOrPut(at, ::mutableMapOf) += homeless
        }
        entries.forEach { (at, classes) -> map.add(at, ClassRecords(classes)) }
    }

    /** Null when no stabs import recorded them: a program imported before the record existed, or with none. */
    fun read(program: Program): Map<Long, Entry>? {
        val map = program.objectMap<ClassRecords>(CLASSES) ?: return null
        return map.propertyIterator.iterator().asSequence().flatMap { map.get(it).classes.entries }
            .associate { it.toPair() }
    }

    fun isRecorded(program: Program) = program.objectMap<ClassRecords>(CLASSES) != null

    /** On the code unit at [at], which creates [MEMBERS] the first time. None there (mid-instruction): not kept. */
    fun writeMember(program: Program, at: Address, attrs: MemberAttrs) {
        program.listing.getCodeUnitAt(at)?.setProperty(MEMBERS, attrs)
    }

    /** The attributes the stabs gave the member at an address, if any. */
    fun memberAttrs(program: Program): (Address) -> MemberAttrs? =
        { at -> program.listing.getCodeUnitAt(at)?.getObjectProperty(MEMBERS) as? MemberAttrs }

    @Suppress("UNCHECKED_CAST")
    private inline fun <reified T : Saveable> Program.objectMap(name: String): ObjectPropertyMap<T>? =
        usrPropertyManager.getObjectPropertyMap(name)?.takeIf { it.valueClass == T::class.java }
            as ObjectPropertyMap<T>?
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
 * Some classes' [ClassHierarchyRecord.Entry]s, as parallel arrays: the classes' namespace ids, their
 * struct ids (`-1` for none) and how many bases each has, then over all bases in turn the namespace id each names
 * (`-1` for a base no class was built for, a forward declaration), else its name, and its flags: the
 * [Access] ordinal, plus [VIRTUAL] for a virtual base.
 */
class ClassRecords() : Saveable {
    /** By namespace id. */
    var classes: Map<Long, ClassHierarchyRecord.Entry> = emptyMap()
        private set

    constructor(classes: Map<Long, ClassHierarchyRecord.Entry>) : this() {
        this.classes = classes
    }

    override fun getObjectStorageFields(): Array<Class<*>> = arrayOf(LONGS, LONGS, INTS, LONGS, STRINGS, INTS)

    override fun save(objStorage: ObjectStorage) {
        val bases = classes.values.flatMap { it.bases }
        objStorage.putLongs(classes.keys.toLongArray())
        objStorage.putLongs(classes.values.map { it.structId ?: -1 }.toLongArray())
        objStorage.putInts(classes.values.map { it.bases.size }.toIntArray())
        objStorage.putLongs(bases.map { it.namespaceId ?: -1 }.toLongArray())
        objStorage.putStrings(bases.map { it.name.orEmpty() }.toTypedArray())
        objStorage.putInts(bases.map { it.access.ordinal or (if (it.isVirtual) VIRTUAL else 0) }.toIntArray())
    }

    override fun restore(objStorage: ObjectStorage) {
        val classIds = objStorage.longs ?: LongArray(0)
        val structIds = objStorage.longs ?: LongArray(0)
        val counts = objStorage.ints ?: IntArray(0)
        val ids = objStorage.longs ?: LongArray(0)
        val names = objStorage.strings ?: emptyArray()
        val flags = objStorage.ints ?: IntArray(0)
        val bases = ids.indices.map { i ->
            ClassHierarchyRecord.Base(
                ids[i].takeIf { it >= 0 },
                names.getOrNull(i)?.takeIf { ids[i] < 0 },
                flags.getOrElse(i) { 0 } and VIRTUAL != 0,
                Access.entries.getOrNull(flags.getOrElse(i) { 0 } and ACCESS) ?: Access.PUBLIC,
            )
        }
        var next = 0
        classes = classIds.indices.associate { i ->
            val count = counts.getOrElse(i) { 0 }
            val own = bases.subList(next.coerceAtMost(bases.size), (next + count).coerceAtMost(bases.size))
            next += count
            classIds[i] to ClassHierarchyRecord.Entry(structIds.getOrNull(i)?.takeIf { it >= 0 }, own)
        }
    }

    override fun getSchemaVersion() = 1
    override fun isUpgradeable(oldSchemaVersion: Int) = false
    override fun upgrade(oldObjStorage: ObjectStorage, oldSchemaVersion: Int, currentObjStorage: ObjectStorage) = false
    override fun isPrivate() = false

    private companion object {
        const val ACCESS = 3
        const val VIRTUAL = 4
    }
}

private val INT = Int::class.javaObjectType
private val BOOLEAN = Boolean::class.javaObjectType
private val LONGS = LongArray::class.java
private val STRINGS = Array<String>::class.java
private val INTS = IntArray::class.java
