package ghistabs.materialize

import ghidra.program.model.address.Address
import ghidra.program.model.listing.Program
import ghidra.util.ObjectStorage
import ghidra.util.Saveable
import ghistabs.cpp.Access
import ghistabs.parse.TypeDecl
import ghistabs.parse.VirtKind
import kotlinx.serialization.Serializable

// What the stabs say of members that nothing else in the program keeps, recorded for the Class
// Hierarchy window, which runs long after the stabs are gone from memory.

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
