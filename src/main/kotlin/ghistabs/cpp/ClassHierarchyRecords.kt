package ghistabs.cpp

import ghidra.framework.options.CustomOption
import ghidra.framework.options.GProperties
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghistabs.GPropertiesFormat
import kotlinx.serialization.Serializable

// What the stabs say of classes and their members that nothing else in the program keeps, recorded for
// the Class Hierarchy window ([ghistabs.browse.ClassHierarchy]), which runs long after the stabs are
// gone from memory.

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
    /** A direct base: the class built for it ([namespaceId]), or only its [name] when none was. */
    @Serializable
    data class Base(val namespaceId: Long?, val name: String?, val isVirtual: Boolean, val access: Access)

    /** A class's struct, by datatype id, and its direct bases in declaration order. */
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

        /** Null when no stabs import recorded them: a program imported before the record existed, or with none. */
        fun Program.readClassRecord(): Map<Long, Entry>? =
            (getOptions(CATEGORY).getCustomOption(CLASSES, null) as? ClassHierarchyRecords)?.classes

        fun Program.areClassesRecorded() = getOptions(CATEGORY).contains(CLASSES)
    }
}
