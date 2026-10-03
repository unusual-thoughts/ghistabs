package ghistabs.importer

import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghistabs.parse.Access

/**
 * The direct bases the stabs give each class, kept in the program for the Class Hierarchy window
 * ([ghistabs.hierarchy.ClassHierarchy]), which runs long after the stabs are gone from memory.
 *
 * Nothing else in the program carries them whole: a class struct holds only the base subobjects it
 * could lay (an empty base takes no bytes, a virtual one sits wherever the most-derived class puts
 * it), and its description names each base by its leaf, which five `…::Base` classes on crypto_mi share.
 *
 * Keyed by namespace id, so a base is the very [GhidraClass] the class pass built for it, whatever its
 * name spells. One line per class: its id, then a tab-separated entry per base in declaration order,
 * `[v]<access><id>`, or `[v]<access>=<name>` for a base no class was built for (a forward declaration).
 * Access is `+` public, `#` protected, `-` private.
 *
 * Beside it, [STRUCTS] holds each class's struct by datatype id, `<namespace id>\t<datatype id>` a line:
 * the typedef shortening pass renames a struct (`map<int, Foo*>`) away from its class's namespace name.
 */
object ClassHierarchyRecord {
    /** A program options category of its own, so the record doesn't crowd Program Information. */
    const val CATEGORY = "Stabs Class Hierarchy"
    private const val BASES = "Bases"

    /** A direct base: the class built for it ([namespaceId]), or only its [name] when none was. */
    data class Base(val namespaceId: Long?, val name: String?, val isVirtual: Boolean, val access: Access)

    private val accessMarks = mapOf(Access.PUBLIC to '+', Access.PROTECTED to '#', Access.PRIVATE to '-')

    fun encode(record: Map<Long, List<Base>>): String = record.entries.joinToString("\n") { (id, bases) ->
        (listOf(id.toString()) + bases.map { it.encode() }).joinToString("\t")
    }

    private fun Base.encode() = buildString {
        if (isVirtual) append('v')
        append(accessMarks.getValue(access))
        if (namespaceId != null) append(namespaceId) else append('=').append(name.orEmpty())
    }

    /** Lines that don't parse are skipped: a record from a later format reads as far as it can. */
    fun decode(text: String): Map<Long, List<Base>> = buildMap {
        for (line in text.lineSequence().filter { it.isNotBlank() }) {
            val fields = line.split('\t')
            val id = fields.first().toLongOrNull() ?: continue
            put(id, fields.drop(1).mapNotNull(::decodeBase))
        }
    }

    private fun decodeBase(field: String): Base? {
        val isVirtual = field.startsWith('v')
        val rest = if (isVirtual) field.substring(1) else field
        val access = accessMarks.entries.firstOrNull { it.value == rest.firstOrNull() }?.key ?: return null
        val target = rest.substring(1)
        return when {
            target.startsWith('=') -> Base(null, target.substring(1), isVirtual, access)
            else -> Base(target.toLongOrNull() ?: return null, null, isVirtual, access)
        }
    }

    fun write(program: Program, record: Map<Long, List<Base>>) =
        program.getOptions(CATEGORY).run {
            setString(BASES, encode(record))
        }

    /** Null when no stabs import recorded one: a program imported before the record existed, or with none. */
    fun read(program: Program): Map<Long, List<Base>>? =
        program.getOptions(CATEGORY).getString(BASES, null)?.let(::decode)
}
