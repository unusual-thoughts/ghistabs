package ghicpp.score

import ghicpp.hierarchy.ClassHierarchy
import kotlinx.serialization.Serializable

/**
 * What a class recovery left in a program, as the scorecard compares it: the Class Hierarchy window's
 * [hierarchy], serialized, plus the two things that view only points at, each class's struct's
 * [fields] and the extent of each vtable a class's members label ([vtables]).
 */
@Serializable
data class Snapshot(
    val fixture: String,
    val hierarchy: ClassHierarchy,
    /** Each class's struct's leaf fields, by class id: offset to size, base classes and nested structs flattened. */
    val fields: Map<Long, Map<Long, Int>> = emptyMap(),
    val vtables: List<VtableExtent> = emptyList(),
)

/** A vtable label of class [classId] at [start], up to the next symbol ([end], exclusive): offsets in the program. */
@Serializable
data class VtableExtent(val start: Long, val end: Long, val classId: Long)
