package ghistabs.materialize

import ghidra.program.database.data.DataTypeUtilities
import ghidra.program.model.data.Composite
import ghidra.program.model.data.DataType
import ghidra.program.model.data.DataTypeManager
import ghidra.program.model.data.Undefined
import ghistabs.diagnose.GapRecord
import ghistabs.diagnose.degradation
import ghistabs.harvest.TypeAst
import ghistabs.parse.TypeDecl
import ghistabs.parse.ownsMaterializedType

/**
 * Compromised DataTypes — anonymous (no name in stab), empty-placeholder (body never
 * materialized), or all-Undefined (body ran but bound nothing). Backs [TypeRegistry.degradedBy];
 * classifies [TypeRegistry.byId] / [TypeRegistry.xrefStubs] entries against the harvest.
 */
internal fun TypeRegistry.computeDegraded(): Map<DataType, String> = buildMap {
    fun classify(ast: TypeAst, dt: DataType) {
        if (containsKey(dt)) return
        // Unresolved XRef placeholders are flagged unconditionally — their dt is an
        // empty Composite we created for the stub, not aliased from elsewhere.
        if (xrefStubs.contains(dt)) {
            put(dt, "xref-stub")
            return
        }
        // Wrapper / alias bodies point their byId at the wrapped target's dt (an anonymous
        // `InlineDef(id, Pointer(X))` aliases `X *32`; a resolved XRef aliases the canonical
        // struct). Classifying them would misattribute named targets as anonymous — skip.
        if (!ast.body.ownsMaterializedType) return
        when {
            ast.name == null -> "anonymous"
            dt is Composite && dt.numComponents == 0 -> "empty-placeholder"
            dt is Composite && dt.allComponentsUndefined() -> "all-undefined"
            else -> null
        }?.let { reason -> put(dt, reason) }
    }
    // Canonical-group winners: the ast that actually built the dt. Non-winner
    // member ids alias to the same dt — don't let an anonymous member misclassify
    // a named winner's dt.
    for (group in resolver.byCanonicalKey.values) {
        dataTypeFor(group.ast.id)?.let { classify(group.ast, it) }
    }
    // Non-canonical top-level asts (XRef aliases, FunctionT, Method, …) that
    // materialized through resolve(); their own ast.id owns the dt directly.
    val canonicalIds = resolver.byCanonicalKey.values.flatMap { it.members }.toSet()
    for (ast in harvest.typeAsts.values) {
        if (ast.id in canonicalIds) continue
        dataTypeFor(ast.id)?.let { classify(ast, it) }
    }
}

/** Reason the DataType is compromised (anonymous / empty / all-Undefined / xref-stub), or null. */
fun TypeRegistry.reasonFor(dt: DataType?): String? = dt?.let { degradedBy[it] }

/** Snapshot of compromised DataTypes by reason — for the registry dump. */
fun TypeRegistry.compromisedTypes(): Map<String, List<DataType>> = degradedBy.entries.groupBy({ it.value }, { it.key })

internal fun TypeRegistry.recordXRefStubAt(useSite: String, at: String, dt: DataType) {
    if (dt in xrefStubs) {
        degradation("xref-stub-in-$useSite", at, "type=${dt.name}")
    }
}

/**
 * Log every Struct/Union typeAst whose body never made it into the DTM as a non-empty aggregate.
 * These cause downstream `merge-failed` "Offset 0 beyond end of structure" cascades.
 */
fun TypeRegistry.reportSurvivingPlaceholders() {
    for ((id, placeholder) in placeholders) {
        val ast = harvest.getType(id) ?: continue
        if (ast.body !is TypeDecl.Struct) continue
        val composite = placeholder as? Composite ?: continue
        // Empty C++ trait/tag types: sizeBytes=1, no source members. Ghidra fills
        // with Undefined1; that's correct, not a degradation.
        val sourceHasNoMembers =
            ast.body.fields.none { !it.isStatic } && ast.body.bases.isEmpty()
        val tag = when {
            composite.numComponents == 0 && !sourceHasNoMembers -> "placeholder-unresolved"
            composite.allComponentsUndefined() && !sourceHasNoMembers -> "placeholder-undefined-fields"
            else -> continue
        }
        degradation(
            tag,
            "${composite.categoryPath}/${composite.name}",
            when (tag) {
                "placeholder-unresolved" -> "never had its body materialized (id=$id)"
                else -> "materialized but every field fell back to Undefined (id=$id)"
            },
        )
    }
}

/** DTM-wide `.conflict` census (name-suffixed forks: `.conflict`, `.conflict1`, …). */
internal fun DataTypeManager.conflictCount(): Long =
    allDataTypes.asSequence().count { DataTypeUtilities.isConflictDataType(it) }.toLong()

/**
 * A `.conflict` fork means a type was applied whose layout didn't compare equal to an existing
 * type of the same name — usually re-resolving an unresolved template (RttiStructs per-CU-COMDAT
 * typeinfo was the offender) rather than a genuine ODR clash. Report how many the import added
 * over the construction-time baseline; a nonzero delta is a WARN.
 */
fun TypeRegistry.reportConflictDelta() {
    val after = dtm.conflictCount()
    debug("dtm-conflicts-pre", count = conflictsBefore)
    debug("dtm-conflicts-post", count = after)
    val added = after - conflictsBefore
    if (added > 0) warn("dtm-conflicts-created", "import forked $added .conflict data types", count = added)
}

// Ghidra's gap-fill byte is DataType.DEFAULT (DefaultDataType), which does NOT implement Undefined,
// so a bare `is Undefined` silently misses it. Undefined.isUndefined covers DefaultDataType, the
// UndefinedN family, and undefined arrays — everything the old `.name.startsWith("undefined")` caught.
val DataType.isUndefined get() = Undefined.isUndefined(this)

/** Every component is in the `UndefinedN` family — distinguishes "body ran but bound nothing" from "body never ran". */
private fun Composite.allComponentsUndefined(): Boolean = numComponents != 0 &&
    components.all { it.dataType.isUndefined }

/**
 * Report runs of unnamed Undefined1 ≥ [minRunBytes] in a struct's component list.
 * Surfaces "couldn't render base subobject" / "undescribed padding" patterns. Each
 * triple is `(fieldName, (offsetBytes, lengthBytes), typeName)`.
 */
fun Composite.detectUndefinedRuns(minRunBytes: Int = 4): List<GapRecord> = buildList {
    var runStartIdx = -1
    var runStart = -1
    var runEnd = -1

    fun flushRun(prevName: String?, nextName: String?) {
        if (runStartIdx < 0) return
        val runBytes = runEnd - runStart
        if (runBytes >= minRunBytes) {
            add(
                GapRecord(
                    offsetBits = (runStart * 8).toLong(),
                    lengthBits = (runBytes * 8).toLong(),
                    prevField = prevName,
                    nextField = nextName,
                ),
            )
        }
        runStartIdx = -1
    }

    val records = components.sortedBy { it.offset }
    for ((i, comp) in records.withIndex()) {
        val isUnnamed = comp.fieldName.isNullOrEmpty()
        val isUndef = comp.dataType.isUndefined
        if (isUnnamed && isUndef) {
            if (runStartIdx < 0) {
                runStartIdx = i
                runStart = comp.offset
            }
            runEnd = comp.offset + comp.length
        } else {
            val prevName = if (runStartIdx > 0) records[runStartIdx - 1].fieldName else null
            flushRun(prevName, name)
        }
    }
    val prevName = if (runStartIdx > 0) records[runStartIdx - 1].fieldName else null
    flushRun(prevName, null)
}
