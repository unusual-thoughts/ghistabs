package ghistabs.materialize

import ghidra.program.model.data.*
import ghistabs.diagnose.Level
import ghistabs.diagnose.degradation
import ghistabs.harvest.Type
import ghistabs.parse.AggrKind
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

/**
 * Empty, mutable stub for [ast]: an EnumDataType (correctly sized), or an empty Structure/Union that
 * [materializeAll] fills in place. Authoritative substitutions (primitives, RTTI pseudo-types) are
 * *not* placeholders — see [DataTypeRegistry.substitute]; callers resolve those first.
 */
internal fun DataTypeRegistry.makePlaceholder(
    ast: Type,
    category: CategoryPath,
    reason: String? = null,
    // The canonical slot name — defaults to the stabs identity, but a scope-attributed group passes
    // its key name (the demangler's leaf) so the type materializes at the demangler's spelling
    // (`/std/string`, not `/std/basic_string<…>`), the slot Ghidra's this-param creator then reuses.
    name: String = ast.ghidraName,
): DataType {
    val dt = when (ast.body) {
        is TypeDecl.Struct if (ast.body.rawKind == AggrKind.UNION) -> UnionDataType(category, name, dtm)

        is TypeDecl.Struct -> {
            val sz = ast.body.usefulStructSize()
            recordTruncation(ast, ast.body.sizeBytes, sz)
            StructureDataType(category, name, sz.toInt(), dtm)
        }

        // Enum placeholder MUST be an EnumDataType, correctly sized: materializeEnum fills this
        // same registered object in place (like structs), so a wrong kind/size would leave a
        // colliding `.conflict` second type. Size per gdb's stabsread.c::read_enum_type —
        // sizeof(int) unless gcc emits an explicit `@s<bits>` (`-fshort-enums`).
        is TypeDecl.Enum -> EnumDataType(category, name, 4, dtm)

        is TypeDecl.WithSizeAttr if ast.body.inner is TypeDecl.Enum ->
            EnumDataType(category, name, ast.body.sizeBytes.toInt(), dtm)

        // An unresolved enum XRef (gcc only forward-referenced it, e.g. `vm_image_type`) must
        // stub as an Enum, not a Structure: a struct stub is a Composite, so StructReturnAnalyzer
        // (§13) would force an enum-returning method through the hidden-pointer ABI
        // (`vm_image_type *__return_storage_ptr__`) and render its values as pointer compares.
        is TypeDecl.XRef if ast.body.kind == AggrKind.ENUM -> EnumDataType(category, name, 4, dtm)

        else -> StructureDataType(category, name, 0, dtm)
    }
    log(
        "placeholder-created",
        "name=$name category=$category reason=${reason ?: "fwd-decl"}",
        if (reason == null) Level.DEBUG else Level.WARN,
    )
    return dt
}

/**
 * Last-described-byte size for a Struct, since stab `sizeBytes` often overshoots
 * (bouniaf s328 but own fields end at 192; bouniaf s416 vs 276 — trailing
 * bytes are gcc's allocation for a subobject only forward-declared in this CU).
 * Trusting sizeBytes silently overwrites a derived class's own fields when the
 * canonical-but-oversized winner is selected. Trim only when the gap > maxFieldSize
 * (upper bound on legitimate tail padding without knowing the struct's alignment).
 */
private fun TypeDecl.Struct<GlobalTypeId>.usefulStructSize(): Long {
    val nonStatic = fields.filter { !it.isStatic }
    if (nonStatic.isEmpty()) return sizeBytes
    val fieldEnd = nonStatic.maxOf { ((it.offsetBits + it.sizeBits + 7) / 8) }
    val maxFieldSize = nonStatic.maxOf { ((it.sizeBits + 7) / 8) }
    return if (sizeBytes - fieldEnd > maxFieldSize) fieldEnd else sizeBytes
}

private fun DataTypeRegistry.recordTruncation(ast: Type, originalBytes: Long, truncatedBytes: Long) {
    if (originalBytes <= truncatedBytes) return
    degradation(
        "struct-truncated",
        ast.ghidraName,
        "stab claims $originalBytes bytes, last described byte $truncatedBytes; trimmed ${originalBytes - truncatedBytes}",
    )
}
