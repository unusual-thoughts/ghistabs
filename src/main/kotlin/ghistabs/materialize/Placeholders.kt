package ghistabs.materialize

import ghidra.program.model.data.*
import ghistabs.harvest.Type
import ghistabs.parse.AggrKind
import ghistabs.parse.TypeDecl

/**
 * Empty, mutable stub for [ast]: an EnumDataType (correctly sized), or an empty Structure/Union that
 * [materializeAll] fills in place. Authoritative substitutions (primitives, RTTI pseudo-types) are
 * *not* placeholders — see [DataTypeRegistry.substitute]; callers resolve those first.
 */
internal fun DataTypeRegistry.makePlaceholder(
    ast: Type,
    category: CategoryPath,
    reason: String,
    // The canonical slot name — defaults to the stabs identity, but a scope-attributed group passes
    // its key name (the demangler's leaf) so the type materializes at the demangler's spelling
    // (`/std/string`, not `/std/basic_string<…>`), the slot Ghidra's this-param creator then reuses.
    name: String = ast.ghidraName,
): DataType = when (ast.body) {
    is TypeDecl.Aggregate if (ast.body.kind == AggrKind.UNION) -> UnionDataType(category, name, dtm)

    // gcc's `s<size>` is the class's sizeof in this CU, tail padding and virtual bases
    // included, so it is the length; whatever it covers that the fields do not, the class
    // layout fills (bases, virtual bases, vptr) or the struct keeps as padding.
    is TypeDecl.Aggregate -> StructureDataType(category, name, ast.body.sizeBytes.toInt(), dtm)

    // Enum placeholder MUST be an EnumDataType, correctly sized: materializeEnum fills this
    // same registered object in place (like structs), so a wrong kind/size would leave a
    // colliding `.conflict` second type. Size per gdb's stabsread.c::read_enum_type —
    // sizeof(int) unless gcc emits an explicit `@s<bits>` (`-fshort-enums`).
    is TypeDecl.Enum -> EnumDataType(category, name, (ast.body.sizeBits / 8).toInt(), dtm)

    // An unresolved enum XRef (gcc only forward-referenced it, e.g. `vm_image_type`) must
    // stub as an Enum, not a Structure: a struct stub is a Composite, so StructReturnAnalyzer
    // (§13) would force an enum-returning method through the hidden-pointer ABI
    // (`vm_image_type *__return_storage_ptr__`) and render its values as pointer compares.
    is TypeDecl.XRef if ast.body.kind == AggrKind.ENUM -> EnumDataType(category, name, 4, dtm)

    else -> StructureDataType(category, name, 0, dtm)
}.also {
    debug("placeholder-created", "name=$name category=$category reason=$reason")
}
