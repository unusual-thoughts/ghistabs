package ghistabs.materialize.cpp

import ghidra.program.model.data.AbstractIntegerDataType
import ghidra.program.model.data.CategoryPath
import ghidra.program.model.data.DataType
import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.Undefined4DataType
import ghidra.program.model.lang.CompilerSpec
import ghistabs.materialize.DataTypeRegistry
import ghistabs.materialize.buildFunctionDefinition
import ghistabs.materialize.resolveRef
import ghistabs.materialize.undef
import ghistabs.parse.GlobalTypeDecl
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

/** A method type (`#`): a `__thiscall` function whose first parameter is `this`. */
internal fun DataTypeRegistry.methodDefinition(
    category: CategoryPath,
    name: String,
    body: TypeDecl.Method<GlobalTypeId>,
): FunctionDefinitionDataType = buildFunctionDefinition(
    category = category,
    name = name,
    ret = body.ret,
    params = body.params,
    thisType = thisTypeFor(body, name),
    callingConvention = CompilerSpec.CALLING_CONVENTION_thiscall,
    at = name,
)

/** Null [TypeDecl.Method.cls] is gdb's stub method (`##<ret>;`) stating no domain — the normal gcc
 *  2.x encoding, not a failure; only a stated-but-unresolvable cls is a real loss. */
private fun DataTypeRegistry.thisTypeFor(body: TypeDecl.Method<GlobalTypeId>, at: String): DataType =
    body.cls?.let { resolveRef(it) ?: undef("method-this-cls", at, it) } ?: Undefined4DataType.dataType

/**
 * `int A::*`: an Itanium data-member pointer is a byte offset, one ptrdiff_t wide, and Ghidra has no
 * pointer-to-member type. gcc ≤ 3.3 spells it as a pointer to the [TypeDecl.Member], ≥ 3.4 as
 * the Member alone (`build_ptrmem_type` stopped wrapping OFFSET_TYPE in POINTER_TYPE), so both
 * land here. The stab can't say which gcc wrote it, so ≥ 3.4's `int A::**` comes out one level
 * short — same width, so no layout moves.
 */
internal fun DataTypeRegistry.memberPointer(): DataType =
    // Unbound, like BuiltinTable's primitives: a program-bound `int` would fork `int.conflict`.
    AbstractIntegerDataType.getSignedDataType(dtm.dataOrganization.pointerSize, null)

/** [memberPointer] when a pointer to [pointee] is gcc ≤ 3.3's `int A::*`, else null. */
internal fun DataTypeRegistry.memberPointerTo(pointee: GlobalTypeDecl): DataType? =
    if (types.isMemberPointee(pointee)) memberPointer() else null
