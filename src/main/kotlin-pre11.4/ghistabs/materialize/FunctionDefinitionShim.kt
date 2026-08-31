package ghistabs.materialize

import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.ParameterDefinition

/**
 * `setArguments` became varargs in 11.4; before it the parameter is a plain array, which a spread
 * call cannot target. In [ghistabs.materialize] so both call sites reach it without an import.
 */
internal fun FunctionDefinitionDataType.setArguments(vararg args: ParameterDefinition) = setArguments(args)
