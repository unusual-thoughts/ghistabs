package ghistabs.materialize.cpp

import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.ParameterDefinition

/**
 * `setArguments` became varargs in 11.4; before it the parameter is a plain array, which a spread
 * call cannot target. Declared per calling package because an extension needs an import otherwise.
 */
internal fun FunctionDefinitionDataType.setArguments(vararg args: ParameterDefinition) = setArguments(args)
