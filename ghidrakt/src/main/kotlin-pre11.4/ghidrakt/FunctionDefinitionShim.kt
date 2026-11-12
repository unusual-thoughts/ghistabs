package ghidrakt

import ghidra.program.model.data.FunctionDefinitionDataType
import ghidra.program.model.data.ParameterDefinition

/**
 * `setArguments` became varargs in 11.4; before it the parameter is a plain array, which a spread
 * call cannot target. Callers reach it through `import ghidrakt.*`.
 */
fun FunctionDefinitionDataType.setArguments(vararg args: ParameterDefinition) = setArguments(args)
