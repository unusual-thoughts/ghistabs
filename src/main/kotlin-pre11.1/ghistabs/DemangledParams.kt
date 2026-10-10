package ghistabs

import ghidra.app.util.demangler.DemangledDataType
import ghidra.app.util.demangler.DemangledFunction

val DemangledFunction.paramTypes: List<DemangledDataType> get() = parameters
