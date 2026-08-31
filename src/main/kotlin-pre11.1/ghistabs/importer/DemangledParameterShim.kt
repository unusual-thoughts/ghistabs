package ghistabs.importer

import ghidra.app.util.demangler.DemangledDataType

/**
 * 11.1 wrapped each demangled parameter in a `DemangledParameter` carrying `.type`; before it,
 * `getParameters()` returned the types themselves. Identity, so `parameters.map { it.type }` reads
 * the same either way. Declared per calling package because an extension needs an import otherwise.
 */
internal val DemangledDataType.type: DemangledDataType get() = this
