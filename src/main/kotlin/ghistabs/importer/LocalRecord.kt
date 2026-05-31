package ghistabs.importer

import ghistabs.parser.SymbolDecl

/**
 * Represents a local variable record from the stabs stream.
 *
 * @property decl The parsed symbol declaration.
 * @property rawValue The raw value from the stab record (stack offset for stack locals).
 * @property recordIndex The index of this record in the stabs stream (for scope filtering).
 */
data class LocalRecord(
    val decl: SymbolDecl,
    val rawValue: Long,
    val recordIndex: Int,
)
