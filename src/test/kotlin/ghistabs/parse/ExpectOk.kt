package ghistabs.parse

import org.junit.jupiter.api.Assertions.fail

/**
 * The parsed value, failing the test with the parse exception when the input didn't parse.
 *
 * Without it a test would compare a [ParseResult] against a bare [SymbolDecl]/[TypeDecl] through
 * `assertEquals(Any?, Any?)` — which compiles, always fails, and reports the mismatch as a value
 * difference rather than as the parse error it actually is.
 */
fun <T> ParseResult<T>.mustBeOk(msg: String = ""): T = when (this) {
    is ParseResult.Ok -> inner
    is ParseResult.Error -> fail("$msg expected a parse, got: ${ex.message}")
}

/** The parse failure, for tests asserting the parser rejects input rather than misreading it. */
fun <T> ParseResult<T>.mustBeError(): StabsParseException = when (this) {
    is ParseResult.Error -> ex
    is ParseResult.Ok -> fail("expected a parse error, got: $inner")
}
