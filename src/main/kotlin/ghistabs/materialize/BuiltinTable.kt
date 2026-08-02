package ghistabs.materialize

import ghidra.program.model.data.*
import ghistabs.parse.TypeDecl

/** Resolves gcc XCOFF builtin slots / primitive ranges / floats / complex to Ghidra [DataType]s. */
fun TypeDecl<*>.resolveBuiltin(): DataType? = when (this) {
    is TypeDecl.Builtin -> resolveSlot(slot)

    // gcc's void — a type explicitly defined as itself (`(x,y)=(x,y)`), recognised at parse.
    TypeDecl.Void -> VoidDataType()

    // `@s<n>` outranks the inner descriptor for *width*: gcc emits it exactly where the inner's
    // own bounds can't carry the answer — `@s128;r(0,25);0;0377…;` truncates to -1L and would
    // otherwise classify __int128 as an 8-byte ulonglong. Identity still comes from the inner:
    // a slot names its primitive outright, and a char range stays char (`@s8;r(0,10);-128;127;`).
    is TypeDecl.WithSizeAttr -> when (inner) {
        // Legacy form `t<n>=@s<bits>;-<slot>`, reaching here after globalize hoists the
        // negative-id Ref. Bool is the recurring case.
        is TypeDecl.Builtin -> resolveSlot(inner.slot) ?: resolveSizedRange(sizeBits, signed = false)

        is TypeDecl.Range -> inner.asChar() ?: resolveSizedRange(sizeBits, signed = inner.min < 0)

        else -> inner.resolveBuiltin()
    }

    is TypeDecl.Range ->
        if (sizeBytes == 0L) VoidDataType() else asChar() ?: resolveSizedRange(sizeBits, min < 0)

    is TypeDecl.Float -> when (sizeBytes) {
        4L -> FloatDataType()
        8L -> DoubleDataType()
        10L, 12L, 16L -> LongDoubleDataType()
        else -> null
    }

    is TypeDecl.Complex -> when (rCode) {
        3 -> Complex8DataType()
        4 -> Complex16DataType()
        5 -> Complex32DataType()
        else -> null
    }

    else -> null
}

/**
 * Stable identity of the Ghidra primitive [this] would materialize to via [resolve], or null
 * when [this] isn't a primitive. `ghistabs.harvest.contentHash` hashes builtins by this so the
 * several stab spellings of one primitive — `char` as `Range(0,127)`, `WithSizeAttr(8, …)`, or
 * `Builtin(-2)` — collapse to one content hash instead of forking a `.conflict` in the DTM.
 * Distinct primitives keep distinct keys: `unsigned char` (`Range(0,255)` → byte) stays apart
 * from `char`.
 */
fun TypeDecl<*>.ghidraClassName(): String? = resolveBuiltin()?.javaClass?.name

/**
 * gcc XCOFF builtin slot → Ghidra type. Slot numbers per stabs spec / gcc `dbxout.c`.
 * Only slots seen on cygwin gcc 3.4.4 XAP2/CSR binaries are mapped; unknowns return null.
 */
private fun resolveSlot(slot: Int): DataType? = when (slot) {
    -1 -> IntegerDataType() // int
    -2 -> CharDataType() // char
    -3 -> ShortDataType() // short
    -4 -> LongDataType() // long
    -5 -> UnsignedCharDataType() // unsigned char
    -6 -> SignedCharDataType() // signed char
    -7 -> UnsignedShortDataType() // unsigned short
    -8 -> UnsignedIntegerDataType() // unsigned int
    -9 -> UnsignedIntegerDataType() // unsigned
    -10 -> UnsignedLongDataType() // unsigned long
    -11 -> VoidDataType() // void
    -12 -> FloatDataType() // float
    -13 -> DoubleDataType() // double
    -14 -> LongDoubleDataType() // long double
    -15 -> IntegerDataType() // integer (alias int)
    -16 -> BooleanDataType() // bool / _Bool
    -17 -> FloatDataType() // short real
    -18 -> DoubleDataType() // real
    -19 -> CharDataType() // stringptr
    -20 -> CharDataType() // character
    -21 -> ByteDataType() // logical*1
    -22 -> ShortDataType() // logical*2
    -23 -> IntegerDataType() // logical*4
    -24 -> IntegerDataType() // logical
    -27 -> SignedByteDataType() // integer*1
    -28 -> ShortDataType() // integer*2
    -29 -> IntegerDataType() // integer*4
    -30 -> WideCharDataType() // wchar_t
    -31 -> LongLongDataType() // long long
    -32 -> UnsignedLongLongDataType() // unsigned long long
    -33 -> UnsignedLongLongDataType() // logical*8
    -34 -> LongLongDataType() // integer*8
    else -> null
}

/**
 * gcc encodes plain `char` as range 0..127 and `signed char` as -128..127; both are the source
 * `char`, so map to CharDataType — otherwise `char*` renders as `byte*`. (`unsigned char`
 * 0..255 stays a byte, see testClassifyUnsignedByte.)
 */
private fun TypeDecl.Range<*>.asChar() = CharDataType().takeIf { (min == 0L || min == -128L) && max == 127L }

/**
 * Pick signed/unsigned int by width when the inner can't be resolved directly. Keyed on bits,
 * not bytes, so a sub-byte or otherwise odd `@s<n>` (`@s4`, `@s24`, `@s128`) falls through to
 * null instead of rounding up into a plausible-looking byte width. Null width → null type.
 */
private fun resolveSizedRange(sizeBits: Long?, signed: Boolean): DataType? = when (sizeBits) {
    8L if signed -> SignedByteDataType()
    8L -> ByteDataType()
    16L if signed -> ShortDataType()
    16L -> UnsignedShortDataType()
    32L if signed -> IntegerDataType()
    32L -> UnsignedIntegerDataType()
    64L if signed -> LongLongDataType()
    64L -> UnsignedLongLongDataType()

    // gcc 3.4.5 emits `__int128` in every CU. Its bounds truncate to 0..-1 — identical to what
    // signed __int128 would truncate to — so signedness is unrecoverable and everything 128-bit
    // lands unsigned. The width is right, which is what layout depends on.
    128L -> UnsignedInteger16DataType()

    else -> null
}
