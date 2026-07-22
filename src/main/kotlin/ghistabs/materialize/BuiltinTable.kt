package ghistabs.materialize

import ghidra.program.model.data.*
import ghistabs.parse.TypeDecl
import java.lang.Long.compareUnsigned

/** Resolves gcc XCOFF builtin slots / primitive ranges / floats / complex to Ghidra [DataType]s. */
fun TypeDecl<*>.resolveBuiltin(): DataType? = when (this) {
    is TypeDecl.Builtin -> resolveSlot(slot)

    // gcc's void — a type explicitly defined as itself (`(x,y)=(x,y)`), recognised at parse.
    TypeDecl.Void -> VoidDataType()

    // Legacy form: `t<n>=@s<bits>;-<slot>` lands here after globalize hoists the
    // negative-id Ref. Bool is the recurring case.
    is TypeDecl.WithSizeAttr if inner is TypeDecl.Builtin ->
        resolveSlot(inner.slot) ?: resolveSizedRange(sizeBits, signed = false)

    is TypeDecl.WithSizeAttr -> {
        inner.resolveBuiltin()?.let { return it }
        if (inner is TypeDecl.Range) {
            return resolveSizedRange(sizeBits, signed = inner.min < 0)
        }
        null
    }

    is TypeDecl.Range -> when (val width = widthBits(min, max)) {
        0 -> VoidDataType()

        // gcc encodes plain `char` as range 0..127 and `signed char` as -128..127; both
        // are the source `char`, so map to CharDataType — otherwise `char*` renders as
        // `byte*`. (`unsigned char` 0..255 stays a byte, see testClassifyUnsignedByte.)
        8 if min == -128L && max == 127L -> CharDataType()

        8 if min == 0L && max == 127L -> CharDataType()

        else -> resolveSizedRange(width, min < 0)
    }

    is TypeDecl.Float -> when (sizeBytes) {
        4 -> FloatDataType()
        8 -> DoubleDataType()
        10, 12, 16 -> LongDoubleDataType()
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
 * Only slots seen on cygwin gcc 3.4.4 bouniaf2/bouniaf binaries are mapped; unknowns return null.
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

/** Pick signed/unsigned int by [sizeBits] when the inner can't be resolved directly. */
private fun resolveSizedRange(sizeBits: Int, signed: Boolean): DataType? = when (sizeBits) {
    8 if signed -> SignedByteDataType()
    8 -> ByteDataType()
    16 if signed -> ShortDataType()
    16 -> UnsignedShortDataType()
    32 if signed -> IntegerDataType()
    32 -> UnsignedIntegerDataType()
    64 if signed -> LongLongDataType()
    64 -> UnsignedLongLongDataType()
    else -> null
}

private fun widthBits(min: Long, max: Long): Int = when {
    // void
    min == 0L && max == 0L -> 0

    // Unsigned: max = 2^n - 1; use unsigned comparison so 0xFFFFFFFF isn't read as negative.
    min == 0L -> when {
        compareUnsigned(max, 0xFFL) <= 0 -> 8
        compareUnsigned(max, 0xFFFFL) <= 0 -> 16
        compareUnsigned(max, 0xFFFFFFFF) <= 0 -> 32
        else -> 64
    }

    // Signed: min = -(2^(n-1)).
    min < 0 -> when {
        min >= -128L -> 8
        min >= -32768L -> 16
        min >= -2147483648L -> 32
        else -> 64
    }

    else -> 32
}
