package ghistabs.materialize

import ghidra.program.model.data.*
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

/** Resolves gcc XCOFF builtin slots / primitive ranges / floats / complex to Ghidra [DataType]s. */
object BuiltinTable {
    fun resolve(decl: TypeDecl<GlobalTypeId>): DataType? = when (decl) {
        is TypeDecl.Builtin -> resolveSlot(decl.slot)

        // Legacy form: `t<n>=@s<bits>;-<slot>` lands here after globalize hoists the
        // negative-id Ref. Bool is the recurring case.
        is TypeDecl.WithSizeAttr if decl.inner is TypeDecl.Builtin ->
            resolveSlot(decl.inner.slot) ?: resolveSizedRange(decl, signed = false)

        is TypeDecl.WithSizeAttr -> {
            val innerResolved = resolve(decl.inner)
            if (innerResolved != null) {
                return innerResolved
            }
            val sizeBits = decl.sizeBits
            if (decl.inner is TypeDecl.Range) {
                val range = decl.inner
                val signed = range.min < 0
                return when (sizeBits) {
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
            }
            null
        }

        is TypeDecl.Range -> {
            val sizeBits = widthBits(decl.min, decl.max)
            val signed = decl.min < 0

            when (sizeBits) {
                0 -> VoidDataType()
                8 if signed && decl.min == -128L && decl.max == 127L -> CharDataType()
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
        }

        is TypeDecl.Float -> when (decl.sizeBytes) {
            4 -> FloatDataType()
            8 -> DoubleDataType()
            10, 12, 16 -> LongDoubleDataType()
            else -> null
        }

        is TypeDecl.Complex -> when (decl.rCode) {
            3 -> Complex8DataType()
            4 -> Complex16DataType()
            5 -> Complex32DataType()
            else -> null
        }

        else -> null
    }

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

    /** Pick signed/unsigned int by [decl.sizeBits] when the inner can't be resolved directly. */
    private fun resolveSizedRange(decl: TypeDecl.WithSizeAttr<GlobalTypeId>, signed: Boolean): DataType? =
        when (decl.sizeBits) {
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
        min == 0L && max == 0L -> 0 // void

        // Unsigned: max = 2^n - 1; use unsigned comparison so 0xFFFFFFFF isn't read as negative.
        min == 0L -> when {
            java.lang.Long.compareUnsigned(max, 0xFFL) <= 0 -> 8
            java.lang.Long.compareUnsigned(max, 0xFFFFL) <= 0 -> 16
            java.lang.Long.compareUnsigned(max, 0xFFFFFFFF) <= 0 -> 32
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
}
