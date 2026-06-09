package ghistabs.builder

import ghidra.program.model.data.*
import ghistabs.parser.GlobalTypeId
import ghistabs.parser.TypeDecl

object BuiltinTable {
    fun resolve(decl: TypeDecl<GlobalTypeId>): DataType? = when (decl) {
        // _Bool special case: gdb stabs encodes _Bool as (0,-16); n=-16 is preserved after globalisation.
        is TypeDecl.WithSizeAttr if decl.inner is TypeDecl.Ref &&
            decl.inner.id.n == -16 -> BooleanDataType()

        // For WithSizeAttr with a non-boolean inner, resolve the inner and check for sign
        is TypeDecl.WithSizeAttr -> {
            val innerResolved = resolve(decl.inner)
            if (innerResolved != null) {
                return innerResolved
            }
            // Otherwise use size attribute to determine the type
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

        is TypeDecl.Complex -> when (decl.rCode) {
            3 -> Complex8DataType()
            4 -> Complex16DataType()
            5 -> Complex32DataType()
            else -> null // long double complex = 32 bytes
        }

        else -> null
    }

    private fun widthBits(min: Long, max: Long): Int = when {
        min == 0L && max == 0L -> 0

        // void/zero-size
        // unsigned: max is 2^n - 1 (use unsigned comparison)
        min == 0L -> when {
            java.lang.Long.compareUnsigned(max, 0xFFL) <= 0 -> 8
            java.lang.Long.compareUnsigned(max, 0xFFFFL) <= 0 -> 16
            java.lang.Long.compareUnsigned(max, 0xFFFFFFFF) <= 0 -> 32
            else -> 64
        }

        // signed: min = -(2^(n-1))
        min < 0 -> when {
            min >= -128L -> 8
            min >= -32768L -> 16
            min >= -2147483648L -> 32
            else -> 64
        }

        // fallback
        else -> 32
    }
}
