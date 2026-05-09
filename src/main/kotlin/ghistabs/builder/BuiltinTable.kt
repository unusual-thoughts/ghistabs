package ghistabs.builder

import ghidra.program.model.data.*
import ghistabs.parser.TypeDecl
import ghistabs.parser.TypeId

object BuiltinTable {
    fun resolve(
        decl: TypeDecl,
        dtm: DataTypeManager,
    ): DataType? {
        return when (decl) {
            // _Bool special case: 8-bit unsigned that maps to BooleanDataType
            is TypeDecl.WithSizeAttr -> {
                when {
                    decl.inner is TypeDecl.Ref && decl.inner.id == TypeId(0, -16) -> {
                        BooleanDataType()
                    }

                    else -> {
                        // For WithSizeAttr with a non-boolean inner, resolve the inner and check for sign
                        val innerResolved = resolve(decl.inner, dtm)
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
                }
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

            is TypeDecl.Complex -> {
                when (decl.rCode) {
                    3 -> Complex8DataType()
                    4 -> Complex16DataType()
                    5 -> Complex32DataType()
                    else -> null // long double complex = 32 bytes
                }
            }

            else -> {
                null
            }
        }
    }

    private fun widthBits(
        min: Long,
        max: Long,
    ): Int =
        when {
            min == 0L && max == 0L -> {
                0
            }

            // void/zero-size
            min == 0L -> {
                // unsigned: max is 2^n - 1 (use unsigned comparison)
                when {
                    java.lang.Long.compareUnsigned(max, 0xFFL) <= 0 -> 8
                    java.lang.Long.compareUnsigned(max, 0xFFFFL) <= 0 -> 16
                    java.lang.Long.compareUnsigned(max, 0xFFFFFFFF) <= 0 -> 32
                    else -> 64
                }
            }

            min < 0 -> {
                // signed: min = -(2^(n-1))
                when {
                    min >= -128L -> 8
                    min >= -32768L -> 16
                    min >= -2147483648L -> 32
                    else -> 64
                }
            }

            else -> {
                32
            } // fallback
        }
}
