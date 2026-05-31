package ghistabs.builder

import ghistabs.parser.TypeDecl
import ghistabs.parser.TypeId
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Pure unit tests for BuiltinTable core logic.
 * Tests the data type classification algorithm without mocking DataTypeManager.
 */
class BuiltinTableTest {
    @Test
    fun testClassifySignedInt32() {
        val kind = classifyBuiltin(TypeDecl.Range(TypeId(0, 1), -2147483648L, 2147483647L))
        assertEquals(BuiltinKind.SIGNED_INT, kind)
        assertEquals(4, kind.sizeBytes)
    }

    @Test
    fun testClassifyUnsignedInt32() {
        val kind = classifyBuiltin(TypeDecl.Range(TypeId(0, 1), 0L, 4294967295L))
        assertEquals(BuiltinKind.UNSIGNED_INT, kind)
        assertEquals(4, kind.sizeBytes)
    }

    @Test
    fun testClassifyUnsignedByte() {
        val kind = classifyBuiltin(TypeDecl.Range(TypeId(0, 1), 0L, 255L))
        assertEquals(BuiltinKind.UNSIGNED_BYTE, kind)
        assertEquals(1, kind.sizeBytes)
    }

    @Test
    fun testClassifyWithSizeAttr64ULL() {
        val kind = classifyBuiltin(TypeDecl.WithSizeAttr(64, TypeDecl.Range(TypeId(0, 6), 0L, -1L)))
        assertEquals(BuiltinKind.UNSIGNED_LONG, kind)
        assertEquals(8, kind.sizeBytes)
    }

    @Test
    fun testClassifyBool() {
        val kind = classifyBuiltin(TypeDecl.WithSizeAttr(8, TypeDecl.Ref(TypeId(0, -16))))
        assertEquals(BuiltinKind.BOOL, kind)
        assertEquals(1, kind.sizeBytes)
    }

    @Test
    fun testClassifyComplex8() {
        val kind = classifyBuiltin(TypeDecl.Complex(3, 8))
        assertEquals(BuiltinKind.COMPLEX8, kind)
        assertEquals(8, kind.sizeBytes)
    }

    @Test
    fun testClassifyComplex16() {
        val kind = classifyBuiltin(TypeDecl.Complex(4, 16))
        assertEquals(BuiltinKind.COMPLEX16, kind)
        assertEquals(16, kind.sizeBytes)
    }

    @Test
    fun testClassifyNonPrimitive() {
        val kind = classifyBuiltin(TypeDecl.Pointer(TypeDecl.Ref(TypeId(0, 1))))
        assertEquals(BuiltinKind.NONE, kind)
    }
}

/**
 * Builtin type classification (pure algorithm, no Ghidra types).
 * Extracted from BuiltinTable.resolve to enable pure unit testing.
 */
enum class BuiltinKind(val sizeBytes: Int) {
    NONE(0),
    VOID(0),
    SIGNED_BYTE(1),
    UNSIGNED_BYTE(1),
    CHAR(1),
    SIGNED_SHORT(2),
    UNSIGNED_SHORT(2),
    SIGNED_INT(4),
    UNSIGNED_INT(4),
    SIGNED_LONG(8),
    UNSIGNED_LONG(8),
    BOOL(1),
    COMPLEX8(8),
    COMPLEX16(16),
    COMPLEX32(32),
}

/**
 * Pure function to classify a TypeDecl into a builtin kind.
 * This extraction allows Kind 1 (pure unit) testing of the classification logic.
 * The actual DataType object construction happens in BuiltinTable.resolve (Ghidra glue).
 */
fun classifyBuiltin(decl: TypeDecl): BuiltinKind = when (decl) {
    is TypeDecl.WithSizeAttr -> {
        when {
            decl.inner is TypeDecl.Ref && decl.inner.id == TypeId(0, -16) -> {
                BuiltinKind.BOOL
            }

            else -> {
                // For WithSizeAttr with a non-boolean inner, resolve the inner first
                val innerKind = classifyBuiltin(decl.inner)
                if (innerKind != BuiltinKind.NONE) {
                    return innerKind
                }
                // Otherwise use size attribute to determine the type
                val sizeBits = decl.sizeBits
                if (decl.inner is TypeDecl.Range) {
                    val range = decl.inner
                    val signed = range.min < 0
                    when (sizeBits) {
                        8 -> if (signed) BuiltinKind.SIGNED_BYTE else BuiltinKind.UNSIGNED_BYTE
                        16 -> if (signed) BuiltinKind.SIGNED_SHORT else BuiltinKind.UNSIGNED_SHORT
                        32 -> if (signed) BuiltinKind.SIGNED_INT else BuiltinKind.UNSIGNED_INT
                        64 -> if (signed) BuiltinKind.SIGNED_LONG else BuiltinKind.UNSIGNED_LONG
                        else -> BuiltinKind.NONE
                    }
                } else {
                    BuiltinKind.NONE
                }
            }
        }
    }

    is TypeDecl.Range -> {
        val sizeBits = widthBits(decl.min, decl.max)
        val signed = decl.min < 0

        when (sizeBits) {
            0 -> BuiltinKind.VOID
            8 -> if (signed &&
                decl.min == -128L &&
                decl.max == 127L
            ) {
                BuiltinKind.CHAR
            } else if (signed) {
                BuiltinKind.SIGNED_BYTE
            } else {
                BuiltinKind.UNSIGNED_BYTE
            }

            16 -> if (signed) BuiltinKind.SIGNED_SHORT else BuiltinKind.UNSIGNED_SHORT
            32 -> if (signed) BuiltinKind.SIGNED_INT else BuiltinKind.UNSIGNED_INT
            64 -> if (signed) BuiltinKind.SIGNED_LONG else BuiltinKind.UNSIGNED_LONG
            else -> BuiltinKind.NONE
        }
    }

    is TypeDecl.Complex -> {
        when (decl.rCode) {
            3 -> BuiltinKind.COMPLEX8
            4 -> BuiltinKind.COMPLEX16
            5 -> BuiltinKind.COMPLEX32
            else -> BuiltinKind.NONE
        }
    }

    else -> BuiltinKind.NONE
}

private fun widthBits(min: Long, max: Long): Int = when {
    min == 0L && max == 0L -> 0

    // void/zero-size
    // unsigned: max is 2^n - 1 (use unsigned comparison)
    min == 0L ->
        when {
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

    else -> 32 // fallback
}
