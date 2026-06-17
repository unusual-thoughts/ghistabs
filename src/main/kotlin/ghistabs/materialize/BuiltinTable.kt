package ghistabs.materialize

import ghidra.program.model.data.*
import ghistabs.parse.GlobalTypeId
import ghistabs.parse.TypeDecl

object BuiltinTable {
    fun resolve(decl: TypeDecl<GlobalTypeId>): DataType? = when (decl) {
        // gcc XCOFF builtin slot — see [TypeDecl.Builtin]. Slot numbers
        // follow gcc/dbxout.c::dbx_register_decl and the stabs spec
        // (`(0,-N)` table). Only slots we've actually seen on XAP2/CSR
        // binaries are mapped here; unknown slots fall through to null
        // so the caller can substitute a placeholder.
        is TypeDecl.Builtin -> resolveSlot(decl.slot)

        // Legacy form: gdb-style `t<n>=@s<bits>;-<slot>` lands as
        // WithSizeAttr(bits, Builtin(slot)) after globalize hoists the
        // negative-id Ref. Bool is the recurring case (size attribute
        // gives the storage width; the slot identifies the primitive).
        is TypeDecl.WithSizeAttr if decl.inner is TypeDecl.Builtin ->
            resolveSlot(decl.inner.slot) ?: resolveSizedRange(decl, signed = false)

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
            else -> null // long double complex = 32 bytes
        }

        else -> null
    }

    /**
     * Map a gcc XCOFF builtin slot number to its Ghidra DataType.
     * Slot numbers per the stabs spec / gcc `dbxout.c`. Only entries
     * actually emitted by the cygwin gcc 3.4.4 toolchain on XAP2/CSR
     * targets are included; expand as new slots show up.
     */
    private fun resolveSlot(slot: Int): DataType? = when (slot) {
        -1 -> IntegerDataType()

        // int (32-bit on target)
        -2 -> CharDataType()

        // char
        -3 -> ShortDataType()

        // short
        -4 -> LongDataType()

        // long
        -5 -> UnsignedCharDataType()

        // unsigned char
        -6 -> SignedCharDataType()

        // signed char
        -7 -> UnsignedShortDataType()

        // unsigned short
        -8 -> UnsignedIntegerDataType()

        // unsigned int
        -9 -> UnsignedIntegerDataType()

        // unsigned
        -10 -> UnsignedLongDataType()

        // unsigned long
        -11 -> VoidDataType()

        // void
        -12 -> FloatDataType()

        // float
        -13 -> DoubleDataType()

        // double
        -14 -> LongDoubleDataType()

        // long double
        -15 -> IntegerDataType()

        // integer (alias int)
        -16 -> BooleanDataType()

        // bool / _Bool
        -17 -> FloatDataType()

        // short real (alias float)
        -18 -> DoubleDataType()

        // real (alias double)
        -19 -> CharDataType()

        // stringptr
        -20 -> CharDataType()

        // character
        -21 -> ByteDataType()

        // logical*1
        -22 -> ShortDataType()

        // logical*2
        -23 -> IntegerDataType()

        // logical*4
        -24 -> IntegerDataType()

        // logical
        -27 -> SignedByteDataType()

        // integer*1
        -28 -> ShortDataType()

        // integer*2
        -29 -> IntegerDataType()

        // integer*4
        -30 -> WideCharDataType()

        // wchar_t
        -31 -> LongLongDataType()

        // long long
        -32 -> UnsignedLongLongDataType()

        // unsigned long long
        -33 -> UnsignedLongLongDataType()

        // logical*8
        -34 -> LongLongDataType()

        // integer*8
        else -> null
    }

    /**
     * Pick a signed/unsigned integer DataType for [decl.sizeBits] when the
     * inner type can't be directly resolved. Used by the WithSizeAttr
     * fallback path for size-tagged builtins.
     */
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
