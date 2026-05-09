package ghistabs.parser

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * ParserPrimitiveTest: Tests for primitive type forms.
 *
 * Verifies AC2.2 (size attributes), AC2.3 (complex types), and pointer/const forms.
 */
class ParserPrimitiveTest {
    @Test
    fun testBoolWithSizeAttr() {
        val input = "_Bool:t(0,21)=@s8;-16"
        val expected =
            SymbolDecl.Typedef(
                name = "_Bool",
                id = TypeId(0, 21),
                body =
                    TypeDecl.WithSizeAttr(
                        sizeBits = 8,
                        inner = TypeDecl.Ref(TypeId(0, -16)),
                    ),
            )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testIntRange() {
        val input = "int:t(0,1)=r(0,1);-2147483648;2147483647;"
        val expected =
            SymbolDecl.Typedef(
                name = "int",
                id = TypeId(0, 1),
                body =
                    TypeDecl.Range(
                        of = TypeId(0, 1),
                        min = -2147483648L,
                        max = 2147483647L,
                    ),
            )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testLongLongIntWithSizeAttrOctal() {
        val input = "long long int:t(0,6)=@s64;r(0,6);0000000000000;01777777777777777777777;"
        val expected =
            SymbolDecl.Typedef(
                name = "long long int",
                id = TypeId(0, 6),
                body =
                    TypeDecl.WithSizeAttr(
                        sizeBits = 64,
                        inner =
                            TypeDecl.Range(
                                of = TypeId(0, 6),
                                min = 0L,
                                max = -1L, // octal 01777777777777777777777 = 2^64-1 = -1L when signed
                            ),
                    ),
            )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testComplexFloat() {
        val input = "complex float:t(0,16)=R3;8;0;"
        val expected =
            SymbolDecl.Typedef(
                name = "complex float",
                id = TypeId(0, 16),
                body = TypeDecl.Complex(rCode = 3, sizeBytes = 8),
            )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testComplexDouble() {
        val input = "complex double:t(0,17)=R3;16;0;"
        val expected =
            SymbolDecl.Typedef(
                name = "complex double",
                id = TypeId(0, 17),
                body = TypeDecl.Complex(rCode = 3, sizeBytes = 16),
            )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testPointerToInt() {
        val input = "pi:t(0,30)=*(0,1)"
        val expected =
            SymbolDecl.Typedef(
                name = "pi",
                id = TypeId(0, 30),
                body = TypeDecl.Pointer(TypeDecl.Ref(TypeId(0, 1))),
            )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testConstPointerToInt() {
        val input = "cpi:t(0,31)=k*(0,1)"
        val expected =
            SymbolDecl.Typedef(
                name = "cpi",
                id = TypeId(0, 31),
                body = TypeDecl.Const(TypeDecl.Pointer(TypeDecl.Ref(TypeId(0, 1)))),
            )
        assertEquals(expected, Parser(input).parseSymbol())
    }
}
