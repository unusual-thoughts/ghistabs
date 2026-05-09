package ghistabs.parser

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * ParserClassTest: Tests for C++ class grammar.
 *
 * Verifies AC2.4: inheritance, methods, vtable markers, and static fields.
 */
class ParserClassTest {
    @Test
    fun testPlainStruct() {
        val input = "Foo:T(0,5)=s8x:(0,1),0,32;y:(0,1),32,32;;;"
        val expected =
            SymbolDecl.TaggedType(
                name = "Foo",
                id = TypeId(0, 5),
                body =
                    TypeDecl.Struct(
                        kind = AggrKind.STRUCT,
                        sizeBytes = 8,
                        bases = emptyList(),
                        fields =
                            listOf(
                                FieldDecl("x", TypeDecl.Ref(TypeId(0, 1)), offsetBits = 0, sizeBits = 32, isStatic = false),
                                FieldDecl("y", TypeDecl.Ref(TypeId(0, 1)), offsetBits = 32, sizeBits = 32, isStatic = false),
                            ),
                        methods = emptyList(),
                        hasVTablePointerMarker = false,
                        vtableTargetTypeId = null,
                    ),
            )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testSingleInheritanceNonVirtual() {
        val input = "Bar:T(0,6)=s4!1,020,(0,5);;;"
        val expected =
            SymbolDecl.TaggedType(
                name = "Bar",
                id = TypeId(0, 6),
                body =
                    TypeDecl.Struct(
                        kind = AggrKind.STRUCT,
                        sizeBytes = 4,
                        bases =
                            listOf(
                                BaseDecl(
                                    type = TypeDecl.Ref(TypeId(0, 5)),
                                    isVirtual = false,
                                    access = Access.PUBLIC,
                                    offsetBits = 0,
                                ),
                            ),
                        fields = emptyList(),
                        methods = emptyList(),
                        hasVTablePointerMarker = false,
                        vtableTargetTypeId = null,
                    ),
            )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testClassWithVTablePointerMarker() {
        val input = "Baz:T(0,7)=s8~%(0,8);;;"
        val expected =
            SymbolDecl.TaggedType(
                name = "Baz",
                id = TypeId(0, 7),
                body =
                    TypeDecl.Struct(
                        kind = AggrKind.STRUCT,
                        sizeBytes = 8,
                        bases = emptyList(),
                        fields = emptyList(),
                        methods = emptyList(),
                        hasVTablePointerMarker = true,
                        vtableTargetTypeId = TypeId(0, 8),
                    ),
            )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testMethodWithMangledSymbol() {
        val input = "Qux:T(0,9)=s4doIt::(1)=#(0,9),(0,1);(0,2);):_ZN3Qux4doItEi;2A.;;;"
        val expected =
            SymbolDecl.TaggedType(
                name = "Qux",
                id = TypeId(0, 9),
                body =
                    TypeDecl.Struct(
                        kind = AggrKind.STRUCT,
                        sizeBytes = 4,
                        bases = emptyList(),
                        fields = emptyList(),
                        methods =
                            listOf(
                                MethodDecl(
                                    name = "doIt",
                                    mangled = "_ZN3Qux4doItEi",
                                    signature =
                                        TypeDecl.Method(
                                            cls = TypeDecl.Ref(TypeId(0, 9)),
                                            ret = TypeDecl.Ref(TypeId(0, 1)),
                                            params = listOf(TypeDecl.Ref(TypeId(0, 2))),
                                        ),
                                    access = Access.PUBLIC,
                                    virt = VirtKind.NORMAL,
                                    isConst = false,
                                    isVolatile = false,
                                    vtableOffsetBits = null,
                                ),
                            ),
                        hasVTablePointerMarker = false,
                        vtableTargetTypeId = null,
                    ),
            )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testVirtualMethod() {
        val input = "Qux:T(0,9)=s4doIt::(1)=#(0,9),(0,1);(0,2);):_ZN3Qux4doItEi;2A*0;(0,9);;;;"
        val expected =
            SymbolDecl.TaggedType(
                name = "Qux",
                id = TypeId(0, 9),
                body =
                    TypeDecl.Struct(
                        kind = AggrKind.STRUCT,
                        sizeBytes = 4,
                        bases = emptyList(),
                        fields = emptyList(),
                        methods =
                            listOf(
                                MethodDecl(
                                    name = "doIt",
                                    mangled = "_ZN3Qux4doItEi",
                                    signature =
                                        TypeDecl.Method(
                                            cls = TypeDecl.Ref(TypeId(0, 9)),
                                            ret = TypeDecl.Ref(TypeId(0, 1)),
                                            params = listOf(TypeDecl.Ref(TypeId(0, 2))),
                                        ),
                                    access = Access.PUBLIC,
                                    virt = VirtKind.VIRTUAL,
                                    isConst = false,
                                    isVolatile = false,
                                    vtableOffsetBits = 0L,
                                ),
                            ),
                        hasVTablePointerMarker = false,
                        vtableTargetTypeId = null,
                    ),
            )
        assertEquals(expected, Parser(input).parseSymbol())
    }

    @Test
    fun testStaticField() {
        val input = "Quux:T(0,11)=s4count:/0(0,1):_ZN4Quux5countE;;;;"
        val expected =
            SymbolDecl.TaggedType(
                name = "Quux",
                id = TypeId(0, 11),
                body =
                    TypeDecl.Struct(
                        kind = AggrKind.STRUCT,
                        sizeBytes = 4,
                        bases = emptyList(),
                        fields =
                            listOf(
                                FieldDecl(
                                    name = "count",
                                    type = TypeDecl.Ref(TypeId(0, 1)),
                                    offsetBits = 0,
                                    sizeBits = 0,
                                    isStatic = true,
                                ),
                            ),
                        methods = emptyList(),
                        hasVTablePointerMarker = false,
                        vtableTargetTypeId = null,
                    ),
            )
        assertEquals(expected, Parser(input).parseSymbol())
    }
}
