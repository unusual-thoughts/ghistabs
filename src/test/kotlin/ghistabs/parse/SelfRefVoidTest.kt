package ghistabs.parse

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * The one distinction that matters for gcc's self-referential encodings: a type *explicitly
 * defined as itself* (`(x,y)=(x,y)`) is void; a bare `name:t(x,y)` (no `=`) is a forward
 * reference, not void. The parser must not collapse them to the same `Ref(self)` shape.
 */
class SelfRefVoidTest {
    @Test
    fun explicitSelfDefIsVoid() {
        assertEquals(
            SymbolDecl.NamedType("void", TypeNameKind.TYPEDEF, LocalTypeId(0, 20), TypeDecl.Void),
            Parser("void:t(0,20)=(0,20)").parseSymbol(),
        )
    }

    @Test
    fun explicitSelfDefIsVoidForTaggedType() {
        assertEquals(
            SymbolDecl.NamedType("void", TypeNameKind.TAG, LocalTypeId(0, 20), TypeDecl.Void),
            Parser("void:T(0,20)=(0,20)").parseSymbol(),
        )
    }

    @Test
    fun bareTypedefIsForwardRefNotVoid() {
        assertEquals(
            SymbolDecl.NamedType("FILE", TypeNameKind.TYPEDEF, LocalTypeId(0, 116), TypeDecl.Ref(LocalTypeId(0, 116))),
            Parser("FILE:t(0,116)").parseSymbol(),
        )
    }

    @Test
    fun bareForwardDeclaredStructIsRefNotVoid() {
        assertEquals(
            SymbolDecl.NamedType("b2World", TypeNameKind.TYPEDEF, LocalTypeId(1, 27), TypeDecl.Ref(LocalTypeId(1, 27))),
            Parser("b2World:t(1,27)").parseSymbol(),
        )
    }

    @Test
    fun inlineSelfDefIsVoid() {
        // `(0,6)=(0,6)` nested inside a typedef: the inline binding survives, its body is void.
        assertEquals(
            SymbolDecl.NamedType(
                "x",
                TypeNameKind.TYPEDEF,
                LocalTypeId(0, 5),
                TypeDecl.InlineDef(LocalTypeId(0, 6), TypeDecl.Void),
            ),
            Parser("x:t(0,5)=(0,6)=(0,6)").parseSymbol(),
        )
    }
}
