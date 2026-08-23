package ghistabs.parse

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

/**
 * The one distinction that matters for gcc's self-referential encodings: a type *explicitly
 * defined as itself* (`(x,y)=(x,y)`) is void; a bare `name:t(x,y)` (no `=`) is a forward
 * reference, not void. The parser must not collapse them to the same `Ref(self)` shape.
 */
class SelfRefVoidTest {
    @Test
    fun explicitSelfDefIsVoid() {
        Parser("void:t(0,20)=(0,20)").parseSymbol() mustBe
            ParseResult.Ok(SymbolDecl.NamedType("void", TypeNameKind.TYPEDEF, LocalTypeId(0, 20), TypeDecl.Void))
    }

    @Test
    fun explicitSelfDefIsVoidForTaggedType() {
        Parser("void:T(0,20)=(0,20)").parseSymbol() mustBe
            ParseResult.Ok(SymbolDecl.NamedType("void", TypeNameKind.TAG, LocalTypeId(0, 20), TypeDecl.Void))
    }

    @Test
    fun bareTypedefIsForwardRefNotVoid() {
        Parser("FILE:t(0,116)").parseSymbol() mustBe
            ParseResult.Ok(
                SymbolDecl.NamedType(
                    "FILE",
                    TypeNameKind.TYPEDEF,
                    LocalTypeId(0, 116),
                    TypeDecl.Ref(LocalTypeId(0, 116)),
                ),
            )
    }

    @Test
    fun bareForwardDeclaredStructIsRefNotVoid() {
        Parser("b2World:t(1,27)").parseSymbol() mustBe
            ParseResult.Ok(
                SymbolDecl.NamedType(
                    "b2World",
                    TypeNameKind.TYPEDEF,
                    LocalTypeId(1, 27),
                    TypeDecl.Ref(LocalTypeId(1, 27)),
                ),
            )
    }

    @Test
    fun inlineSelfDefIsVoid() {
        // `(0,6)=(0,6)` nested inside a typedef: the inline binding survives, its body is void.
        Parser("x:t(0,5)=(0,6)=(0,6)").parseSymbol() mustBe ParseResult.Ok(
            SymbolDecl.NamedType(
                "x",
                TypeNameKind.TYPEDEF,
                LocalTypeId(0, 5),
                TypeDecl.InlineDef(LocalTypeId(0, 6), TypeDecl.Void),
            ),
        )
    }
}
