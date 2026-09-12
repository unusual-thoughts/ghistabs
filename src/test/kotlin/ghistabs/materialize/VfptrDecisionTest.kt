package ghistabs.materialize

import ghistabs.test.mustBe
import ghistabs.test.mustBeA
import org.junit.jupiter.api.Test

class VfptrDecisionTest {
    @Test
    fun `skipInheritedFromBase - poly base present returns skip action`() {
        val action = chooseVfptrAction(
            hasPolymorphicBaseSubobject = true,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = null,
            canonicalVfptrFieldName = "{vfptr}",
        )
        action.mustBeA<VfptrAction.SkipInheritedFromBase>()
    }

    @Test
    fun `noParserVptr noComponent - insert at offset 0`() {
        val action = chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = null,
            componentAtTargetOffset = null,
            canonicalVfptrFieldName = "{vfptr}",
        )
        action.mustBeA<VfptrAction.Insert>()
        (action as VfptrAction.Insert).offsetBytes mustBe 0
    }

    @Test
    fun `parserVptrAt4 noComponent - insert at offset 4`() {
        val action = chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 4,
            componentAtTargetOffset = null,
            canonicalVfptrFieldName = "{vfptr}",
        )
        action.mustBeA<VfptrAction.Insert>()
        (action as VfptrAction.Insert).offsetBytes mustBe 4
    }

    @Test
    fun `canonicalVfptrAtOffset - already canonical action`() {
        val snapshot = FirstComponentSnapshot(fieldName = "{vfptr}", offsetBytes = 0, isUndefined = false)
        val action = chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        action.mustBeA<VfptrAction.AlreadyCanonical>()
    }

    @Test
    fun `parserEmittedVptrAtOffset - replace action with old name`() {
        val snapshot = FirstComponentSnapshot(fieldName = $$"_vptr$Foo", offsetBytes = 0, isUndefined = false)
        val action = chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        action.mustBeA<VfptrAction.Replace>()
        val replace = action as VfptrAction.Replace
        replace.offsetBytes mustBe 0
        replace.wasFieldName mustBe $$"_vptr$Foo"
    }

    @Test
    fun `regularFieldAtOffset - collision action`() {
        val snapshot = FirstComponentSnapshot(fieldName = "x", offsetBytes = 0, isUndefined = false)
        val action = chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        action.mustBeA<VfptrAction.CollisionAt>()
        val collision = action as VfptrAction.CollisionAt
        collision.offsetBytes mustBe 0
        collision.occupantFieldName mustBe "x"
    }

    @Test
    fun `baseSubobjectAtOffset - skip inherited (no collision)`() {
        // bouniaf → ios_base cascade: the unresolved base occupies offset 0 as
        // a synthesized `_base_unknown_0` field. firstPolymorphicBase couldn't
        // prove polymorphism (base type doesn't resolve), but the layout still
        // hands us a base subobject at the vfptr offset; we must not overwrite it.
        val snapshot = FirstComponentSnapshot(fieldName = "_base_unknown_0", offsetBytes = 0, isUndefined = false)
        val action = chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        action.mustBeA<VfptrAction.SkipInheritedFromBase>()
    }

    @Test
    fun `resolvedBaseAtOffset - skip inherited (no collision)`() {
        val snapshot = FirstComponentSnapshot(fieldName = "_base_bouniaf", offsetBytes = 0, isUndefined = false)
        val action = chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        action.mustBeA<VfptrAction.SkipInheritedFromBase>()
    }

    @Test
    fun `undefinedSlot - insert action`() {
        val snapshot = FirstComponentSnapshot(fieldName = null, offsetBytes = 0, isUndefined = true)
        val action = chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        action.mustBeA<VfptrAction.Insert>()
    }
}
