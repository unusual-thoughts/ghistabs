package ghistabs.builder

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class VfptrDecisionTest {
    @Test
    fun `skipInheritedFromBase - poly base present returns skip action`() {
        val action = VfptrDecision.chooseVfptrAction(
            hasPolymorphicBaseSubobject = true,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = null,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.SkipInheritedFromBase)
    }

    @Test
    fun `noParserVptr noComponent - insert at offset 0`() {
        val action = VfptrDecision.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = null,
            componentAtTargetOffset = null,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.Insert)
        assertTrue((action as VfptrAction.Insert).offsetBytes == 0)
    }

    @Test
    fun `parserVptrAt4 noComponent - insert at offset 4`() {
        val action = VfptrDecision.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 4,
            componentAtTargetOffset = null,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.Insert)
        assertTrue((action as VfptrAction.Insert).offsetBytes == 4)
    }

    @Test
    fun `canonicalVfptrAtOffset - already canonical action`() {
        val snapshot = FirstComponentSnapshot(fieldName = "{vfptr}", offsetBytes = 0, isUndefined = false)
        val action = VfptrDecision.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.AlreadyCanonical)
    }

    @Test
    fun `parserEmittedVptrAtOffset - replace action with old name`() {
        val snapshot = FirstComponentSnapshot(fieldName = "_vptr\$Foo", offsetBytes = 0, isUndefined = false)
        val action = VfptrDecision.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.Replace)
        val replace = action as VfptrAction.Replace
        assertTrue(replace.offsetBytes == 0)
        assertTrue(replace.wasFieldName == "_vptr\$Foo")
    }

    @Test
    fun `regularFieldAtOffset - collision action`() {
        val snapshot = FirstComponentSnapshot(fieldName = "x", offsetBytes = 0, isUndefined = false)
        val action = VfptrDecision.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.CollisionAt)
        val collision = action as VfptrAction.CollisionAt
        assertTrue(collision.offsetBytes == 0)
        assertTrue(collision.occupantFieldName == "x")
    }

    @Test
    fun `baseSubobjectAtOffset - skip inherited (no collision)`() {
        // bouniaf → ios_base cascade: the unresolved base occupies offset 0 as
        // a synthesised `_base_unknown_0` field. firstPolymorphicBase couldn't
        // prove polymorphism (base type doesn't resolve), but the layout still
        // hands us a base subobject at the vfptr offset; we must not overwrite it.
        val snapshot = FirstComponentSnapshot(fieldName = "_base_unknown_0", offsetBytes = 0, isUndefined = false)
        val action = VfptrDecision.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.SkipInheritedFromBase)
    }

    @Test
    fun `resolvedBaseAtOffset - skip inherited (no collision)`() {
        val snapshot = FirstComponentSnapshot(fieldName = "_base_bouniaf", offsetBytes = 0, isUndefined = false)
        val action = VfptrDecision.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.SkipInheritedFromBase)
    }

    @Test
    fun `undefinedSlot - insert action`() {
        val snapshot = FirstComponentSnapshot(fieldName = null, offsetBytes = 0, isUndefined = true)
        val action = VfptrDecision.chooseVfptrAction(
            hasPolymorphicBaseSubobject = false,
            parserVptrOffsetBytes = 0,
            componentAtTargetOffset = snapshot,
            canonicalVfptrFieldName = "{vfptr}",
        )
        assertTrue(action is VfptrAction.Insert)
    }
}
