package ghistabs.importer

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class LocalVarDedupTest {
    @Test
    fun shouldSkipLocal_paramCollisionReturnsDuplicateParamName() {
        val result = LocalVarDedup.shouldSkipLocal(
            "this",
            existingParamNames = setOf("this"),
            existingLocalNames = emptySet(),
        )
        assertEquals(SkipReason.DuplicateParamName, result)
    }

    @Test
    fun shouldSkipLocal_localCollisionReturnsDuplicateLocalName() {
        val result = LocalVarDedup.shouldSkipLocal(
            "i",
            existingParamNames = emptySet(),
            existingLocalNames = setOf("i"),
        )
        assertEquals(SkipReason.DuplicateLocalName, result)
    }

    @Test
    fun shouldSkipLocal_noCollisionReturnsNull() {
        val result = LocalVarDedup.shouldSkipLocal(
            "foo",
            existingParamNames = emptySet(),
            existingLocalNames = emptySet(),
        )
        assertNull(result)
    }

    @Test
    fun shouldSkipLocal_paramTakesPrecedenceOverLocal() {
        val result = LocalVarDedup.shouldSkipLocal(
            "x",
            existingParamNames = setOf("x"),
            existingLocalNames = setOf("x"),
        )
        assertEquals(SkipReason.DuplicateParamName, result)
    }
}
