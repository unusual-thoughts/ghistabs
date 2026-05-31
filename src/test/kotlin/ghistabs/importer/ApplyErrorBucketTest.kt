package ghistabs.importer

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class ApplyErrorBucketTest {
    @Test
    fun bucket_entrypointInMessageReturnsEntrypointMismatch() {
        val exception = RuntimeException("function entrypoint mismatch")
        val result = ApplyErrorBucket.bucket(exception)
        assertEquals("entrypoint-mismatch", result)
    }

    @Test
    fun bucket_parameterInMessageReturnsParameterMismatch() {
        val exception = RuntimeException("Parameter wrong")
        val result = ApplyErrorBucket.bucket(exception)
        assertEquals("parameter-mismatch", result)
    }

    @Test
    fun bucket_unknownReturnsOther() {
        val exception = RuntimeException("?")
        val result = ApplyErrorBucket.bucket(exception)
        assertEquals("other", result)
    }
}
