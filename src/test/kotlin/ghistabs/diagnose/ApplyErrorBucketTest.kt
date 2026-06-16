package ghistabs.diagnose

import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class ApplyErrorBucketTest {
    @Test
    fun bucket_entrypointInMessageReturnsEntrypointMismatch() {
        val exception = RuntimeException("function entrypoint mismatch")
        val result = ApplyErrorBucket.bucket(exception)
        Assertions.assertEquals("entrypoint-mismatch", result)
    }

    @Test
    fun bucket_parameterInMessageReturnsParameterMismatch() {
        val exception = RuntimeException("Parameter wrong")
        val result = ApplyErrorBucket.bucket(exception)
        Assertions.assertEquals("parameter-mismatch", result)
    }

    @Test
    fun bucket_unknownReturnsOther() {
        val exception = RuntimeException("?")
        val result = ApplyErrorBucket.bucket(exception)
        Assertions.assertEquals("other", result)
    }
}
