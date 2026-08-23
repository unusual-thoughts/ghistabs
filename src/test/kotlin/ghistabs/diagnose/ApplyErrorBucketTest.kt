package ghistabs.diagnose

import ghistabs.test.mustBe
import org.junit.jupiter.api.Test

class ApplyErrorBucketTest {
    @Test
    fun bucket_entrypointInMessageReturnsEntrypointMismatch() {
        val exception = RuntimeException("function entrypoint mismatch")
        val result = ApplyErrorBucket.bucket(exception)
        result mustBe "entrypoint-mismatch"
    }

    @Test
    fun bucket_parameterInMessageReturnsParameterMismatch() {
        val exception = RuntimeException("Parameter wrong")
        val result = ApplyErrorBucket.bucket(exception)
        result mustBe "parameter-mismatch"
    }

    @Test
    fun bucket_unknownReturnsOther() {
        val exception = RuntimeException("?")
        val result = ApplyErrorBucket.bucket(exception)
        result mustBe "other"
    }
}
