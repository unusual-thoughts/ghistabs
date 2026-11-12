package ghistabs.importer

import ghidrakt.test.mustBe
import org.junit.jupiter.api.Test

class SymbolApplierErrorBucketTest {
    @Test
    fun bucket_entrypointInMessageReturnsEntrypointMismatch() {
        val exception = RuntimeException("function entrypoint mismatch")
        val result = SymbolApplier.errorBucket(exception)
        result mustBe "entrypoint-mismatch"
    }

    @Test
    fun bucket_parameterInMessageReturnsParameterMismatch() {
        val exception = RuntimeException("Parameter wrong")
        val result = SymbolApplier.errorBucket(exception)
        result mustBe "parameter-mismatch"
    }

    @Test
    fun bucket_unknownReturnsOther() {
        val exception = RuntimeException("?")
        val result = SymbolApplier.errorBucket(exception)
        result mustBe "other"
    }
}
