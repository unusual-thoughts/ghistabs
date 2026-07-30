package ghistabs

import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.api.extension.ExtensionContext
import org.junit.jupiter.api.extension.InvocationInterceptor
import org.junit.jupiter.api.extension.ReflectiveInvocationContext
import org.opentest4j.TestAbortedException
import java.lang.reflect.Method

/**
 * Marks a parameterized test as a known, deterministic failure on the listed [fixtures]: for those
 * binaries a thrown assertion is the expected outcome (swallowed), while an *unexpected pass* is turned
 * into a failure so a since-fixed case can't silently rot in the list. Every other fixture runs normally.
 * `assumeTrue` skips are never mistaken for the expected failure — they pass straight through.
 *
 * Keyed by fixture, not by method: these gaps are per-binary (gcc 12 omitting the method stab section,
 * an AFTER-mode empty-stub gap), so the same method passes on the other fixtures.
 */
@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
@ExtendWith(ExpectedToFailExtension::class)
annotation class ExpectedToFail(val fixtures: Array<String>, val reason: String)

class ExpectedToFailExtension : InvocationInterceptor {
    override fun interceptTestMethod(
        invocation: InvocationInterceptor.Invocation<Void>,
        invocationContext: ReflectiveInvocationContext<Method>,
        extensionContext: ExtensionContext,
    ) {
        val expected = extensionContext.requiredTestMethod.getAnnotation(ExpectedToFail::class.java)
        val binaryName = (extensionContext.requiredTestInstance as StabsImportRegressionBase).binaryName
        if (binaryName !in expected.fixtures) return invocation.proceed().let { }

        try {
            invocation.proceed()
        } catch (skip: TestAbortedException) {
            throw skip
        } catch (_: Throwable) {
            return // the expected failure for this fixture
        }
        throw AssertionError(
            "@ExpectedToFail: '$binaryName' now passes ${extensionContext.requiredTestMethod.name}() " +
                "(${expected.reason}) — drop it from the fixtures list.",
        )
    }
}
