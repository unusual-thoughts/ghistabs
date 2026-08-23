package ghistabs.testing

import ghistabs.integration.StabsImportRegressionBase
import org.junit.jupiter.api.extension.ExtendWith
import org.junit.jupiter.api.extension.ExtensionContext
import org.junit.jupiter.api.extension.InvocationInterceptor
import org.junit.jupiter.api.extension.ReflectiveInvocationContext
import org.opentest4j.TestAbortedException
import java.io.File
import java.lang.reflect.Method

/**
 * Marks a test as a known, deterministic failure on the listed [fixtures]: for those binaries a thrown
 * assertion is the expected outcome (swallowed), while an *unexpected pass* is turned into a failure so
 * a since-fixed case can't silently rot in the list. Every other fixture runs normally.
 *
 * Not interchangeable with an `assumeTrue` gate, and the two answer different questions. `assumeTrue`
 * says *this fixture does not have the shape the invariant is about* — a plain C binary has no
 * inheritance to materialize, so there is nothing to check. This says *the fixture has the shape and we
 * get it wrong*. Replacing one of these with an assumption would turn a known defect into a silent skip
 * and drop the ratchet that reports the fix.
 *
 * Keyed by fixture, not by method: these gaps are per-binary (gcc 12 omitting the method stab section,
 * an AFTER-mode empty-stub gap), so the same method passes on the other fixtures.
 *
 * `assumeTrue` skips pass straight through — they are never mistaken for the expected failure. That
 * leaves one hole this cannot close per-invocation: an entry whose test *skips* on its fixture is inert,
 * and skipping is legitimate for a method gated by mode (`demanglerHasNoEmptyStubs` runs only in AFTER).
 * [ghistabs.audit.ExpectedToFailAuditTest] closes it over the corpus, from the outcomes this records.
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
        val method = extensionContext.requiredTestMethod
        val expected = method.getAnnotation(ExpectedToFail::class.java)
        val binaryName = (extensionContext.requiredTestInstance as StabsImportRegressionBase).binaryName
        fun record(outcome: String) = outcomes.appendText("${method.name} $binaryName $outcome\n")

        if (binaryName !in expected.fixtures) {
            // Recorded too: the audit cannot call an entry dead until it knows the run reached that
            // fixture at all.
            try {
                invocation.proceed()
            } finally {
                record("ran")
            }
            return
        }

        try {
            invocation.proceed()
        } catch (skip: TestAbortedException) {
            record("skipped")
            throw skip
        } catch (_: Throwable) {
            record("failed")
            return // the expected failure for this fixture
        }
        record("passed")
        throw AssertionError(
            "@ExpectedToFail: '$binaryName' now passes ${method.name}() " +
                "(${expected.reason}) — drop it from the fixtures list.",
        )
    }

    private companion object {
        /** Per fork, to sidestep cross-JVM append races, and inside `results/` because the gradle task
         *  already archives that directory per run — a stale dump would read as a dead entry. */
        val outcomes = File("build/test-output/results/expected-to-fail-${ProcessHandle.current().pid()}.txt")
            .apply { parentFile.mkdirs() }
    }
}
