package ghistabs.test
import org.junit.jupiter.api.Assertions.*

fun <T> T.must(msg: String? = null, f: T.() -> Boolean) = assertTrue({ f() }, msg)
fun <T> T.mustNot(msg: String? = null, f: T.() -> Boolean) = assertFalse({ f() }, msg)

infix fun <T> T.mustBeSameAs(expected: T) = assertSame(expected, this)
fun <T> T.mustBeSameAs(expected: T, msg: String) = assertSame(expected, this, msg)
infix fun <T> T.mustNotBeSameAs(expected: T) = assertNotSame(expected, this)
fun <T> T.mustNotBeSameAs(expected: T, msg: String) = assertNotSame(expected, this, msg)

infix fun <T> T.mustBe(expected: T) = assertEquals(expected, this)
fun <T> T.mustBe(expected: T, msg: String) = assertEquals(expected, this, msg)
infix fun <T> T.mustNotBe(unexpected: T) = assertNotEquals(unexpected, this)
fun <T> T.mustNotBe(unexpected: T, msg: String) = assertNotEquals(unexpected, this, msg)

fun Any?.mustBeNull(msg: String? = null) = assertNull(this, msg)
fun Any?.mustNotBeNull(msg: String? = null) = assertNotNull(this, msg)
inline fun <reified T> Any?.mustBeA(msg: String? = null): T = assertInstanceOf<T>(T::class.java, this, msg)
inline fun <reified T> Any?.mustNotBeA(msg: String? = null) = assertFalse(this is T, msg)

fun Boolean.mustBeTrue(msg: String? = null) = assertTrue(this, msg)
fun Boolean.mustBeFalse(msg: String? = null) = assertFalse(this, msg)

fun <T> List<T>.mustBeEmpty(msg: String? = null) = assertEquals(emptyList<T>(), this, msg)
fun <T> List<T>.mustNotBeEmpty(msg: String? = null) = assertNotEquals(emptyList<T>(), this, msg)
fun Collection<*>.mustBeEmpty(msg: String? = null) = assertTrue(isEmpty(), msg)
fun Collection<*>.mustNotBeEmpty(msg: String? = null) = assertTrue(isNotEmpty(), msg)
inline fun <reified T> Array<T>.mustBeEmpty(msg: String? = null) = assertEquals(emptyArray<T>(), this, msg)
inline fun <reified T> Array<T>.mustNotBeEmpty(msg: String? = null) = assertNotEquals(emptyArray<T>(), this, msg)
fun Map<*, *>.mustBeEmpty(msg: String? = null) = assertTrue(isEmpty(), msg)
fun Map<*, *>.mustNotBeEmpty(msg: String? = null) = assertTrue(isNotEmpty(), msg)
fun String.mustBeEmpty(msg: String? = null) = assertEquals("", this, msg)
fun String.mustNotBeEmpty(msg: String? = null) = assertNotEquals("", this, msg)

infix fun <T> T.mustBeIn(set: Collection<T>) = assertTrue(this in set)
infix fun String.mustBeIn(haystack: String) = assertTrue(this in haystack)
infix fun Char.mustBeIn(haystack: String) = assertTrue(this in haystack)

infix fun <T> T.mustNotBeIn(set: Collection<T>) = assertTrue(this !in set)
infix fun String.mustNotBeIn(haystack: String) = assertTrue(this !in haystack)
infix fun Char.mustNotBeIn(haystack: String) = assertTrue(this !in haystack)
