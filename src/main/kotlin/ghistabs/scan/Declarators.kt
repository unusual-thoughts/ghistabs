package ghistabs.scan

import java.io.File

/**
 * A definition found in source text: the name it declares, its parameter list as the file spells it,
 * and the lines its head and body span.
 */
data class Definition(val name: String, val params: String, val startLine: Int, val endLine: Int)

/**
 * Which definition encloses a line, and where a file declares a name.
 *
 * Hand-rolled because Ghidra has no C++ front end: `ghidra.app.util.cparser.C` knows no `class`,
 * `template`, `namespace`, `operator` or `::`, and no result it produces carries a line. So this
 * never *understands* C++ — it matches braces over [scannable] text and reads the head above each
 * one, which is all "which function is `stl_vector.h:123` inside" needs.
 *
 * [compiledOut] blanks lines the preprocessor said a conditional dropped ([Preprocessed]); without
 * it both branches of an `#ifdef` are indexed, which is harmless for a line lookup — a line is in
 * one branch or the other — but not for the rare pair that opens a brace in one arm and closes it
 * in the next.
 */
class DeclaratorIndex(text: String, compiledOut: Set<Int> = emptySet()) {
    private val chars = text.stripCommentsAndLiterals()
    private val lineStarts = listOf(0) + chars.indices.filter { chars[it] == '\n' }.map { it + 1 }

    /** How many lines the file has — the one non-circular extent an included file can be given (§43). */
    val lineCount = lineStarts.size - if (chars.lastOrNull() == '\n') 1 else 0

    init {
        compiledOut.forEach { line -> lineStarts.getOrNull(line - 1)?.let { blankLine(it) } }
    }

    /** Every definition in the file, outermost first — a class's methods follow the class. */
    val definitions: List<Definition> by lazy {
        bodies.mapNotNull { (open, close) ->
            val start = headStart(open)
            declarator(String(chars, start, open - start))
                ?.let { Definition(it.name, it.params, lineAt(start + it.at), lineAt(close)) }
        }
    }

    /**
     * The innermost definition [line] falls in — a method rather than the class holding it, an
     * inlined one-liner rather than the constructor whose initialiser list precedes it.
     */
    fun enclosing(line: Int) =
        definitions.filter { line in it.startLine..it.endLine }.minByOrNull { it.endLine - it.startLine }

    /**
     * Where the file names a type: `(class|struct|union|enum) <name>` and `typedef … <name>;`, the
     * two forms a stabs declaration can be looked for in. Several lines per name is normal — a
     * forward declaration and its definition, or one specialisation per instantiation.
     */
    val declarations: Map<String, List<Int>> by lazy {
        val text = String(chars)
        (TAG.findAll(text) + TYPEDEF.findAll(text))
            .mapNotNull { m ->
                m.groups.drop(1).filterNotNull().lastOrNull()?.let { it.value to lineAt(it.range.first) }
            }
            .groupBy({ it.first }, { it.second })
            .mapValues { (_, lines) -> lines.distinct().sorted() }
    }

    private fun blankLine(start: Int) =
        (start until chars.size).takeWhile { chars[it] != '\n' }.forEach { chars[it] = ' ' }

    private fun lineAt(offset: Int) = lineStarts.binarySearch(offset).let { if (it >= 0) it + 1 else -it - 1 }

    /**
     * Every `{ … }` pair, by offset. What is still open at the end runs to EOF rather than being
     * dropped: truncated text should still name its last definition.
     */
    private val bodies: List<Pair<Int, Int>> by lazy {
        val open = ArrayDeque<Int>()
        buildList {
            chars.forEachIndexed { i, c ->
                when (c) {
                    '{' -> open.addLast(i)
                    '}' -> open.removeLastOrNull()?.let { add(it to i) }
                }
            }
            open.forEach { add(it to chars.lastIndex) }
        }
    }

    /**
     * Where the head above a body begins: the previous `;`, `}` or `{`, counted outside parentheses.
     * (so `for (i = 0; …)` is one head and not two.)
     */
    private fun headStart(open: Int): Int {
        var depth = 0
        for (i in open - 1 downTo 0) {
            when (chars[i]) {
                ')' -> depth++
                '(' -> depth--
                ';', '}', '{' -> if (depth <= 0) return i + 1
            }
        }
        return 0
    }

    private companion object {
        const val ID = """[A-Za-z_$][A-Za-z0-9_$]*"""
        const val TARGS = """(?:<[^<>]*(?:<[^<>]*>[^<>]*)*>)?"""

        // `operator()`, `operator[]`, `operator+=`, `operator new[]`, and the conversion operators
        // whose name is a type — `operator void*`, `operator const char*`, `operator std::string`.
        const val CONVERSION = """(?:$ID\s+)*$ID(?:\s*::\s*$ID)*\s*(?:[*&]\s*)*"""
        const val OPERATOR =
            """operator(?:\s*(?:\(\s*\)|\[\s*]|[^\w\s(\[]+)|\s+(?:(?:new|delete)\s*(?:\[\s*])?|$CONVERSION))"""
        val DECLARATOR = Regex("""((?:$ID\s*$TARGS\s*::\s*)*(?:$OPERATOR|~\s*$ID|$ID))\s*$""")
        val TRAILING = Regex("""\s*(?:\bconst\b|\bvolatile\b|\bthrow\s*\([^()]*\)|=\s*0)$""")

        // `class X;` is excluded: a forward declaration is a weaker fact than the definition, and
        // saying it declares the name lets `stringfwd.h`'s `class allocator;` outrank `stl_alloc.h`,
        // where the class actually is.
        val TAG = Regex("""\b(?:class|struct|union|enum)\s+($ID)\b(?!\s*;)""")
        val TYPEDEF =
            Regex("""\btypedef\b(?:[^;{}]|\{[^{}]*})*?(?:\(\s*\*\s*($ID)\s*\)\s*\(|($ID)\s*(?:\[[^\]]*])*\s*;)""")
        val WHITESPACE = Regex("""\s+""")

        const val TAIL = 256

        /** Heads that end in a parameter list but are not definitions. */
        val CONTROL = setOf("if", "else", "for", "while", "switch", "do", "try", "catch", "return", "sizeof", "throw")
    }

    /** A declarator's name, its parameter list, and where in the head the name starts. */
    private data class Declarator(val name: String, val params: String, val at: Int)

    /**
     * The name a head declares, or null when the head is not a definition's.
     *
     * A definition head ends in its parameter list, modulo `const`/`throw(…)`, so anything not
     * ending in `)` — `class A : public B`, `enum`, `namespace std`, `int a[] =` — is rejected
     * without a keyword list. What survives that and *is* a keyword is a control statement.
     *
     * The initialiser list is cut first, at the last `:` outside parentheses, but only when what
     * precedes it is itself a declarator: `Foo(int) : _M_start(0)` cuts and names `Foo`, while
     * `public: void f()` does not, and neither does `class A : public B`. §44's Python heuristic
     * named `_M_start` for stl_vector.h L112 for want of that distinction.
     */
    private fun declarator(head: String): Declarator? {
        val cut = head.lastTopLevelColon()?.takeIf { head.take(it).unqualified().endsWith(")") }
        val decl = head.take(cut ?: head.length).unqualified()
        val open = decl.takeIf { it.endsWith(")") }?.matchingOpen() ?: return null
        val prefix = decl.take(open)
        val tail = prefix.tail()
        val match = DECLARATOR.find(tail) ?: return null
        val name = match.groupValues[1].replace(WHITESPACE, " ").trim()
        val params = decl.substring(open + 1, decl.lastIndex).replace(WHITESPACE, " ").trim()
        return Declarator(name, params, prefix.length - tail.length + match.range.first)
            .takeIf { name !in CONTROL }
    }

    /** The head without the qualifiers that may follow a parameter list. */
    private tailrec fun String.unqualified(): String {
        val trimmed = trimEnd()
        val tail = trimmed.tail()
        val at = TRAILING.find(tail)?.range?.first ?: return trimmed
        return trimmed.dropLast(tail.length - at).unqualified()
    }

    /**
     * The end of a head, where a name and its qualifiers are.
     *
     * A head reaches back to the previous statement, and [scannable] leaves the comment above a
     * function as whitespace rather than removing it, so heads run to thousands of characters —
     * on which an end-anchored regex with `\s*` in it costs quadratic time per starting position.
     * Nothing this looks for is longer than [TAIL]; a name that were would lose its outer
     * qualifier, not gain a wrong one, because a window opening inside a template argument list
     * cannot match `::` where a `>` or a `,` follows.
     */
    private fun String.tail() = takeLast(TAIL)

    /** The `(` matching the `)` this ends with. */
    private fun String.matchingOpen(): Int? {
        var depth = 0
        for (i in indices.reversed()) {
            when (this[i]) {
                ')' -> depth++
                '(' -> if (--depth == 0) return i
            }
        }
        return null
    }

    private fun String.lastTopLevelColon() = indices.fold(0 to null as Int?) { (depth, colon), i ->
        when (this[i]) {
            '(', '[' -> depth + 1 to colon
            ')', ']' -> depth - 1 to colon
            ':' -> depth to if (depth == 0 && getOrNull(i - 1) != ':' && getOrNull(i + 1) != ':') i else colon
            else -> depth to colon
        }
    }.second
}

/**
 * One [DeclaratorIndex] per local file per run.
 *
 * Keyed by modification time as well as path, so a file edited between renders in a long-lived
 * Ghidra session is re-read rather than answered from a stale scan.
 */
class SourceIndexes(private val compiledOut: (File) -> Set<Int> = { emptySet() }) {
    private val indexes = mutableMapOf<Pair<String, Long>, DeclaratorIndex>()

    operator fun get(file: File): DeclaratorIndex =
        indexes.getOrPut(file.path to file.lastModified()) { DeclaratorIndex(file.readText(), compiledOut(file)) }
}
