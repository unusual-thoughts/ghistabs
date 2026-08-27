package ghistabs.render

import ghidra.app.decompiler.*
import ghidra.app.decompiler.component.DecompilerUtils
import ghidra.program.model.listing.Function
import ghistabs.harvest.Func
import ghistabs.harvest.GhidraSourceFile
import ghistabs.harvest.blockAt

/** The fragments a wrapped logical line was rejoined from, each token at its offset in the join. */
private fun List<ClangLine>.placed(spell: Spelling): List<Placed> {
    var base = 0
    return flatMapIndexed { i, line ->
        base += if (i == 0) 0 else line.rejoin(this[i - 1]).length
        line.placed(spell).map { it.copy(at = base + it.at) }.also { base += line.rendered(spell).trim().length }
    }
}

private fun List<ClangLine>.rendered(spell: Spelling) = mapIndexed { i, line ->
    (if (i == 0) "" else line.rejoin(this[i - 1])) + line.rendered(spell).trim()
}.joinToString("")

private fun List<Placed>.braces() = filter { it.token.isBrace() }.map { Brace(it.token.text.first(), it.at) }

private val EMPTY_BLOCK = listOf('{', '}')

/* An already-closed empty block at the end of a decompiled line — Ghidra spells it `{ }` or `{}` */
fun List<Brace>.isEmptyBlock() = map(Brace::char) == EMPTY_BLOCK

/**
 * Offsets just past each shallowest-depth `&&`/`||` — the top-level boolean joins, the readable
 * points to break an over-long row at. Empty where the row has none at any depth.
 *
 * The operators are [ClangOpToken]s and the depth comes from the paren and bracket tokens, so an
 * `&&` inside a call's arguments is nested rather than top-level and one inside a string literal is
 * not an operator at all — neither of which a character scan could tell.
 */
private fun List<Placed>.booleanCuts(): List<Cut> {
    val toks = significant()
    var depth = 0
    return toks.mapIndexedNotNull { i, p ->
        when (p.token.text) {
            "(", "[" -> null.also { depth++ }
            ")", "]" -> null.also { depth-- }
            "&&", "||" -> if (p.token is ClangOpToken) toks.getOrNull(i + 1)?.let { Cut(it.at, depth) } else null
            else -> null
        }
    }
}

private const val SJLJ_PERSONALITY = "___gxx_personality_sj0"
private val SJLJ_CALLS = setOf("__Unwind_SjLj_Register", "__Unwind_SjLj_Unregister")

/**
 * ClangLines that are gcc SjLj exception scaffolding: the `__Unwind_SjLj_*` register/unregister
 * calls, the personality-routine store, and every write to the write-only call-site-index slot —
 * the SjLj context base + 4, base being the `&ctx` passed to `__Unwind_SjLj_Register`. Empty unless
 * the SjLj personality routine appears, so DWARF-EH (ELF) binaries, which keep unwinding out of the
 * code, match nothing.
 */
private fun sjljScaffolding(lines: List<ClangLine>): Set<ClangLine> {
    if (lines.none { l -> l.content().any { it.text == SJLJ_PERSONALITY } }) return emptySet()
    // The `&ctx` passed to __Unwind_SjLj_Register is an address-of, so its ClangVariableToken has no
    // stack varnode — we can't read the context offset from it. Identify the call-site index by its
    // signature instead: it's the one stack slot written on many lines as the sole variable (SjLj
    // stores it before every protected call and never reads it).
    val callSiteOffset = lines
        .mapNotNull { it.stackOffsets().singleOrNull() }
        .groupingBy { it }.eachCount()
        .filterValues { it >= 3 }
        .maxByOrNull { it.value }?.key
    return lines.filterTo(mutableSetOf()) { line ->
        line.content().any { (it is ClangFuncNameToken && it.text in SJLJ_CALLS) || it.text == SJLJ_PERSONALITY } ||
            (callSiteOffset != null && line.stackOffsets().singleOrNull() == callSiteOffset)
    }
}

private const val KEYWORD_IF = "if"
private const val KEYWORD_ELSE = "else"

/**
 * Range within the row's text of the condition of an `if (…) {` that opens a block at its end.
 *
 * The `if` is a [ClangOpToken] (`printc.cc` emits it `tagOp(KEYWORD_IF, …, op)`) and its condition is
 * delimited by a real paren pair — `ClangSyntaxToken.getOpen()`/`getClose()` — so a row carrying
 * several statements, which every row does here (the folded head, rejoined continuations), gives up
 * exactly the last `if`'s condition. Walking parens back through the characters could not: on
 * `… { if (a != false) { if (b == c) {` a greedy match spanned both conditions and one brace.
 */
private fun List<Placed>.ifCondition(): IntRange? {
    val toks = significant()
    if (toks.lastOrNull()?.token?.let { it.isBrace() && it.text == "{" } != true) return null
    val keyword = toks.indexOfLast { it.token is ClangOpToken && it.token.text == KEYWORD_IF }
        .takeIf { it >= 0 } ?: return null
    val open = toks[keyword + 1].token as? ClangSyntaxToken ?: return null
    val id = open.open.takeIf { it >= 0 } ?: return null
    // The closer must be the row's second-to-last token: anything between it and the `{` (a `goto`,
    // another statement) means this brace is not the one this `if` opens.
    val close = toks[toks.size - 2].takeIf { (it.token as? ClangSyntaxToken)?.close == id } ?: return null
    return (toks[keyword + 1].at + 1)..<close.at
}

/**
 * The rows of the two branches of the `if` whose opening brace is [brace], from the groups
 * `emitBlockIf` puts them in: `beginBlock(getBlock(1))` for the then branch and
 * `beginBlock(getBlock(2))` for the else, each a plain [ClangTokenGroup] sibling of the brace that
 * opens it. Walking rows and counting brace depth found the same thing only as long as every brace
 * on a row was a block and the separator was spelled the way the pass expected.
 *
 * The `else`'s own brace sits either before its group or, where `printc.cc` had queued a *pending*
 * brace to merge an `else if` and then found no `if` to merge with, as that group's first token.
 * Either way the branch is the group; what tells a real chain apart is that its group opens with the
 * `if` instead — which is why a plain `else` is recognised by the brace being *somewhere* and not by
 * matching `} else {` against `} else if (`.
 */
private fun branchesAt(brace: ClangToken, rowOf: Map<ClangLine, Int>): Branches? {
    val siblings = (brace.Parent() ?: return null).children()
        .filter { it !is ClangBreak && (it !is ClangToken || it.isSignificant) }
    val i = siblings.indexOfFirst { it === brace }.takeIf { it >= 0 } ?: return null
    val then = siblings.getOrNull(i + 1)?.asBlock() ?: return null
    if (!siblings.getOrNull(i + 2).spells("}") || !siblings.getOrNull(i + 3).spells(KEYWORD_ELSE)) return null
    val braced = siblings.getOrNull(i + 4).spells("{")
    val otherwise = (if (braced) siblings.getOrNull(i + 5) else siblings.getOrNull(i + 4))
        ?.asBlock()?.takeIf { braced || it.wrapsItsOwnBraces() } ?: return null
    return Branches(
        then.rows(rowOf) ?: return null,
        otherwise.rows(rowOf, unwrap = !braced) ?: return null,
    )
}

/**
 * Decompiler output with the leading declaration block folded onto the signature line and
 * same-typed locals grouped (`string *a; string *b;` → `string *a,*b;`), so statements start at
 * the top of the span instead of one-decl-per-line pushing them down. Locals gcc attributed to a
 * header drop out of the fold — they are declared in that header's own render. Every line's role and
 * each declaration's type are read from the clang token stream — comment banners by ClangCommentToken,
 * statements by ClangStatement ancestry, the signature by ClangFuncProto, declarations by
 * ClangVariableDecl ancestry, K&R nesting by the line's own `indent` — so nothing is guessed from
 * the rendered characters.
 *
 * [spell] is applied per token, not to the assembled row, so every offset a row carries is an offset
 * into its final text.
 */
fun DecompileResults.compressedDecompLines(
    source: GhidraSourceFile,
    func: Func,
    spell: Spelling = { it.text },
    elideSjlj: Boolean = false,
): List<DecompLine> {
    // exception in box2d, cCodeMarkup was null for some function. should log.
    val raw = DecompilerUtils.toLines(cCodeMarkup ?: return listOf())
    val victims = if (elideSjlj) sjljScaffolding(raw) else emptySet()
    // Drop Ghidra's blank lines outright — we place with our own spacing, and a stray blank
    // otherwise surfaces as a bare `// ⇐ L NN` tag when a run breaks into the gap below the span.
    val lines = raw
        .filterNot { it in victims || it.significant().isEmpty() }
        .dropWhile { it.isComment() }
    val ghFunction = function

    // Everything a row's tokens say about it. Shared with the folded head, which is a row like any
    // other here: gcc gives a leading `if` no ClangStatement, so it lands in the head's prefix rather
    // than the body, and the pass that uninverts branches reads the head's `if` like any row's.
    fun structure(placed: List<Placed>, rowOf: Map<ClangLine, Int>) = placed.significant().lastOrNull()
        ?.token?.takeIf { it.isBrace() && it.text == "{" }
        .let { brace -> Triple(placed.ifCondition(), brace?.let { branchesAt(it, rowOf) }, placed.booleanCuts()) }

    fun row(g: List<ClangLine>, rowOf: Map<ClangLine, Int>): DecompLine {
        val placed = g.placed(spell)
        val (condition, branches, cuts) = structure(placed, rowOf)
        return DecompLine(
            g.rendered(spell),
            g.first().address(),
            g.first().indent,
            g.flatMap { it.addresses() }.map { func.blockAt(it) }.distinct().singleOrNull(),
            braces = placed.braces(),
            ifCondition = condition,
            branches = branches,
            thisAt = placed.thisAt(),
            booleanCuts = cuts,
            thisArgs = placed.thisArguments(),
        )
    }

    val bodyStart = lines.indexOfFirst { it.isCode() }
    if (bodyStart <= 0) {
        return lines.map { l ->
            DecompLine(l.rendered(spell), l.address(), braces = l.placed(spell).braces())
        }
    }
    val (declLines, prefix) = lines.subList(0, bodyStart).partition { it.isDeclaration() }
    val signature = prefix.rendered(spell)
    val head = (
        listOf(signature) +
            groupDecls(declLines.filterNot { it.declaresForeign(func, source) }, spell)
        )
        .filter { it.isNotEmpty() }
        .joinToString(" ")
    // Rejoin the lines Ghidra wrapped one logical line onto: a continuation sits at the same block
    // depth as the line it continues but is indented deeper (a nested statement goes a block deeper; a
    // sibling stays at the same indent). Merging here keeps each logical line on one address, so it
    // lands on one row later. Indent is the head line's own nesting level; braces stay their own lines.
    val body = lines.subList(bodyStart, lines.size).fold(mutableListOf<MutableList<ClangLine>>()) { acc, line ->
        val head = acc.lastOrNull()?.first()
        val continues = head != null &&
            ((line.indent > head.indent && line.blockDepth() == head.blockDepth()) || line.isTrailingPunctuation())
        if (continues) acc.last() += line else acc += mutableListOf(line)
        acc
    }
    // Row 0 is the head, so a body group's row is its index plus one. Needed before the rows exist:
    // a branch group's extent is a pair of row numbers, and the tokens name lines, not rows.
    val rowOf = body.flatMapIndexed { i, g -> g.map { it to i + 1 } }.toMap()

    val declared = (prefix + declLines)
        .flatMap { it.significant() }
        .filterIsInstance<ClangVariableToken>()
        .map { it.text }
        .toSet()
    // The head is the prefix lines with the declarations folded in, so its structure is the prefix's —
    // a declaration carries no brace, no `this` and no condition. It does carry an `if`: gcc gives a
    // leading one no ClangStatement, so it is not code by the body test and folds in here.
    val headTokens = prefix.placed(spell)
    val (headCondition, headBranches, headCuts) = structure(headTokens, rowOf)
    val headRow = DecompLine(
        head,
        null,
        declares = declared,
        braces = headTokens.braces(),
        ifCondition = headCondition,
        branches = headBranches,
        thisAt = headTokens.thisAt(),
        booleanCuts = headCuts,
        memberCuts = memberCutsOf(headTokens, ghFunction),
        prototype = signature,
    )
    return listOf(headRow) + body.map { row(it, rowOf) }
}

private fun List<Placed>.thisAt() = filter { it.token.isThis() }.map { it.at..<it.at + it.token.text.length }

/**
 * The extent of a `this` passed as a call's first argument, comma and all — the offsets that turn
 * `find_slt(this,uVar1)` into `find_slt(uVar1)`.
 *
 * Read off the token stream rather than the characters: a `(this,` can only be found reliably where
 * the `(` is known to open a call's argument list and the `this` is known to be the variable token
 * Ghidra prints for the implicit object parameter, not part of a longer expression like
 * `(this->next)`. A lone `f(this)` loses just the argument.
 */
private fun List<Placed>.thisArguments(): List<IntRange> {
    val significant = significant()
    return significant.indices.mapNotNull { i ->
        val open =
            significant[i].takeIf { it.token.text == "(" && it.token is ClangSyntaxToken } ?: return@mapNotNull null
        if (significant.getOrNull(i - 1)?.token !is ClangFuncNameToken) return@mapNotNull null
        val arg = significant.getOrNull(i + 1)?.takeIf { it.token.isThis() } ?: return@mapNotNull null
        val after = significant.getOrNull(i + 2)?.token?.text
        val end = when (after) {
            "," -> significant[i + 2].at + 1
            ")" -> arg.at + arg.token.text.length
            else -> return@mapNotNull null
        }
        // Take the blank after the comma with it, so the argument list does not render `f( x)`.
        val padded = if (after == "," && significant.getOrNull(i + 3)?.at == end + 1) end + 1 else end
        arg.at..<padded.coerceAtLeast(open.at + 1)
    }
}

/**
 * What a legal C++ member definition of this head must leave out, empty where the function is not a
 * class member.
 *
 * Ghidra prints a member function the way its own model stores one: with a return type on every
 * function, and the `this` pointer as an explicit first parameter. Neither is legal C++ where the
 * definition is qualified — `void bouniaf::bouniaf(bouniaf *this)` draws "constructor cannot have a
 * return type" and "invalid parameter name: 'this' is a keyword" — so a qualified definition drops
 * the explicit parameter, leaving the body's uses of `this` to the implicit one, and a constructor
 * or destructor drops the return type as well.
 *
 * Both are named by *extent*: the return type is a [ClangReturnType] group and the parameter a
 * [ClangVariableDecl] one, so what goes is exactly what Ghidra put there, wherever in the list it
 * sits and however its type is spelled. Finding the parameter list by its parentheses and the `this`
 * inside it by a regex left every `vector<Exclusion*,…> *this` in place — the pattern could not
 * carry a `*` inside the type — and would have mis-cut a parameter that was a function pointer.
 *
 * Only when qualified: dropping the parameter from a free function would leave its body referring to
 * a `this` that no longer exists.
 */
private fun memberCutsOf(tokens: List<Placed>, function: Function?): List<IntRange> {
    val owner = function?.parentNamespace?.takeIf { !it.isGlobal } ?: return emptyList()
    return buildList {
        tokens.groupOf(ClangVariableDecl::class.java) { it.token.isThis() }
            ?.let { add(tokens.extent(it, ",")) }
        // A constructor and a destructor are named for their class; nothing else may drop its return
        // type. For a template it is the *template's* name: `DynArray<char,10ul>`'s ctor is `DynArray`.
        val cls = owner.name.substringBefore('<')
        if (function.name == cls || function.name == "~$cls") {
            tokens.groupOf(ClangReturnType::class.java) { true }?.let { add(tokens.extent(it, null)) }
        }
    }
}

/** The nearest [cls] ancestor of the first token matching [of], or null when none does. */
private fun <T : ClangNode> List<Placed>.groupOf(cls: Class<T>, of: (Placed) -> Boolean) =
    firstOrNull { of(it) && it.token.ancestor(cls) != null }?.token?.ancestor(cls)

/**
 * The offsets [group]'s tokens occupy in the row, extended over one following [separator] and the
 * blanks around it — so cutting the range leaves neither a doubled space nor a dangling comma.
 */
private fun List<Placed>.extent(group: ClangNode, separator: String?): IntRange {
    val own = indices.filter { this[it].token.isUnder(group) }
    val next = (own.last() + 1..<size).firstOrNull { this[it].token.isSignificant }
    // The separator goes with the group: the one after it, or — where the group ends its list, as
    // `this` does for a member whose other parameters precede it — the one before instead.
    val takesNext = separator != null && next != null && this[next].token.text == separator
    val start = when {
        separator == null || takesNext -> own.first()

        else -> (own.first() - 1 downTo 0).firstOrNull { this[it].token.isSignificant }
            ?.takeIf { this[it].token.text == separator } ?: own.first()
    }
    var end = if (takesNext) next + 1 else own.last() + 1
    while (end < size && !this[end].token.isSignificant) end++
    val last = this[own.last()]
    return this[start].at..<(getOrNull(end)?.at ?: (last.at + last.token.text.length))
}

private fun ClangToken.isUnder(group: ClangNode): Boolean =
    generateSequence(Parent()) { it.Parent() }.any { it === group }

/**
 * Group same-typed declaration lines into one statement each. The type is the line's
 * [ClangTypeToken] (Ghidra emits it as one token — the base type, without the `*`/`[N]`
 * declarator), the declarator the tokens after it up to the terminator; types keep first-appearance order.
 */
private fun groupDecls(declLines: List<ClangLine>, spell: Spelling): List<String> = declLines
    .mapNotNull { line ->
        val toks = line.significant()
        val typeIdx = toks.indexOfFirst { it is ClangTypeToken }
        if (typeIdx < 0) return@mapNotNull null
        val declarator = toks.subList(typeIdx + 1, toks.size).dropLast(1).joinToString("") { spell(it) }
        spell(toks[typeIdx]) to declarator
    }
    .groupBy({ it.first }, { it.second })
    .map { (type, declarators) -> "$type ${declarators.joinToString(",")};" }

/**
 * Put an `if`/`else` back the way round the source had it, negating the condition to match.
 *
 * Ghidra picks whichever sense of a branch its own analysis reached, which is regularly the opposite
 * of what was written: `if (ByteCount() > sizeof(long)) return false;` comes back as
 * `if (uVar1 < 5) { …the whole rest of the function… } else { local_c = false; }`. Structurally
 * sound, faithful to the binary, and backwards to read.
 *
 * Which way round the source had it is not guessed from the shape — gcc's line table says so. Every
 * line carries the address its tokens came from, so each branch has a lowest source line, and the
 * branch the source wrote first is the one with the lower. `IsConvertableToLong`'s else-branch
 * anchors at integer.cpp L2800 against the then-branch's L2802, so the source's condition was this
 * one's negation.
 *
 * Swapping also pays back placement: the lower-anchored branch moves first, so its rows stop being
 * held below the higher-anchored ones by [nestingRows].
 *
 * Spelled `!(…)` rather than by flipping the comparison — sound whatever the condition is, where
 * `<` → `>=` holds only for a bare relational one. Which rows are which branch, and whether there is
 * a plain `else` at all, come from [DecompLine.branches]: the groups `printc.cc` wrapped each branch
 * in. `else if` chains have no such pair, so a chain's second condition can't be stranded under a
 * negated first.
 */
fun List<DecompLine>.uninvertConditions(sourceLine: (DecompLine) -> Int?): List<DecompLine> {
    val lines = toMutableList()
    // Innermost first. A swap moves whole branch blocks, so an enclosing `if`'s extents survive a
    // nested one's swap while the reverse is not true. The decisions themselves don't depend on the
    // order — each reads only its branches' source lines, which no swap changes.
    for (open in indices.reversed()) {
        val line = lines[open]
        val condition = line.ifCondition ?: continue
        val (then, otherwise) = line.branches ?: continue
        val first = { rows: IntRange -> rows.mapNotNull { sourceLine(lines[it]) }.minOrNull() }
        val thenAt = first(then) ?: continue
        val elseAt = first(otherwise) ?: continue
        if (elseAt >= thenAt) continue
        lines[open] = line.negate(condition)
        // The rows between the branches — the `}`, the `else {` — stay between them.
        val separator = ((then.last + 1)..<otherwise.first).map { lines[it] }
        val swapped = otherwise.map { lines[it] } + separator + then.map { lines[it] }
        swapped.forEachIndexed { i, l -> lines[then.first + i] = l }
    }
    return lines
}
