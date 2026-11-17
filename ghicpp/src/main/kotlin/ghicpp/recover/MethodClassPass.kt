package ghicpp.recover

import ghicpp.*
import ghicpp.ClassHierarchyRecords.Companion.readClassRecord
import ghicpp.MemberAttrs.Companion.isGuessedClass
import ghicpp.MemberAttrs.Companion.isPlacedByClassPass
import ghicpp.MemberAttrs.Companion.memberAttrs
import ghicpp.MemberAttrs.Companion.recordGuessed
import ghicpp.abi.StructorRole
import ghicpp.dissect.decompileEach
import ghicpp.dissect.pointerInto
import ghidra.program.model.data.Structure
import ghidra.program.model.listing.BookmarkType
import ghidra.program.model.listing.Function
import ghidra.program.model.listing.GhidraClass
import ghidra.program.model.listing.Program
import ghidra.program.model.pcode.HighFunction
import ghidra.program.model.pcode.PcodeOp
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import ghidrakt.*
import ghidrakt.diagnose.DiagnosticSink

/**
 * A call passing an object as [callee]'s `this`: [caller]'s own, or one of class [built], which [caller] built
 * with a constructor or holds at an offset into its own `this`.
 */
data class ThisCall(val caller: Function, val callee: Function, val built: GhidraClass? = null)

/**
 * What a [MethodClassPass] run moved: [perRound], how many each round that moved any did, the first off the known
 * classes alone, each later one off guesses too.
 */
data class MethodClassResult(val perRound: List<Int> = emptyList()) {
    /** How many it moved in all. */
    val moved get() = perRound.sum()

    /** How many rounds moved something; the one after them, which moved nothing, ended the run. */
    val rounds get() = perRound.size

    /** How many the rounds after the first moved: what trusting its own guesses added. */
    val offGuesses get() = perRound.drop(1).sum()

    /** "N method class(es) guessed", then, past one round, the rounds and what they added. */
    override fun toString() = "$moved method class(es) guessed" +
        if (rounds > 1) " in $rounds round(s), $offGuesses of them off earlier guesses" else ""
}

/** A function's class, as [MethodClassGuesser] guessed it, off [sites] calls. */
data class MethodClassGuess(val cls: GhidraClass, val sites: Int)

/**
 * Guesses the classes of the functions called on objects of the classes in [bases], each with the base it
 * shares its address with. A [GhidraClass] hashes by identity, so each class goes by its one instance among
 * [bases]' keys, and a function's namespace by id.
 */
class MethodClassGuesser(
    private val bases: Map<GhidraClass, GhidraClass?>,
    private val recorded: Set<Function> = emptySet(),
) {
    private val byId = bases.keys.associateBy { it.id }

    /** The class [f] is a method of, if one of [bases]. */
    private fun classOf(f: Function) = byId[f.parentNamespace.id]

    /** [classOf] [f], where that is known ([hasKnownClass]) or a class pass placed [f] there ([recorded]). */
    private fun knownClassOf(f: Function) = classOf(f)?.takeIf { f.hasKnownClass() || f in recorded }

    /** [cls], then the base it shares its address with, and so on up. */
    fun addressChain(cls: GhidraClass): List<GhidraClass> = generateSequence(cls) { bases[it] }.take(MAX_DEPTH).toList()

    /**
     * The class of each function [calls] pass an object whose class is known: the caller's own `this`, when
     * the caller is known to be a method of one of [bases], or an object the caller built with a constructor.
     * A method of a class is also called on its derived classes' objects, so where those are of several classes it
     * belongs to the one all the others derive from, through the bases they share their address with, and
     * to none where no one class is.
     */
    fun guess(calls: Collection<ThisCall>): Map<Function, MethodClassGuess> = calls.filter {
        classOf(it.callee) == null
    }.groupBy { it.callee }.mapNotNull { (f, sites) ->
        val classes = sites.mapNotNull { it.built ?: knownClassOf(it.caller) }
        val cls = classes.distinct().singleOrNull { c -> classes.all { c in addressChain(it) } }
        cls?.let { f to MethodClassGuess(it, classes.size) }
    }.toMap()
}

private const val MAX_DEPTH = 64

/**
 * Whether [this]'s class is known, not guessed: its name came with the program or its debug info, or from a user,
 * and not from an analysis such as a class pass or `RecoverClassesFromRTTIScript`.
 */
fun Function.hasKnownClass() = symbol.source == SourceType.IMPORTED || symbol.source == SourceType.USER_DEFINED

/**
 * [MethodClassGuesser] over a program, for any ABI: every unnamed function in the global namespace whose
 * convention takes `this` (`__thiscall`, or `__fastcall`, whose first argument comes in the same register),
 * off its callers' decompiled calls, against the classes [ClassHierarchyRecords] holds, their methods, the
 * objects their constructors build, and the member objects and bases their structs lay at an offset. Only a
 * method whose class is known counts ([hasKnownClass]), or one a class pass placed ([isPlacedByClassPass]), so
 * neither another guess (unless [trustGuesses]) nor `RecoverClassesFromRTTIScript`'s placements are evidence.
 * Each guess moves the function into its class, its convention then a method's ([fixMethodConvention]: a
 * `__fastcall` that takes nothing in EDX becomes a `__thiscall`), and leaves an Analysis bookmark saying where
 * it came from.
 *
 * With [trustGuesses], a guess is evidence too: the methods it guessed, in this run or an earlier one
 * ([isGuessedClass]), are decompiled as a known class's are, and it guesses again off their calls, round after round
 * until a round moves nothing, or [MAX_ROUNDS].
 */
class MethodClassPass(private val program: Program, sink: DiagnosticSink, private val trustGuesses: Boolean = false) :
    DiagnosticSink by sink {
    private val thisStorage = program.thisStorage()
    private val symbols = program.symbolTable

    /** Each recorded class, with its non-virtual base at offset 0, the one it shares its address with. */
    val bases by lazy {
        val records = program.readClassRecord().orEmpty()
        val classes = records.keys.mapNotNull { id ->
            (symbols.getSymbol(id)?.`object` as? GhidraClass)?.let { id to it }
        }.toMap()
        classes.map { (id, cls) ->
            val base = records.getValue(id).bases.firstOrNull { !it.isVirtual && (it.offset ?: 0L) == 0L }
            cls to base?.namespaceId?.let(classes::get)
        }.toMap()
    }

    /**
     * How many it moved, round by round. Only the evidence is decompiled: the recorded classes' methods and
     * constructors' callers, then, with [trustGuesses], the methods each round moved.
     */
    fun run(monitor: TaskMonitor): MethodClassResult {
        if (bases.isEmpty() || thisStorage == null) return MethodClassResult()
        val functions = program.functionManager.getFunctions(true).toList()
        val candidates = functions.filterTo(mutableSetOf()) { it.isCandidate() }
        if (candidates.isEmpty()) return MethodClassResult()
        val byId = bases.keys.associateBy { it.id }
        val recorded = functions.filterTo(mutableSetOf()) { program.isPlacedByClassPass(it) }
        val recordedCtors = recorded.filterTo(mutableSetOf()) {
            program.memberAttrs(it.entryPoint)?.structor == StructorRole.CONSTRUCTOR
        }
        // What counts as placed in its class: what a class pass placed, and, trusted, what an earlier run guessed.
        val trusted = recorded + functions.filter { trustGuesses && program.isGuessedClass(it) }
        val methods = functions.filter { it.hasKnownClass() || it in trusted }
            .mapNotNull { f -> byId[f.parentNamespace.id]?.let { f to it } }.toMap(mutableMapOf())
        // A constructor the debug info names goes by its class's name.
        val ctors = methods.filter { (f, cls) -> f in recordedCtors || (f.hasKnownClass() && f.name == cls.name) }
        monitor.message = "Finding constructors' callers"
        val evidence = methods.keys + ctors.keys.flatMap { it.getCallingFunctions(monitor) }
        return MethodClassResult(guessRounds(evidence, candidates, methods, ctors, trusted, monitor)).also { result ->
            if (trustGuesses) log("method-class-rounds", "$result: ${result.perRound.joinToString(", ")} per round")
        }
    }

    /**
     * Guesses off the calls [firstEvidence] makes, and with [trustGuesses] again off those the methods each round
     * moved, until one moves none of [candidates]: how many each round moved. [methods] and [known] grow by them.
     */
    private fun guessRounds(
        firstEvidence: Collection<Function>,
        candidates: MutableSet<Function>,
        methods: MutableMap<Function, GhidraClass>,
        ctors: Map<Function, GhidraClass>,
        trusted: Collection<Function>,
        monitor: TaskMonitor,
    ): List<Int> {
        var evidence = firstEvidence
        val known = trusted.toMutableSet()
        val calls = mutableListOf<ThisCall>()
        val perRound = mutableListOf<Int>()
        for (round in 1..(if (trustGuesses) MAX_ROUNDS else 1)) {
            if (evidence.isEmpty() || candidates.isEmpty()) break
            val what = if (round == 1) "methods and constructors' callers" else "guessed methods, round $round"
            program.decompileEach(evidence, monitor, "Decompiling $what") { f, high ->
                calls += thisCalls(f, high, ctors, methods[f]).filter { it.callee in candidates }
            }
            val guesses = MethodClassGuesser(bases, known).guess(calls.filter { it.callee in candidates })
            monitor.initialize(guesses.size.toLong(), "Moving methods into their guessed classes")
            val placed = guesses.filter { (f, guess) ->
                monitor.increment()
                place(f, guess, round)
            }
            if (placed.isEmpty()) break
            perRound += placed.size
            candidates -= placed.keys
            known += placed.keys
            placed.forEach { (f, guess) -> methods[f] = guess.cls }
            evidence = placed.keys
        }
        return perRound
    }

    /** An unnamed global function whose first argument comes in where `this` does ([takesThisAt]). */
    private fun Function.isCandidate() = parentNamespace.isGlobal && symbol.source == SourceType.DEFAULT &&
        !isThunk && takesThisAt(thisStorage)

    /**
     * The calls [f] makes on its own `this`, on objects it built with one of [ctors], and, where it's a method
     * of [own], on the object of a class [own]'s struct lays at an offset into `this` ([classAt]), decompiled as
     * [high].
     */
    private fun thisCalls(
        f: Function,
        high: HighFunction,
        ctors: Map<Function, GhidraClass>,
        own: GhidraClass?,
    ): List<ThisCall> {
        val self = f.argumentAt(f.thisIndex())
        val ops = high.pcodeOps.asSequence().toList()
        // The objects the function built, by where they point, from their constructor's argument and result.
        val built = buildMap {
            for (op in ops) {
                val ctor = op.directCallee() ?: continue
                val cls = ctors[ctor] ?: continue
                op.thisArgument(ctor)?.pointerInto()?.let { put(it, cls) }
                op.output?.pointerInto()?.let { put(it, cls) }
            }
        }
        return ops.mapNotNull { op ->
            val callee = op.directCallee() ?: return@mapNotNull null
            val obj = op.thisArgument(callee)?.pointerInto() ?: return@mapNotNull null
            when {
                !obj.isThis(self) -> built[obj]?.let { ThisCall(f, callee, it) }
                obj.offset == 0L -> ThisCall(f, callee)
                else -> own?.let { classAt(it, obj.offset) }?.let { ThisCall(f, callee, it) }
            }
        }
    }

    /** Each recorded class, by the id of its struct. */
    private val byStruct by lazy {
        bases.keys.mapNotNull { cls ->
            program.classStruct(cls)?.let { program.dataTypeManager.getID(it) to cls }
        }.toMap()
    }

    /**
     * The class whose struct [cls]'s lays at [offset], a member object or a base there, inside its `<Class>_data`
     * structs and its bases' too; null where none starts there.
     */
    private fun classAt(cls: GhidraClass, offset: Long): GhidraClass? {
        var struct: Structure = program.classStruct(cls) ?: return null
        var at = offset.toInt()
        repeat(MAX_NESTING) {
            val part = struct.getComponentContaining(at)?.takeIf { it.dataType is Structure } ?: return null
            val inner = part.dataType as Structure
            if (part.offset == at) byStruct[program.dataTypeManager.getID(inner)]?.let { return it }
            struct = inner
            at -= part.offset
        }
        return null
    }

    private fun PcodeOp.directCallee(): Function? {
        if (opcode != PcodeOp.CALL || numInputs < 2) return null
        val f = program.functionManager.getFunctionAt(getInput(0).address) ?: return null
        return f.getThunkedFunction(true) ?: f
    }

    /**
     * Moves [f] into its [guess]ed class, recorded as guessed ([recordGuessed]) and bookmarked as guessed in
     * [round], off guesses of its own after the first.
     */
    private fun place(f: Function, guess: MethodClassGuess, round: Int): Boolean = runCatching {
        f.parentNamespace = guess.cls
        f.fixMethodConvention(takesThis = true)
        program.recordGuessed(f)
        val off = if (round == 1) "objects of known class" else "objects of known or guessed class, round $round"
        program.bookmarkManager.setBookmark(
            f.entryPoint,
            BookmarkType.ANALYSIS,
            BOOKMARK,
            "Class guessed from ${guess.sites} call(s) on $off",
        )
    }.onFailure {
        warn("this-class-unplaced", "${f.name} -> ${guess.cls.getName(true)}: $it", f.entryPoint)
    }.isSuccess

    companion object {
        const val BOOKMARK = "Method class guess"

        /** How many rounds a run that trusts its guesses guesses at most. */
        const val MAX_ROUNDS = 16

        val TRUST_GUESSES = BoolOption(
            "Trust guessed method classes",
            "Count the methods it guessed the class of as evidence, as it does the ones a class pass placed, " +
                "and guess again off the calls they make, until nothing more moves",
            false,
        )

        /** How deep [classAt] looks into structs within structs. */
        private const val MAX_NESTING = 8
    }
}
