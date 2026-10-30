package ghistabs.cpp.eh

import ghidra.program.model.data.*

/**
 * gcc's SJLJ exception ABI on 32-bit x86 (gcc 3.0 on): the `SjLj_Function_Context` a function with
 * landing pads registers, the unwinder's other types, and the signatures of its entry points.
 *
 * A type the program already has by name (from libgcc's stabs) is used as is; otherwise it is made
 * under [CATEGORY].
 */
class SjljAbi(private val dtm: DataTypeManager) {
    val word: DataType = typedef("_Unwind_Word", UnsignedIntegerDataType.dataType)
    val ptr: DataType = typedef("_Unwind_Ptr", UnsignedIntegerDataType.dataType)
    private val exceptionClass = typedef("_Unwind_Exception_Class", UnsignedLongLongDataType.dataType)

    val reasonCode: DataType = existing("_Unwind_Reason_Code") ?: resolve(
        EnumDataType(CATEGORY, "_Unwind_Reason_Code", 4, dtm).apply {
            REASON_CODES.forEachIndexed { i, name -> add(name, i.toLong()) }
        },
    )

    /** gcc's is an `int` with `#define`d flags; an enum of them reads `_UA_CLEANUP_PHASE | _UA_HANDLER_FRAME`. */
    private val action: DataType = existing("_Unwind_Action")?.takeIf { it.length == 4 } ?: resolve(
        EnumDataType(CATEGORY, "_Unwind_Action", 4, dtm).apply {
            ACTIONS.forEachIndexed { i, name -> add(name, 1L shl i) }
        },
    )

    // The three structs point at each other through the function types, so each is resolved empty
    // first, then filled.
    private val exceptionShell = existing("_Unwind_Exception") as? Structure
    val exception = exceptionShell ?: shell("_Unwind_Exception")

    private val functionContextShell = existing(CONTEXT) as? Structure

    /** The program's own context, or a new one; [functionContext] is it once it has a `jbuf`. */
    private val fc = functionContextShell ?: shell(CONTEXT)

    /** SJLJ's unwind context is the one pointer: `struct _Unwind_Context { struct SjLj_Function_Context *fc; }`. */
    val context = (existing("_Unwind_Context") as? Structure)
        ?: shell("_Unwind_Context").apply { add(pointer(fc), "fc", null) }

    private val cleanup = function(
        "_Unwind_Exception_Cleanup_Fn",
        VoidDataType.dataType,
        "reason" to reasonCode,
        "exc" to pointer(exception),
    )

    val personality: DataType = function(
        "_Unwind_Personality_Fn",
        reasonCode,
        "version" to IntegerDataType.dataType,
        "actions" to action,
        "exceptionClass" to exceptionClass,
        "ue_header" to pointer(exception),
        "context" to pointer(context),
    )

    val stop: DataType = function(
        "_Unwind_Stop_Fn",
        reasonCode,
        "version" to IntegerDataType.dataType,
        "actions" to action,
        "exceptionClass" to exceptionClass,
        "exceptionObject" to pointer(exception),
        "context" to pointer(context),
        "stop_parameter" to pointer(VoidDataType.dataType),
    )

    val trace: DataType = function(
        "_Unwind_Trace_Fn",
        reasonCode,
        "context" to pointer(context),
        "arg" to pointer(VoidDataType.dataType),
    )

    /**
     * The `__builtin_setjmp` buffer on i386: frame, receiver label, stack pointer. gcc 3.4 on reserves
     * 2 more unused words; these 3 are common to every version.
     */
    val jbuf: DataType = existing(JBUF) ?: resolve(
        StructureDataType(CATEGORY, JBUF, 0, dtm).apply {
            isPackingEnabled = true
            val void = pointer(VoidDataType.dataType)
            add(void, "frame", "the frame base locals count from, from which the receiver rebuilds %ebp")
            add(void, "resume", "the receiver, which dispatches on call_site to the landing pad")
            add(void, "stack", "%esp at the setup")
        },
    )

    init {
        if (exceptionShell == null) {
            exception.apply {
                add(exceptionClass, "exception_class", null)
                add(pointer(cleanup), "exception_cleanup", null)
                add(word, "private_1", null)
                add(word, "private_2", null)
                // `__attribute__((__aligned__))`, 16 on i386, pads gcc's to 32 bytes.
                explicitMinimumAlignment = EXCEPTION_ALIGN
            }
        }
    }

    /**
     * The context struct. stabs leave out its flexible `void *jbuf[]`, so a program's own one that ends
     * at `lsda` gets [jbuf] appended. Null when the program's one has some other layout.
     */
    val functionContext = when {
        functionContextShell == null -> fc.also(::fillContext)
        !isContextHead(fc) -> null
        fc.length == JBUF_OFFSET -> fc.also { it.add(jbuf, "jbuf", JBUF_COMMENT) }
        else -> fc.takeIf { it.length == JBUF_OFFSET + jbuf.length }
    }

    private fun fillContext(s: Structure) = s.apply {
        add(pointer(s), "prev", "the next older registered context")
        add(IntegerDataType.dataType, "call_site", "the LSDA call-site record in effect, from 1; 0 terminates, -1 none")
        add(ArrayDataType(word, DATA_WORDS, word.length, dtm), "data", "[0] the _Unwind_Exception, [1] the selector")
        add(pointer(personality), "personality", null)
        add(pointer(VoidDataType.dataType), "lsda", null)
        add(jbuf, "jbuf", JBUF_COMMENT)
    }

    private fun isContextHead(s: Structure) = s.length >= JBUF_OFFSET &&
        listOf(
            "prev" to 0,
            "call_site" to CALL_SITE_OFFSET,
            "data" to 8,
            "personality" to PERSONALITY_OFFSET,
            "lsda" to LSDA_OFFSET,
        )
            .all { (name, offset) ->
                s.getComponentAt(offset)?.let { it.fieldName == name && it.offset == offset } == true
            }

    /** A gcc EH entry point's signature by its C name, or null when [name] is none. */
    fun signature(name: String): Signature? = signatures[name]

    private val signatures: Map<String, Signature> by lazy {
        val exc = pointer(exception)
        val ctx = pointer(context)
        val fc = pointer(functionContext ?: VoidDataType.dataType)
        val void = VoidDataType.dataType
        val voidp = pointer(void)
        val int = IntegerDataType.dataType
        val personalityArgs = (personality as FunctionDefinition).arguments.map { it.name to it.dataType }
        buildMap {
            fun sig(name: String, ret: DataType, vararg args: Pair<String, DataType>, noReturn: Boolean = false) =
                put(name, Signature(ret, args.toList(), noReturn))
            sig(REGISTER, void, "fc" to fc)
            sig(UNREGISTER, void, "fc" to fc)
            sig("_Unwind_SjLj_RaiseException", reasonCode, "exc" to exc)
            sig(
                "_Unwind_SjLj_ForcedUnwind",
                reasonCode,
                "exc" to exc,
                "stop" to pointer(stop),
                "stop_argument" to voidp,
            )
            sig("_Unwind_SjLj_Resume", void, "exc" to exc, noReturn = true)
            sig("_Unwind_SjLj_Resume_or_Rethrow", reasonCode, "exc" to exc)
            sig("_Unwind_SjLj_SetContext", void, "fc" to fc)
            sig("_Unwind_SjLj_GetContext", fc)
            sig("_Unwind_DeleteException", void, "exc" to exc)
            sig("_Unwind_GetGR", word, "context" to ctx, "index" to int)
            sig("_Unwind_SetGR", void, "context" to ctx, "index" to int, "val" to word)
            sig("_Unwind_GetIP", ptr, "context" to ctx)
            sig("_Unwind_GetIPInfo", ptr, "context" to ctx, "ip_before_insn" to pointer(int))
            sig("_Unwind_SetIP", void, "context" to ctx, "val" to ptr)
            sig("_Unwind_GetCFA", word, "context" to ctx)
            sig("_Unwind_GetLanguageSpecificData", voidp, "context" to ctx)
            sig("_Unwind_GetRegionStart", ptr, "context" to ctx)
            sig("_Unwind_GetDataRelBase", ptr, "context" to ctx)
            sig("_Unwind_GetTextRelBase", ptr, "context" to ctx)
            sig("_Unwind_FindEnclosingFunction", voidp, "pc" to voidp)
            sig("_Unwind_Backtrace", reasonCode, "trace" to pointer(trace), "trace_argument" to voidp)
            for (name in PERSONALITIES) sig(name, reasonCode, *personalityArgs.toTypedArray())
            sig("__cxa_allocate_exception", voidp, "thrown_size" to UnsignedIntegerDataType.dataType)
            sig("__cxa_free_exception", void, "vptr" to voidp)
            sig("__cxa_throw", void, "obj" to voidp, "tinfo" to voidp, "dest" to voidp, noReturn = true)
            sig("__cxa_begin_catch", voidp, "exc_obj_in" to voidp)
            sig("__cxa_end_catch", void)
            sig("__cxa_rethrow", void, noReturn = true)
            sig("__cxa_call_unexpected", void, "exc_obj_in" to voidp, noReturn = true)
            sig("__cxa_get_exception_ptr", voidp, "exc_obj_in" to voidp)
        }
    }

    /** A return type, named parameters, and whether it never returns. */
    data class Signature(val ret: DataType, val params: List<Pair<String, DataType>>, val noReturn: Boolean)

    /** The program's [name], its own (from stabs) before one an earlier run made under [CATEGORY]. */
    private fun existing(name: String): DataType? = mutableListOf<DataType>()
        .also { dtm.findDataTypes(name, it) }
        .filter { it !is Pointer && it.name == name }
        .minByOrNull { it.categoryPath == CATEGORY }

    private fun resolve(dt: DataType) = dtm.resolve(dt, DataTypeConflictHandler.DEFAULT_HANDLER)

    private fun pointer(dt: DataType) = PointerDataType(dt, dtm)

    private fun shell(name: String) =
        resolve(StructureDataType(CATEGORY, name, 0, dtm).apply { isPackingEnabled = true }) as Structure

    private fun typedef(name: String, base: DataType) =
        existing(name) ?: resolve(TypedefDataType(CATEGORY, name, base, dtm))

    private fun function(name: String, ret: DataType, vararg args: Pair<String, DataType>) =
        (existing(name) as? FunctionDefinition) ?: resolve(
            FunctionDefinitionDataType(CATEGORY, name, dtm).apply {
                returnType = ret
                setArguments(*args.map { (n, t) -> ParameterDefinitionImpl(n, t, null) }.toTypedArray())
            },
        )

    companion object {
        val CATEGORY = CategoryPath("/libgcc")
        const val CONTEXT = "SjLj_Function_Context"
        const val JBUF = "SjLj_jbuf"

        /** The C++ personality routine gcc's SJLJ prologues store. */
        const val PERSONALITY = "__gxx_personality_sj0"
        const val REGISTER = "_Unwind_SjLj_Register"
        const val UNREGISTER = "_Unwind_SjLj_Unregister"

        /** The calls that push and pop a function's context on the thread's chain. */
        val REGISTRATION_CALLS = setOf(REGISTER, UNREGISTER)

        /** Offsets in the context of the slots a registering prologue stores, and of the call-site index. */
        const val CALL_SITE_OFFSET = 4
        const val PERSONALITY_OFFSET = 0x18
        const val LSDA_OFFSET = 0x1c
        const val JBUF_OFFSET = 0x20

        /** `jbuf[1]`, the receiver label, against the LSDA slot. */
        const val RESUME_FROM_LSDA = JBUF_OFFSET + 4 - LSDA_OFFSET

        private const val DATA_WORDS = 4
        private const val EXCEPTION_ALIGN = 16
        private const val JBUF_COMMENT = "__builtin_setjmp's buffer, declared void *jbuf[]"

        private val REASON_CODES = listOf(
            "_URC_NO_REASON", "_URC_FOREIGN_EXCEPTION_CAUGHT", "_URC_FATAL_PHASE2_ERROR", "_URC_FATAL_PHASE1_ERROR",
            "_URC_NORMAL_STOP", "_URC_END_OF_STACK", "_URC_HANDLER_FOUND", "_URC_INSTALL_CONTEXT",
            "_URC_CONTINUE_UNWIND",
        )
        private val ACTIONS =
            listOf("_UA_SEARCH_PHASE", "_UA_CLEANUP_PHASE", "_UA_HANDLER_FRAME", "_UA_FORCE_UNWIND", "_UA_END_OF_STACK")

        /** The SJLJ personality routines of C, C++, Java and Objective-C. */
        val PERSONALITIES = listOf(
            "__gcc_personality_sj0",
            PERSONALITY,
            "__gcj_personality_sj0",
            "__gnu_objc_personality_sj0",
        )
    }
}
