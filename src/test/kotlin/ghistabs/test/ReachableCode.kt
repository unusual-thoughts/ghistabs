package ghistabs.test

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.util.Textifier
import org.objectweb.asm.util.TraceMethodVisitor

/**
 * The bytecode a call graph can execute, method by method, read with Ghidra's own copy of ASM. Only
 * classes loaded from a directory are walked, which is this project's output: Ghidra's jars and the JDK
 * are pinned by version elsewhere.
 *
 * It is a rapid type analysis. A static or special call reaches the method it names; a virtual one also
 * reaches each override in a class the graph instantiates, so a call to an interface reaches the
 * implementations that can actually be on the other end. Library code calls back into ours too (Ghidra
 * calls a `DataType`'s methods, a `HashMap` calls `hashCode`), so an instantiated class also reaches
 * every method it overrides from a supertype outside the project. Class initializers run on first
 * use of a class. Methods in [excluded] are never entered.
 */
internal class ReachableCode(private val loader: ClassLoader, private val excluded: Set<Ref>) {
    /** A method, in internal (`a/b/C`) and descriptor form. */
    data class Ref(val owner: String, val name: String, val desc: String)

    private val nodes = mutableMapOf<String, ClassNode?>()
    private val libraryMethods = mutableMapOf<String, Set<String>>()

    private val pending = ArrayDeque<Pair<ClassNode, MethodNode>>()
    private val visited = mutableSetOf<Ref>()
    private val initialized = mutableSetOf<String>()
    private val instantiated = mutableSetOf<String>()
    private val virtualCalls = mutableSetOf<Ref>()

    /** Text per reached class header and method, keyed and so ordered by what it describes. */
    private val texts = sortedMapOf<String, String>()

    /** Internal names of the classes the walk reached. */
    val classes: Set<String> get() = initialized

    /** The methods the walk reached, as `owner.name(desc)`. */
    val methods: Set<String> get() = texts.keys.filterTo(sortedSetOf()) { '(' in it }

    /** Everything reached, as one text to hash. */
    fun text() = texts.entries.joinToString("\n") { (key, text) -> "$key\n$text" }

    /** [type] constructed from outside the walk, as Ghidra constructs the analyzers it discovers. */
    fun instantiatedExternally(type: Class<*>) {
        val name = Type.getInternalName(type)
        node(name)?.methods?.filter { it.name == "<init>" }?.forEach { reach(Ref(name, it.name, it.desc)) }
        instantiate(name)
        drain()
    }

    /** Every method of [type] called [name], as an entry point. */
    fun calledExternally(type: Class<*>, name: String) {
        val owner = Type.getInternalName(type)
        initialize(owner)
        node(owner)?.methods?.filter { it.name == name }?.forEach { reach(Ref(owner, it.name, it.desc)) }
        drain()
    }

    private fun node(name: String): ClassNode? = nodes.getOrPut(name) {
        // SKIP_DEBUG: line numbers and local names would make a moved comment a different method.
        loader.getResource("$name.class")?.takeIf { it.protocol == "file" }?.openStream()?.use { input ->
            ClassNode().also { ClassReader(readable(input.readBytes())).accept(it, ClassReader.SKIP_DEBUG) }
        }
    }

    /**
     * [bytes] relabelled as the newest class file version Ghidra's ASM reads, which can trail the JDK
     * the project compiles for: nothing the compiler emits for us has changed shape since.
     */
    private fun readable(bytes: ByteArray) = bytes.also {
        val major = (it[6].toInt() and 0xff shl 8) or (it[7].toInt() and 0xff)
        if (major > ASM_MAX_MAJOR) {
            it[6] = (ASM_MAX_MAJOR shr 8).toByte()
            it[7] = ASM_MAX_MAJOR.toByte()
        }
    }

    private fun drain() {
        while (pending.isNotEmpty()) {
            val (owner, method) = pending.removeFirst()
            texts["${owner.name}.${method.name}${method.desc}"] = method.text()
            method.instructions.forEach { insn ->
                when (insn) {
                    is MethodInsnNode -> call(insn.opcode, Ref(insn.owner, insn.name, insn.desc))
                    is FieldInsnNode -> initialize(insn.owner)
                    is TypeInsnNode -> if (insn.opcode == Opcodes.NEW) instantiate(insn.desc)
                    is InvokeDynamicInsnNode -> insn.bsmArgs.filterIsInstance<Handle>().forEach(::handle)
                    is LdcInsnNode -> (insn.cst as? Handle)?.let(::handle)
                }
            }
        }
    }

    private fun handle(handle: Handle) {
        val ref = Ref(handle.owner, handle.name, handle.desc)
        when (handle.tag) {
            Opcodes.H_INVOKEVIRTUAL, Opcodes.H_INVOKEINTERFACE -> call(Opcodes.INVOKEVIRTUAL, ref)
            Opcodes.H_NEWINVOKESPECIAL -> instantiate(handle.owner).also { call(Opcodes.INVOKESPECIAL, ref) }
            Opcodes.H_INVOKESTATIC, Opcodes.H_INVOKESPECIAL -> call(Opcodes.INVOKESPECIAL, ref)
            else -> initialize(handle.owner) // a field handle
        }
    }

    private fun call(opcode: Int, ref: Ref) {
        initialize(ref.owner)
        resolve(ref.owner, ref.name, ref.desc)
        if (opcode == Opcodes.INVOKEVIRTUAL || opcode == Opcodes.INVOKEINTERFACE) {
            if (virtualCalls.add(ref)) {
                instantiated.filter { isSubtype(it, ref.owner) }.forEach { resolve(it, ref.name, ref.desc) }
            }
        }
    }

    /** The implementation [type] has of [name] and [desc]: its own, a superclass's, else a default method. */
    private fun resolve(type: String, name: String, desc: String) {
        var current: String? = type
        while (current != null) {
            val node = node(current) ?: return
            if (node.methods.any { it.name == name && it.desc == desc }) return reach(Ref(current, name, desc))
            current = node.superName
        }
        projectAncestors(type).forEach { ancestor ->
            node(ancestor)?.methods?.firstOrNull { it.name == name && it.desc == desc && !it.isAbstract }
                ?.let { reach(Ref(ancestor, name, desc)) }
        }
    }

    private fun reach(ref: Ref) {
        if (ref in excluded || !visited.add(ref)) return
        val node = node(ref.owner) ?: return
        val method = node.methods.firstOrNull { it.name == ref.name && it.desc == ref.desc } ?: return
        if (!method.isAbstract) pending += node to method
    }

    private fun initialize(type: String) {
        val node = node(type) ?: return
        if (!initialized.add(type)) return
        texts[type] = "extends ${node.superName} implements ${node.interfaces.sorted()}"
        node.superName?.let(::initialize)
        node.methods.firstOrNull { it.name == "<clinit>" }?.let { reach(Ref(type, it.name, it.desc)) }
    }

    private fun instantiate(type: String) {
        if (node(type) == null || !instantiated.add(type)) return
        initialize(type)
        virtualCalls.filter { isSubtype(type, it.owner) }.forEach { resolve(type, it.name, it.desc) }
        val callbacks = libraryAncestors(type).flatMapTo(mutableSetOf(), ::libraryMethodsOf)
        projectAncestors(type).forEach { ancestor ->
            node(ancestor)?.methods
                ?.filter { it.access and Opcodes.ACC_STATIC == 0 && "${it.name}${it.desc}" in callbacks }
                ?.forEach { resolve(type, it.name, it.desc) }
        }
    }

    /** [type] and every supertype the project built, interfaces included. */
    private fun projectAncestors(type: String): Set<String> = buildSet {
        val queue = ArrayDeque(listOf(type))
        while (queue.isNotEmpty()) {
            val node = node(queue.removeFirst()) ?: continue
            if (add(node.name)) queue += listOfNotNull(node.superName) + node.interfaces
        }
    }

    /** The supertypes outside the project that [type]'s own supertypes name directly. */
    private fun libraryAncestors(type: String) = projectAncestors(type)
        .flatMap { listOfNotNull(node(it)?.superName) + node(it)?.interfaces.orEmpty() }
        .filter { node(it) == null }
        .toSet()

    /** Name-and-descriptor of every instance method [type] (a library class) declares or inherits. */
    private fun libraryMethodsOf(type: String): Set<String> = libraryMethods.getOrPut(type) {
        val loaded = runCatching { Class.forName(type.replace('/', '.'), false, loader) }.getOrNull()
            ?: return@getOrPut emptySet()
        generateSequence(loaded) { it.superclass }
            .flatMap { it.declaredMethods.asSequence() }
            .plus(loaded.methods)
            .map { "${it.name}${Type.getMethodDescriptor(it)}" }
            .toSet()
    }

    private fun isSubtype(type: String, of: String): Boolean {
        val ancestors = projectAncestors(type)
        if (of in ancestors) return true
        val target = runCatching { Class.forName(of.replace('/', '.'), false, loader) }.getOrNull() ?: return false
        return libraryAncestors(type).any { ancestor ->
            runCatching { target.isAssignableFrom(Class.forName(ancestor.replace('/', '.'), false, loader)) }
                .getOrDefault(true)
        }
    }

    private companion object {
        /** `Opcodes.V23`, spelled out because older Ghidras ship an ASM without the constant. */
        const val ASM_MAX_MAJOR = 67
    }

    private val MethodNode.isAbstract get() = access and Opcodes.ACC_ABSTRACT != 0

    private fun MethodNode.text(): String {
        val printer = Textifier()
        accept(TraceMethodVisitor(printer))
        return printer.text.joinToString("")
    }
}
