package ghistabs.harvest

import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.DummySink
import ghistabs.parse.*
import ghistabs.parse.TypeDecl.Struct.Base
import ghistabs.parse.TypeDecl.Struct.Field

typealias CollisionBucket = MutableSet<TypeDecl<GlobalTypeId>>
typealias NameBuckets = MutableMap<String, CollisionBucket>
typealias Collisions = MutableMap<GlobalTypeId, NameBuckets>

class TypeStore(
    private val byId: MutableMap<GlobalTypeId, Type> = mutableMapOf(),
    private val collisions: Collisions = mutableMapOf(),
    sink: DiagnosticSink = DummySink,
) : DiagnosticSink by sink {

    /**
     * Gather TypeAsts for every InlineDef in [sym]. The nested asts inherit the
     * enclosing declaration's source location.
     */
    fun hoistSymbolDefs(sym: Symbol, cu: SourceFile.CUSource) {
        fun TypeDecl<GlobalTypeId>.walk(): List<Type> = when (this) {
            // Emit the InlineDef ast AND recurse — gcc nests them (e.g. Method whose
            // return is an inline-defined Pointer-to-X). Without recursion the inner
            // ids are referenced but never registered → dangling Refs + false collisions.
            is TypeDecl.InlineDef -> listOf(
                Type(
                    cu,
                    id,
                    null,
                    inner,
                    declLine = sym.declLine,
                    declSourceFile = sym.sourceFile,
                ),
            ) + inner.walk()

            else -> children.flatMap { field -> field.flatMap { it.walk() } }
        }
        append(*sym.body.type.walk().toTypedArray())
    }

    /**
     * Accumulate asts with first-writer-wins on GlobalTypeId. XRef placeholders are replaced
     * by any concrete body. Collisions go into [collisions] for post-harvest classification —
     * no per-collision Ref-walking here (slow on template-heavy binaries);
     * `Harvest.classifyCollisions` runs once at the end against a memoized contentCache.
     */
    private fun append(vararg asts: Type) {
        val (colliding, good) = asts.partition { ast ->
            byId[ast.id]?.let { it.body is TypeDecl.XRef } == false
        }
        for ((id, incoming) in colliding.groupBy { it.id }) {
            val existing = byId[id]!!

            // `void:t(0,20)=(0,20)` and bare re-declarations parse as self-refs. They must never
            // shadow a concrete body: a real incoming supersedes a self-ref `ex` (box2d re-decl over
            // its real struct), and self-ref incomings are dropped when `ex` is already concrete. A
            // lone self-ref (no concrete body at this id) survives and resolves to void downstream.
            val incoming = incoming.filterNot { it.isSelfRef() }
            if (existing.isSelfRef()) {
                incoming.firstOrNull()?.let { byId[id] = it }
                continue
            }
            if (incoming.isEmpty()) continue

            // Name-promotion: an anonymous InlineDef ast can be superseded by an explicit
            // named Typedef at the same id. Range's `of` self-ref differs between forms so
            // we don't require body equality — both non-XRefTarget + existing unnamed.
            val namedIncoming = incoming.firstOrNull { it.name != null && !it.body.isXRefTarget }
            if (namedIncoming != null && existing.name == null && !existing.body.isXRefTarget) {
                byId[id] = namedIncoming
                continue
            }

            // Structural-equality skip (no Ref-walk): literal re-emissions aren't worth
            // recording. classifyCollisions does the deeper check for survivors.
            val alternates = incoming.filter { it.body != existing.body }.map { it.body }
            if (alternates.isEmpty()) continue
            val bucket = collisions
                .getOrPut(id) { mutableMapOf() }
                .getOrPut(existing.nameOrUnique) { mutableSetOf() }
            bucket.add(existing.body)
            bucket.addAll(alternates)
        }
        byId.putAll(good.map { it.id to it })
    }

    operator fun plusAssign(ast: Type) {
        append(ast)
    }

    /**
     * Recover gcc 12's malformed C++ inheritance emission. Instead of the documented
     * `!N,<bases>;` form, gcc 12 emits inheritance as a leading pseudo-field whose bitsize
     * is bytes×64 (a double byte→bit conversion bug; gdb itself crashes on these). Example:
     * `XMLText:T(0,81)=s112XMLNode:(0,25),0,6656;…` — XMLNode is 104B (832b) but stab says 6656.
     *
     * Detect via `field.sizeBits > struct.sizeBytes * 8` (real fields can't exceed their
     * enclosing struct), then move the field into `bases[]` and — if the Ref id is
     * dangling — synthesize an XRef-stub named after the field for cross-CU resolution.
     */
    private fun synthesizeXRefStubsForDanglingInheritanceRefs() {
        val synthetic = mutableListOf<Type>()
        // Outer struct id → its inheritance-pseudo-fields. Rewriting moves them to `bases`
        // so the materializer's BaseInsertionPlanner / firstPolymorphicBase / vtable wiring
        // sees the inheritance.
        val outerRewrites =
            mutableMapOf<GlobalTypeId, MutableList<Field<GlobalTypeId>>>()
        for (ast in byId.values) {
            val struct = ast.body as? TypeDecl.Struct ?: continue
            val structBits = struct.sizeBytes * 8
            for (field in struct.fields) {
                val ref = field.type as? TypeDecl.Ref ?: continue
                if (field.name.isEmpty()) continue
                if (field.sizeBits <= structBits) continue
                // Rewrite fires regardless of whether the Ref is bound — the bogus-bitsize
                // signal is independent of cross-CU resolution.
                outerRewrites.getOrPut(ast.id) { mutableListOf() }.add(field)
                // Stub only needed when the Ref has no binding (materializer resolves
                // bound Refs directly).
                if (ref.id in byId) continue
                synthetic.add(
                    ast.copy(
                        id = ref.id,
                        name = field.name,
                        body = TypeDecl.XRef(AggrKind.STRUCT, field.name),
                    ),
                )
            }
        }
        if (synthetic.isNotEmpty()) {
            log(
                "xref-stubs-synthesized",
                "${synthetic.size} inheritance-pseudo-field Refs → synthetic XRef stubs",
            )
            append(*synthetic.toTypedArray())
        }
        for ((outerId, pseudoFields) in outerRewrites) {
            val outer = byId[outerId] ?: continue
            val struct = outer.body as? TypeDecl.Struct ?: continue
            val pseudoSet = pseudoFields.toSet()
            val newBases = struct.bases + pseudoFields.map { f ->
                Base(type = f.type, isVirtual = false, access = Access.PUBLIC, offsetBits = f.offsetBits)
            }
            val newFields = struct.fields.filter { it !in pseudoSet }
            byId[outerId] = outer.copy(
                body = struct.copy(bases = newBases, fields = newFields),
            )
        }
        if (outerRewrites.isNotEmpty()) {
            log(
                "inheritance-pseudo-fields-promoted",
                "${outerRewrites.size} outer struct(s) rewritten to populate bases[]",
            )
        }
    }

    /**
     * Pure core of the `typedef struct {…} Name;` naming (see [nameAnonymousTypedefTargets]).
     * Returns `anonymous-aggregate-id → name` for every anonymous Struct/Enum that a typedef targets,
     * when **exactly one** typedef name claims it (ambiguous multi-name targets are left anonymous).
     * Two stab encodings qualify: the inline form `t3=4=s…` (`InlineDef`, gcc's usual for `typedef
     * struct {…} Name`) and the separate-then-reference form `t2=1` with `1=e…` (`Ref`, gcc's usual for
     * `typedef enum {…} Name`). Only genuinely anonymous targets (no tag) — a bare alias to an
     * already-named type is skipped by the target-name guard, and a builtin/pointer target by the kind
     * guard.
     */
    internal fun anonymousTypedefTargetNames(): Map<GlobalTypeId, String> {
        val namesByTarget = mutableMapOf<GlobalTypeId, MutableSet<String>>()
        for (td in byId.values) {
            val name = td.name?.ifEmpty { null } ?: continue
            val targetId = when (val body = td.body) {
                is TypeDecl.InlineDef -> body.id
                is TypeDecl.Ref -> body.id
                else -> continue
            }
            val target = byId[targetId] ?: continue
            if (!target.name.isNullOrEmpty()) continue
            if (target.body !is TypeDecl.Struct && target.body !is TypeDecl.Enum) continue
            namesByTarget.getOrPut(targetId) { mutableSetOf() }.add(name)
        }
        return namesByTarget.filterValues { it.size == 1 }.mapValues { it.value.single() }
    }

    /**
     * `typedef struct {…} Name;` reaches us as an anonymous aggregate + a same-named typedef that
     * inline-defines it. C-semantically the aggregate's name *is* the typedef's, so adopt it, so the
     * anonymous struct/enum carries the real name and [HarvestIndex.byLocation] can merge it with
     * the named copy from another header spelling (render-backlog §20).
     */
    private fun nameAnonymousTypedefTargets() {
        val renames = anonymousTypedefTargetNames()
        for ((id, name) in renames) byId[id] = byId.getValue(id).copy(name = name)
        if (renames.isNotEmpty()) debug("typedef-named-anon-aggregate", count = renames.size.toLong())
    }

    fun toHarvest(): Pair<Map<GlobalTypeId, Type>, Map<GlobalTypeId, Map<String, Set<TypeDecl<GlobalTypeId>>>>> {
        synthesizeXRefStubsForDanglingInheritanceRefs()
        nameAnonymousTypedefTargets()
        return byId to collisions
    }
}

/** A bare forward-declaration `name:t(cu,n)` parses as a Ref to its own id (gcc's explicit void
 *  `(x,y)=(x,y)` is a distinct TypeDecl.Void, caught at parser stage). */
private fun Type.isSelfRef() = body.let { it is TypeDecl.Ref && it.id == id }
