package ghistabs.builder

import ghidra.program.model.data.*
import ghistabs.importer.BookmarkSink
import ghistabs.parser.*

@JvmInline
value class ContentHash(
    val v: Long,
) {
    companion object {
        fun of(decl: TypeDecl): ContentHash = ContentHash(hashDecl(decl))

        private fun hashDecl(decl: TypeDecl): Long {
            var h = 0L
            h = h * 31 +
                when (decl) {
                    is TypeDecl.Ref -> 1L
                    is TypeDecl.Range -> 2L
                    is TypeDecl.Pointer -> 3L
                    is TypeDecl.Reference -> 4L
                    is TypeDecl.Const -> 5L
                    is TypeDecl.Volatile -> 6L
                    is TypeDecl.Array -> 7L
                    is TypeDecl.Enum -> 8L
                    is TypeDecl.Struct -> 9L
                    is TypeDecl.FunctionT -> 10L
                    is TypeDecl.Method -> 11L
                    is TypeDecl.Complex -> 12L
                    is TypeDecl.XRef -> 13L
                    is TypeDecl.WithSizeAttr -> 14L
                    is TypeDecl.InlineDef -> 15L
                    TypeDecl.Builtin -> 16L
                }

            h =
                when (decl) {
                    is TypeDecl.Ref -> {
                        h * 31 + decl.id.cu.toLong() * 31 + decl.id.n.toLong()
                    }

                    is TypeDecl.Range -> {
                        h * 31 + decl.of.cu.toLong() * 31 + decl.of.n.toLong() + decl.min.hashCode().toLong() * 31 +
                            decl.max.hashCode().toLong()
                    }

                    is TypeDecl.Pointer -> {
                        h * 31 + hashDecl(decl.pointee)
                    }

                    is TypeDecl.Reference -> {
                        h * 31 + hashDecl(decl.referent)
                    }

                    is TypeDecl.Const -> {
                        h * 31 + hashDecl(decl.inner)
                    }

                    is TypeDecl.Volatile -> {
                        h * 31 + hashDecl(decl.inner)
                    }

                    is TypeDecl.Array -> {
                        h * 31 + hashDecl(decl.element) + (decl.length?.hashCode()?.toLong() ?: 0L) +
                            (decl.indexType?.let { hashDecl(it) } ?: 0L)
                    }

                    is TypeDecl.Enum -> {
                        h * 31 + decl.members.fold(0L) { acc, p -> acc * 31 + p.first.hashCode().toLong() + p.second }
                    }

                    is TypeDecl.Struct -> {
                        h * 31 + decl.kind.hashCode().toLong() + decl.sizeBytes +
                            decl.fields.fold(0L) { acc, f -> acc * 31 + f.name.hashCode().toLong() + hashDecl(f.type) } +
                            decl.methods.fold(0L) { acc, m -> acc * 31 + m.name.hashCode().toLong() }
                    }

                    is TypeDecl.FunctionT -> {
                        h * 31 + hashDecl(decl.ret) + decl.params.fold(0L) { acc, p -> acc * 31 + hashDecl(p) }
                    }

                    is TypeDecl.Method -> {
                        h * 31 + hashDecl(decl.cls) + hashDecl(decl.ret) +
                            decl.params.fold(0L) { acc, p -> acc * 31 + hashDecl(p) }
                    }

                    is TypeDecl.Complex -> {
                        h * 31 + decl.rCode.toLong() + decl.sizeBytes.toLong()
                    }

                    is TypeDecl.XRef -> {
                        h * 31 + decl.kind.hashCode().toLong() + decl.tagName.hashCode().toLong()
                    }

                    is TypeDecl.WithSizeAttr -> {
                        h * 31 + decl.sizeBits.toLong() + hashDecl(decl.inner)
                    }

                    is TypeDecl.InlineDef -> {
                        h * 31 + decl.id.cu.toLong() * 31 + decl.id.n.toLong() + hashDecl(decl.body)
                    }

                    TypeDecl.Builtin -> {
                        h
                    }
                }
            return h
        }
    }
}

data class TypeAst(
    val id: TypeId,
    val name: String,
    val body: TypeDecl,
    val cuFile: String,
)

class TypeRegistry(
    private val dtm: DataTypeManager,
    private val sink: BookmarkSink,
) {
    private val byId: MutableMap<TypeId, DataType> = mutableMapOf()
    private val byHash: MutableMap<Pair<String, ContentHash>, DataType> = mutableMapOf()
    private val conflictCount: MutableMap<String, Int> = mutableMapOf()

    fun materialiseAll(
        asts: List<TypeAst>,
        attribution: (String, Set<String>) -> CategoryPath = { name, cus -> Attribution.categoryFor(name, cus) },
    ) {
        val byName = asts.groupBy { it.name }
        for (ast in asts) {
            resolve(ast, byName, attribution)
        }
    }

    fun dataTypeFor(decl: TypeDecl): DataType? =
        when (decl) {
            is TypeDecl.Ref -> {
                byId[decl.id]
            }

            is TypeDecl.InlineDef -> {
                byId[decl.id] ?: dataTypeFor(decl.body)
            }

            is TypeDecl.Builtin, is TypeDecl.Range, is TypeDecl.Complex, is TypeDecl.WithSizeAttr -> {
                BuiltinTable.resolve(decl, dtm)
            }

            is TypeDecl.Pointer -> {
                val inner = dataTypeFor(decl.pointee)
                PointerDataType(inner ?: Undefined4DataType.dataType, 4, dtm)
            }

            is TypeDecl.Reference -> {
                val inner = dataTypeFor(decl.referent)
                PointerDataType(inner ?: Undefined4DataType.dataType, 4, dtm)
            }

            is TypeDecl.Const -> {
                dataTypeFor(decl.inner)
            }

            is TypeDecl.Volatile -> {
                dataTypeFor(decl.inner)
            }

            is TypeDecl.Array -> {
                val elem = dataTypeFor(decl.element) ?: return null
                ArrayDataType(elem, (decl.length ?: 0L).toInt().coerceAtLeast(0), elem.length)
            }

            else -> {
                null
            } // Struct, Enum, FunctionT, Method, XRef must have been registered via materialiseAll
        }

    private fun resolve(
        ast: TypeAst,
        byName: Map<String, List<TypeAst>>,
        attribution: (String, Set<String>) -> CategoryPath,
    ): DataType {
        // 1. Check if already resolved
        byId[ast.id]?.let { return it }

        // 2. Compute content hash
        val hash = ContentHash.of(ast.body)

        // 3. Check for cross-CU dedup
        val hashKey = ast.name to hash
        byHash[hashKey]?.let { existing ->
            byId[ast.id] = existing
            return existing
        }

        // 4. Compute category
        val definingCUs = byName[ast.name]?.map { it.cuFile }?.toSet() ?: setOf(ast.cuFile)
        val category = attribution(ast.name, definingCUs)

        // 5. Create placeholder (struct/union for aggregates, struct for others)
        val placeholder =
            when (ast.body) {
                is TypeDecl.Struct -> {
                    if (ast.body.kind == AggrKind.UNION) {
                        UnionDataType(category, ast.name, dtm)
                    } else {
                        StructureDataType(category, ast.name, 0, dtm)
                    }
                }

                else -> {
                    StructureDataType(category, ast.name, 0, dtm)
                }
            }

        // 6. Register placeholder BEFORE recursing
        byId[ast.id] = placeholder

        // 7. Materialise body
        val materialised = materialiseBody(ast, category, placeholder)

        // 8. Update byId if materialised is different
        if (materialised !== placeholder) {
            byId[ast.id] = materialised
        }

        // 9. Add to DTM
        try {
            dtm.addDataType(materialised, DataTypeConflictHandler.KEEP_HANDLER)
        } catch (e: Exception) {
            sink.log("dtm-add-error", "Failed to add ${ast.name} to DTM: ${e.message}")
        }

        // 10. Register in byHash
        val finalName = materialised.name
        val finalCat = materialised.categoryPath.toString()
        byHash[ast.name to hash] = materialised

        return materialised
    }

    private fun materialiseBody(
        ast: TypeAst,
        category: CategoryPath,
        placeholder: DataType,
    ): DataType =
        when (val body = ast.body) {
            is TypeDecl.Builtin, is TypeDecl.Range, is TypeDecl.Complex, is TypeDecl.WithSizeAttr -> {
                BuiltinTable.resolve(body, dtm) ?: placeholder
            }

            is TypeDecl.Pointer -> {
                val inner = dataTypeFor(body.pointee)
                PointerDataType(inner ?: Undefined4DataType.dataType, 4, dtm)
            }

            is TypeDecl.Reference -> {
                val inner = dataTypeFor(body.referent)
                PointerDataType(inner ?: Undefined4DataType.dataType, 4, dtm)
            }

            is TypeDecl.Const -> {
                dataTypeFor(body.inner) ?: placeholder
            }

            is TypeDecl.Volatile -> {
                dataTypeFor(body.inner) ?: placeholder
            }

            is TypeDecl.InlineDef -> {
                dataTypeFor(body.body) ?: placeholder
            }

            is TypeDecl.Array -> {
                val elem = dataTypeFor(body.element) ?: Undefined4DataType.dataType
                ArrayDataType(elem, (body.length ?: 0L).toInt().coerceAtLeast(0), elem.length)
            }

            is TypeDecl.Enum -> {
                val sizeBytes = 4 // GCC default
                val e = EnumDataType(category, ast.name, sizeBytes, dtm)
                for ((mname, mval) in body.members) {
                    e.add(mname, mval)
                }
                e
            }

            is TypeDecl.Struct -> {
                // Use the appropriate type (struct or union)
                var struct: Composite =
                    if (body.kind == AggrKind.UNION) {
                        UnionDataType(category, ast.name, dtm)
                    } else {
                        placeholder as StructureDataType
                    }

                for (field in body.fields) {
                    if (field.isStatic) continue // Skip static fields
                    val ft = dataTypeFor(field.type) ?: Undefined4DataType.dataType
                    val len = if (ft.length <= 0) 4 else ft.length
                    try {
                        if (struct is Structure) {
                            struct.replaceAtOffset((field.offsetBits / 8).toInt(), ft, len, field.name, null)
                        } else if (struct is Union) {
                            (struct as Union).add(ft, field.name, null)
                        }
                    } catch (e: Exception) {
                        sink.log("field-layout", "Failed to add field '${field.name}' to '${ast.name}': ${e.message}")
                    }
                }
                struct
            }

            is TypeDecl.FunctionT -> {
                val fd = FunctionDefinitionDataType(category, ast.name, dtm)
                fd.setReturnType(dataTypeFor(body.ret) ?: VoidDataType())
                val params =
                    body.params
                        .mapIndexed { i, p ->
                            ParameterDefinitionImpl("arg$i", dataTypeFor(p) ?: Undefined4DataType.dataType, null)
                        }.toTypedArray()
                fd.setArguments(*params)
                fd
            }

            is TypeDecl.Method -> {
                val fd = FunctionDefinitionDataType(category, ast.name, dtm)
                fd.setReturnType(dataTypeFor(body.ret) ?: VoidDataType())
                val thisParam = ParameterDefinitionImpl("this", dataTypeFor(body.cls) ?: Undefined4DataType.dataType, null)
                val otherParams =
                    body.params.mapIndexed { i, p ->
                        ParameterDefinitionImpl("arg$i", dataTypeFor(p) ?: Undefined4DataType.dataType, null)
                    }
                fd.setArguments(*(listOf(thisParam) + otherParams).toTypedArray())
                fd
            }

            is TypeDecl.XRef -> {
                sink.log("xref-stub", "Forward ref to '${body.tagName}'; materialising stub")
                placeholder
            }

            is TypeDecl.Ref -> {
                // Back-reference — should already be in byId from a prior resolve
                byId[body.id] ?: run {
                    sink.log("dangling-ref", "Dangling ref to (${body.id.cu},${body.id.n}) in '${ast.name}'")
                    Undefined4DataType.dataType
                }
            }
        }

    private fun registerWithConflict(
        dt: DataType,
        name: String,
        hash: ContentHash,
        cuPath: String,
    ): DataType {
        // Not used in this version; we use DTM's KEEP_HANDLER instead
        return dt
    }
}
