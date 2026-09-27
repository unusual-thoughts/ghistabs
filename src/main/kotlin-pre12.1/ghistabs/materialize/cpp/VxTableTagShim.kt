package ghistabs.materialize.cpp

import ghidra.program.model.gclass.ClassUtils
import kotlin.reflect.KClass

/** Before 12.1 `ClassUtils` has no vtable tag, and nothing reads one. */
@Suppress("UNUSED_PARAMETER", "UnusedParameter", "UnusedReceiverParameter")
internal fun KClass<ClassUtils>.createVxTableDescriptionOffsetTag(ptrOffsetInClass: Long): String? = null
