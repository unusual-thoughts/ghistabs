package ghidrakt

import ghidra.program.model.gclass.ClassUtils
import kotlin.reflect.KClass

/** Before 12.1 `ClassUtils` has no vtable tag, and nothing reads one. */
@Suppress("UNUSED_PARAMETER", "UnusedParameter", "UnusedReceiverParameter")
fun KClass<ClassUtils>.createVxTableDescriptionOffsetTag(ptrOffsetInClass: Long): String? = null
