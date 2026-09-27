package ghistabs.materialize.cpp

/** Before 12.1 `ClassUtils` has no vtable tag, and nothing reads one. */
@Suppress("UNUSED_PARAMETER")
internal fun vxTableOffsetTag(ptrOffsetInClass: Long): String? = null
