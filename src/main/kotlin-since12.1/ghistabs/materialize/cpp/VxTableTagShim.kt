package ghistabs.materialize.cpp

import ghidra.program.model.gclass.ClassUtils
import kotlin.reflect.KClass

/** 12.1+: the description tag `ClassUtils.isVTable` recognises a table by. */
@Suppress("UnusedReceiverParameter")
internal fun KClass<ClassUtils>.createVxTableDescriptionOffsetTag(ptrOffsetInClass: Long): String? =
    ClassUtils.createVxTableDescriptionOffsetTag(ptrOffsetInClass)
