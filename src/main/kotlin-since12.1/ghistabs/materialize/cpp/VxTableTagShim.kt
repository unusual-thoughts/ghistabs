package ghistabs.materialize.cpp

import ghidra.program.model.gclass.ClassUtils

/** 12.1+: the description tag `ClassUtils.isVTable` recognises a table by. */
internal fun vxTableOffsetTag(ptrOffsetInClass: Long): String? =
    ClassUtils.createVxTableDescriptionOffsetTag(ptrOffsetInClass)
