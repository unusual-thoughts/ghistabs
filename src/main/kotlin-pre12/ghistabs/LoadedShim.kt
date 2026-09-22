package ghistabs

import ghidra.app.util.opinion.Loaded
import ghidra.framework.model.DomainObject

/**
 * Pre-12: `Loaded` hands its object over carrying no reference of its own — the consumer was named
 * once, at import time. 12.0 moved that to extraction time, where `getDomainObject(consumer)` adds
 * the reference and the loaded object keeps its own until it is closed. This adds what the 12 call
 * takes for granted; a member wins over an extension, so 12+ uses Ghidra's own.
 *
 * In [ghistabs] rather than Ghidra's package because that is where the call site is: an extension is
 * only visible unqualified from the package that declares it.
 */
internal fun <T : DomainObject> Loaded<T>.getDomainObject(consumer: Any): T =
    domainObject.also { it.addConsumer(consumer) }
