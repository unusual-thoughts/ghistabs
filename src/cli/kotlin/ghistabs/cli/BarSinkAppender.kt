package ghistabs.cli

import ghistabs.diagnose.Level
import org.apache.logging.log4j.core.Appender
import org.apache.logging.log4j.core.Core
import org.apache.logging.log4j.core.Filter
import org.apache.logging.log4j.core.LogEvent
import org.apache.logging.log4j.core.appender.AbstractAppender
import org.apache.logging.log4j.core.config.Property
import org.apache.logging.log4j.core.config.plugins.Plugin
import org.apache.logging.log4j.core.config.plugins.PluginAttribute
import org.apache.logging.log4j.core.config.plugins.PluginElement
import org.apache.logging.log4j.core.config.plugins.PluginFactory
import org.apache.logging.log4j.Level as Log4jLevel

/** Log4j's own scale, mapped onto ours: FATAL/ERROR, WARN, INFO, everything quieter is DEBUG. */
private fun Log4jLevel.toDiagnostic() = when {
    intLevel() <= Log4jLevel.ERROR.intLevel() -> Level.ERROR
    intLevel() <= Log4jLevel.WARN.intLevel() -> Level.WARN
    intLevel() <= Log4jLevel.INFO.intLevel() -> Level.INFO
    else -> Level.DEBUG
}

/**
 * Ghidra configures log4j itself during `Application.initializeApplication`, and its console appender
 * writes straight to `System.out` — outside the [com.github.ajalt.mordant.terminal.Terminal] the
 * progress animation redraws through, so each such line strands a bar frame on screen. Ghidra's
 * `LoggingInitialization` resolves `-Dlog4j.configurationFile` against the classpath first, so the
 * launcher points it at `ghistabs-log4j2.xml`, which swaps that console appender for this one and
 * routes the events into [BarLoggerMonitorSink] (which also applies `--log-level`).
 *
 * Events logged before the sink exists have nowhere to go and are dropped.
 */
@Plugin(name = "BarSink", category = Core.CATEGORY_NAME, elementType = Appender.ELEMENT_TYPE)
class BarSinkAppender private constructor(name: String, filter: Filter?) :
    AbstractAppender(name, filter, null, true, Property.EMPTY_ARRAY) {
    override fun append(event: LogEvent) {
        val sink = BarLoggerMonitorSink.active ?: return
        val logger = event.loggerName?.substringAfterLast('.').orEmpty()
        sink.logAtLevel("${event.message.formattedMessage} ($logger)", event.level.toDiagnostic())
        event.thrown?.let { sink.run { it.exception(event.level.toDiagnostic()) } }
    }

    companion object {
        @JvmStatic
        @PluginFactory
        fun createAppender(@PluginAttribute("name") name: String, @PluginElement("Filter") filter: Filter?) =
            BarSinkAppender(name, filter)
    }
}
