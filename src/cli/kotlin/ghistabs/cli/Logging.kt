package ghistabs.cli

import ghidra.program.model.address.Address
import ghidra.util.ErrorLogger
import ghidra.util.task.TaskMonitorAdapter
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.diagnose.color
import me.tongfei.progressbar.DelegatingProgressBarConsumer
import me.tongfei.progressbar.ProgressBarBuilder
import java.io.PrintStream
import java.io.Writer

/** Streams each diagnostic line at or above [minLevel] to [out], flushing so the log is live. */
class StreamSink(private val minLevel: Level, private val out: Writer) : DiagnosticSink {
    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        if (message == null || level < minLevel) return
        val at = address?.let { "[@$it]" } ?: ""
        out.append("[$level][$category]$at $message\n")
        out.flush()
    }
}

const val MSG_WIDTH = 60

class BarLoggerMonitorSink(
    private val minLevel: Level,
    private val barStream: PrintStream = System.err,
    private val logStream: PrintStream = System.out,
) : TaskMonitorAdapter(),
    ErrorLogger,
    DiagnosticSink {
    private var width = 0

    private val bar by lazy {
        ProgressBarBuilder().hideEta().setConsumer(
            DelegatingProgressBarConsumer {
                width = it.length
                barStream.append('\r' + it)
                barStream.flush()
            },
        ).build().setExtraMessage("Starting Ghidra...".padEnd(MSG_WIDTH))
    }

    private fun out(message: Any?) {
        logStream.append("\r${message.toString().trimEnd().padEnd(width)}\n")
        logStream.flush()
        bar.refresh()
    }

    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        if (message.isNullOrBlank() || level < minLevel) return
        val at = address?.let { "[@$it]" } ?: ""
        out("${level.color()}[\u001b[1m$category\u001b[22m]$at $message")
    }

    fun Throwable.exception() {
        message?.let { out(it) }
        printStackTrace(barStream)
    }

    fun logAtLevel(message: Any?, level: Level) {
        if (level >= minLevel) {
            out("${level.color()}$message")
        }
    }

    override fun debug(originator: Any?, message: Any?) = logAtLevel(message, Level.DEBUG)
    override fun debug(originator: Any?, message: Any?, throwable: Throwable?) {
        debug(originator, message)
        throwable?.exception()
    }

    override fun error(originator: Any?, message: Any?) = logAtLevel(message, Level.ERROR)
    override fun error(originator: Any?, message: Any?, throwable: Throwable?) {
        error(originator, message)
        throwable?.exception()
    }

    override fun info(originator: Any?, message: Any?) = logAtLevel(message, Level.INFO)
    override fun info(originator: Any?, message: Any?, throwable: Throwable?) {
        info(originator, message)
        if (throwable != null) {
            throwable.message?.let { out(it) }
            throwable.printStackTrace(barStream)
        }
    }

    override fun trace(originator: Any?, message: Any?) { }
    override fun trace(originator: Any?, message: Any?, throwable: Throwable?) { }

    override fun warn(originator: Any?, message: Any?) = logAtLevel(message, Level.WARN)
    override fun warn(originator: Any?, message: Any?, throwable: Throwable?) {
        warn(originator, message)
        throwable?.printStackTrace(barStream)
    }

    override fun getMessage(): String? = bar.extraMessage
    override fun setMessage(message: String?) {
        bar.setExtraMessage(message?.replace("\r", "")?.replace("\n", "")?.take(MSG_WIDTH)?.padEnd(MSG_WIDTH))
    }

    override fun getProgress() = bar.current
    override fun setProgress(to: Long) {
        bar.stepTo(to.coerceAtLeast(0))
    }
    override fun incrementProgress(count: Long) {
        bar.stepBy(count.coerceAtLeast(0))
    }

    fun Long.validMax() = when {
        this < 0 -> -1
        this == 0L -> 1
        else -> this
    }
    override fun initialize(max: Long) {
        bar.maxHint(max.validMax())
        bar.refresh()
        bar.stepTo(0)
    }

    override fun getMaximum() = bar.max
    override fun setMaximum(max: Long) {
        bar.maxHint(max.validMax())
    }

    override fun isIndeterminate() = bar.isIndefinite
    override fun setIndeterminate(ind: Boolean) {
        if (ind) {
            bar.maxHint(-1)
        }
    }

    override fun setShowProgressValue(show: Boolean) {
        if (!show) {
            bar.stepTo(0)
            bar.refresh()
        }
    }
}
