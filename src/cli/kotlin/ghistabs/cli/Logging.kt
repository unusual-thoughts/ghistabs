package ghistabs.cli

import com.github.ajalt.mordant.animation.animation
import com.github.ajalt.mordant.animation.asRefreshable
import com.github.ajalt.mordant.animation.progress.MultiProgressBarAnimation
import com.github.ajalt.mordant.animation.progress.advance
import com.github.ajalt.mordant.animation.progress.animateOnThread
import com.github.ajalt.mordant.animation.progress.execute
import com.github.ajalt.mordant.rendering.OverflowWrap
import com.github.ajalt.mordant.rendering.TextAlign
import com.github.ajalt.mordant.rendering.TextColors.*
import com.github.ajalt.mordant.rendering.TextStyle
import com.github.ajalt.mordant.rendering.TextStyles.bold
import com.github.ajalt.mordant.rendering.TextStyles.dim
import com.github.ajalt.mordant.rendering.Whitespace
import com.github.ajalt.mordant.table.ColumnWidth
import com.github.ajalt.mordant.terminal.Terminal
import com.github.ajalt.mordant.widgets.Text
import com.github.ajalt.mordant.widgets.progress.*
import ghidra.program.model.address.Address
import ghidra.util.ErrorLogger
import ghidra.util.task.TaskMonitorAdapter
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
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

private const val BAR_WIDTH = 24

/** Level tag style paired with the body style, mirroring the old hand-rolled SGR pairs. */
private val Level.styles get() = when (this) {
    Level.DEBUG -> (bold + brightBlue) to (dim + white)
    Level.INFO -> (bold + brightGreen) to TextStyle()
    Level.WARN -> (bold + brightYellow) to yellow
    Level.ERROR -> (bold + brightRed) to red
}

/** Ghidra reports indeterminate work as a non-positive maximum; mordant spells that `null`. */
private fun Long.orIndeterminate() = takeIf { it > 0 }

/**
 * Ghidra's [TaskMonitorAdapter] and our [DiagnosticSink] rendered as one mordant progress bar. Log
 * lines print through the same [Terminal] as the animation, whose interceptor clears and redraws the
 * bar around them — no cursor bookkeeping here — and downgrades the styles when stdout isn't a tty.
 */
class BarLoggerMonitorSink(private val minLevel: Level, private val terminal: Terminal = Terminal()) :
    TaskMonitorAdapter(),
    ErrorLogger,
    DiagnosticSink {
    // The message takes whatever the fixed cells leave, ellipsized rather than wrapped: a second line
    // would need cursor moves to redraw, which the terminal may not have.
    private val layout = progressBarContextLayout {
        cell(ColumnWidth.Expand(), align = TextAlign.LEFT) {
            Text(context, whitespace = Whitespace.PRE, overflowWrap = OverflowWrap.ELLIPSES)
        }
        percentage()
        progressBar(width = BAR_WIDTH)
        completed()
        timeElapsed()
    }

    // Only a holder for the task state (completed, total, elapsed): its own refresh() is never called.
    private val bar = MultiProgressBarAnimation(terminal).addTask(layout, total = null, context = "Starting Ghidra...")

    /**
     * The bar is drawn from [bar]'s state by hand rather than by [MultiProgressBarAnimation.refresh],
     * whose every refresh past `completed == total` ends in `Animation.stop()` — and stop prints a
     * newline, so a phase resting at 100% scrolls a frame per refresh. Ghidra completes phase after
     * phase on one monitor, so that is most of them. Nothing here ever declares itself finished; the
     * animation runs until [stop].
     */
    private val animator = terminal.animation<Unit> { MultiProgressBarWidgetMaker.build(layout to bar.makeState()) }
        .asRefreshable { false }
        .animateOnThread(terminal)

    // Non-interactive output gets no interceptor, so a running animation would push a frame per
    // refresh down the pipe. Leaving it unstarted makes the updates invisible instead.
    init {
        active = this
        if (terminal.terminalInfo.outputInteractive) animator.execute()
    }

    fun stop() = animator.stop()

    /** Where [BarSinkAppender] sends Ghidra's log4j events; log4j builds it, so it can't be injected. */
    companion object {
        @Volatile
        internal var active: BarLoggerMonitorSink? = null
    }

    private fun out(level: Level, prefix: String, message: Any?) {
        val (tag, body) = level.styles
        terminal.println(
            "${tag(level.name.take(1))} $prefix${body(message.toString().trimEnd())}",
            whitespace = Whitespace.PRE,
        )
    }

    override fun log(category: String, message: String?, level: Level, address: Address?, count: Long) {
        if (message.isNullOrBlank() || level < minLevel) return
        val at = address?.let { green(" @$it") }.orEmpty()
        out(level, "${bold("[$category]")}$at ", message)
    }

    fun Throwable.exception(level: Level) {
        message?.let { out(level, "", it) }
        terminal.println(stackTraceToString(), whitespace = Whitespace.PRE)
    }

    fun logAtLevel(message: Any?, level: Level) {
        if (level >= minLevel) out(level, "", message)
    }

    override fun debug(originator: Any?, message: Any?) = logAtLevel(message, Level.DEBUG)
    override fun debug(originator: Any?, message: Any?, throwable: Throwable?) {
        debug(originator, message)
        throwable?.exception(Level.DEBUG)
    }

    override fun error(originator: Any?, message: Any?) = logAtLevel(message, Level.ERROR)
    override fun error(originator: Any?, message: Any?, throwable: Throwable?) {
        error(originator, message)
        throwable?.exception(Level.ERROR)
    }

    override fun info(originator: Any?, message: Any?) = logAtLevel(message, Level.INFO)
    override fun info(originator: Any?, message: Any?, throwable: Throwable?) {
        info(originator, message)
        throwable?.exception(Level.INFO)
    }

    override fun trace(originator: Any?, message: Any?) { }
    override fun trace(originator: Any?, message: Any?, throwable: Throwable?) { }

    override fun warn(originator: Any?, message: Any?) = logAtLevel(message, Level.WARN)
    override fun warn(originator: Any?, message: Any?, throwable: Throwable?) {
        warn(originator, message)
        throwable?.exception(Level.WARN)
    }

    override fun getMessage() = bar.context
    override fun setMessage(message: String?) = bar.update {
        context = message.orEmpty().replace("\r", "").replace("\n", "")
    }

    override fun getProgress() = bar.completed
    override fun setProgress(to: Long) = bar.update { completed = to.coerceAtLeast(0) }
    override fun incrementProgress(count: Long) = bar.advance(count.coerceAtLeast(0))

    override fun initialize(max: Long) = bar.update {
        total = max.orIndeterminate()
        completed = 0
    }

    override fun getMaximum() = bar.total ?: 0
    override fun setMaximum(max: Long) = bar.update { total = max.orIndeterminate() }

    override fun isIndeterminate() = bar.total == null
    override fun setIndeterminate(ind: Boolean) {
        if (ind) bar.update { total = null }
    }

    override fun setShowProgressValue(show: Boolean) {
        if (!show) bar.update { completed = 0 }
    }
}
