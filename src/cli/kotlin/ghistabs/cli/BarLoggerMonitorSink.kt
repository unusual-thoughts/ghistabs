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
import com.github.ajalt.mordant.rendering.TextStyles.*
import com.github.ajalt.mordant.rendering.Whitespace
import com.github.ajalt.mordant.table.ColumnWidth
import com.github.ajalt.mordant.table.horizontalLayout
import com.github.ajalt.mordant.terminal.Terminal
import com.github.ajalt.mordant.widgets.Text
import com.github.ajalt.mordant.widgets.progress.*
import ghidra.program.model.address.Address
import ghidra.util.ErrorLogger
import ghidra.util.task.TaskMonitorAdapter
import ghistabs.diagnose.DiagnosticSink
import ghistabs.diagnose.Level
import ghistabs.formatSi
import ghistabs.kebabToCamelCase

/** Level tag style paired with the body style, mirroring the old hand-rolled SGR pairs. */
private val Level.styles get() = when (this) {
    Level.DEBUG -> Triple(bold + brightBlue, italic + blue, dim + white)
    Level.INFO -> Triple(bold + brightGreen, italic + green, reset.style)
    Level.WARN -> Triple(bold + brightYellow, italic + brightYellow, yellow)
    Level.ERROR -> Triple(bold + brightRed, italic + brightRed, red)
}

/** Ghidra reports indeterminate work as a non-positive maximum; mordant spells that `null`. */
private fun Long.orIndeterminate() = takeIf { it > 0 }

/**
 * Ghidra's [TaskMonitorAdapter], [ErrorLogger] and our [DiagnosticSink] rendered as one mordant progress bar. Log
 * lines print through the same [Terminal] as the animation.
 */
class BarLoggerMonitorSink(
    private val minLevel: Level,
    private val terminal: Terminal = Terminal(),
    private val ghidra: Boolean = true,
) : TaskMonitorAdapter(),
    ErrorLogger,
    DiagnosticSink {

    companion object {
        /** Where [BarSinkAppender] sends Ghidra's log4j events; log4j builds it, so it can't be injected. */
        @Volatile
        internal var active: BarLoggerMonitorSink? = null
        private const val BAR_WIDTH = 24
        private const val COUNT_WIDTH = 5

        private val layout = progressBarContextLayout {
            cell(ColumnWidth.Expand(), align = TextAlign.LEFT) {
                Text(bold(context), whitespace = Whitespace.NOWRAP, overflowWrap = OverflowWrap.ELLIPSES)
            }
            cell(ColumnWidth.Fixed(COUNT_WIDTH), align = TextAlign.RIGHT) {
                Text(
                    when (total) {
                        null, 0L, 1L -> ""
                        else if completed <= 0 -> ""
                        else -> completed.formatSi(COUNT_WIDTH)
                    },
                    overflowWrap = OverflowWrap.TRUNCATE,
                )
            }
            progressBar(width = BAR_WIDTH)
            cell(ColumnWidth.Fixed(COUNT_WIDTH), align = TextAlign.LEFT) {
                Text(
                    when (total) {
                        null, 0L, 1L -> ""
                        else -> total?.formatSi(COUNT_WIDTH).orEmpty()
                    },
                    overflowWrap = OverflowWrap.TRUNCATE,
                )
            }
            timeElapsed(style = italic.style)
        }
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

    private fun out(
        level: Level,
        message: String,
        category: String? = null,
        address: Address? = null,
        degrades: String? = null,
    ) {
        if (message.isBlank() || level < minLevel) return
        val (tag, cat, body) = level.styles

        terminal.println(
            horizontalLayout {
                column(0) { width = ColumnWidth.Fixed(1) }
                category?.let {
                    column(1) {
                        width = ColumnWidth.Fixed(24)
                        align = TextAlign.CENTER
                    }
                }
                cell(tag(level.name.take(1)))
                category?.let {
                    cell(cat(it)) {
                        whitespace = Whitespace.NORMAL
                        overflowWrap = OverflowWrap.ELLIPSES
                    }
                }
                cell(
                    listOfNotNull(
                        address?.let { green($"@$it") },
                        degrades?.let { magenta(italic(it)) },
                        body(message),
                    ).joinToString(" "),
                ) {
                    whitespace = Whitespace.PRE_WRAP
                    overflowWrap = OverflowWrap.BREAK_WORD
                }
            },

        )
    }

    override fun log(
        category: String,
        message: String?,
        level: Level,
        address: Address?,
        degrades: String?,
        count: Long,
    ) {
        out(level, message ?: return, category.kebabToCamelCase(), address, degrades)
    }

    fun Throwable.exception(level: Level) {
        message?.let { out(level, it) }
        terminal.println(stackTraceToString(), whitespace = Whitespace.PRE)
    }

    private val Any.tag get() = when (this) {
        is String -> this
        is Class<*> -> simpleName
        else -> this::class.simpleName
    }

    fun logGhidra(message: Any?, originator: Any?, level: Level) {
        if (!ghidra) return
        when (val msg = message?.toString()) {
            null -> {}
            else if msg.startsWith("WARNING! ") -> out(Level.WARN, msg.substring(9), originator?.tag)
            else -> out(level, msg, originator?.tag)
        }
    }

    override fun error(originator: Any?, message: Any?) = logGhidra(message, originator, Level.ERROR)
    override fun error(originator: Any?, message: Any?, throwable: Throwable?) {
        error(originator, message)
        throwable?.exception(Level.ERROR)
    }

    override fun warn(originator: Any?, message: Any?) = logGhidra(message, originator, Level.WARN)
    override fun warn(originator: Any?, message: Any?, throwable: Throwable?) {
        warn(originator, message)
        throwable?.exception(Level.WARN)
    }

    override fun info(originator: Any?, message: Any?) = logGhidra(message, originator, Level.INFO)
    override fun info(originator: Any?, message: Any?, throwable: Throwable?) {
        info(originator, message)
        throwable?.exception(Level.INFO)
    }

    override fun debug(originator: Any?, message: Any?) = logGhidra(message, originator, Level.DEBUG)
    override fun debug(originator: Any?, message: Any?, throwable: Throwable?) {
        debug(originator, message)
        throwable?.exception(Level.DEBUG)
    }

    override fun trace(originator: Any?, message: Any?) { }
    override fun trace(originator: Any?, message: Any?, throwable: Throwable?) { }

    override fun getMessage() = bar.context
    override fun setMessage(message: String?) = bar.update {
        context = message.orEmpty()
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
        bar.update { this.visible = show }
    }
}
