package ghistabs.materialize.cpp.abi

import ghidra.docking.settings.Settings
import ghidra.docking.settings.SettingsImpl

/**
 * `Settings.isImmutableSettings()` arrives in 12.0. Before it, the flag lives only in [SettingsImpl]'s
 * private `immutable` (set for [SettingsImpl.NO_SETTINGS] and for a component whose manager disallows
 * default component settings), and writes to such settings are dropped with a warning. That field is
 * what 12's `SettingsImpl` returns; the other implementations a component hands out
 * (`ComponentDBSettings`) answer false there too.
 *
 * Declared in the caller's own package so that 12.0+, where this file is not compiled, has no import
 * left pointing at nothing.
 */
internal val Settings.isImmutableSettings: Boolean
    get() = this is SettingsImpl && immutable.getBoolean(this)

private val immutable = SettingsImpl::class.java.getDeclaredField("immutable").apply { isAccessible = true }
