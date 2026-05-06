package ghistabs

import ghidra.app.util.Option
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.opinion.AbstractProgramWrapperLoader
import ghidra.app.util.opinion.LoadSpec
import ghidra.app.util.opinion.Loader.ImporterSettings
import ghidra.framework.model.DomainObject
import ghidra.program.model.listing.Program
import ghidra.util.exception.CancelledException
import java.io.IOException
import kotlin.collections.ArrayList
import kotlin.collections.MutableCollection
import kotlin.collections.MutableList

/**
 * Provide class-level documentation that describes what this loader does.
 */
class StabsLoader : AbstractProgramWrapperLoader() {
    override fun getName(): String {
        // Name the loader.  This name must match the name of the loader in the .opinion files.

        return "My loader"
    }

    @kotlin.Throws(IOException::class)
    override fun findSupportedLoadSpecs(provider: ByteProvider?): MutableCollection<LoadSpec?> {
        val loadSpecs: MutableList<LoadSpec?> = ArrayList<LoadSpec?>()

        // Examine the bytes in 'provider' to determine if this loader can load it.  If it
        // can load it, return the appropriate load specifications.
        return loadSpecs
    }

    @kotlin.Throws(CancelledException::class, IOException::class)
    override fun load(
        prgram: Program?,
        settiings: ImporterSettings?,
    ) {
        // Load the bytes from 'settings.provider()' into the 'program'.
    }

    override fun getDefaultOptions(
        provider: ByteProvider?,
        loadSpec: LoadSpec?,
        domainObject: DomainObject?,
        isLoadIntoProgram: Boolean,
        mirrorFsLayout: Boolean,
    ): MutableList<Option?> {
        val list =
            super.getDefaultOptions(
                provider,
                loadSpec,
                domainObject,
                isLoadIntoProgram,
                mirrorFsLayout,
            )

        // If this loader has custom options, add them to 'list'
        list.add(Option("Option name goes here", "Default option value goes here"))

        return list
    }

    override fun validateOptions(
        provider: ByteProvider?,
        loadSpec: LoadSpec?,
        options: MutableList<Option?>?,
        program: Program?,
    ): String? {
        // If this loader has custom options, validate them here.  Not all options require
        // validation.

        return super.validateOptions(provider, loadSpec, options, program)
    }
}
