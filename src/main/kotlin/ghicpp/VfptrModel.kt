package ghicpp

import ghidra.framework.options.Options
import ghidra.program.model.listing.Program
import ghistabs.EnumOption
import ghistabs.get

/**
 * Where a polymorphic class's `{vfptr}` comes from, which decides whether a virtual call resolves to
 * a named slot or overruns into `vfptr[N]`. Whatever laid the class: the stabs import, or a class pass
 * off the RTTI ([ghicpp.recover.ClassStructFiller]).
 *
 * The vptr sits inside a base subobject, so a derived class can only carry a pointer to
 * its **own** vftable if something gives way, and the static type of that field is what the
 * decompiler indexes. With one shared field typed `<Root>_vftable *`, every derived slot lands past
 * the end of the root's table: `xmltest_gcc421` renders 31 of its 40 virtual calls as
 * `vfptr[4].~TiXmlBase` and never mentions a derived vftable type at all.
 *
 * A third shape exists: Ghidra's own `RecoveredClassHelper` expands the base subobject away
 * entirely and puts `vftablePtr` at offset 0, trading the `_base_` component for the pointer.
 */
enum class VfptrModel {
    /** One `{vfptr}` on the root of each hierarchy, inherited through `_base_`. Derived slots overrun. */
    INHERITED,

    /**
     * Each polymorphic class owns a `{vfptr}` typed to its own vftable, and embeds the base holding the
     * vptr as that base's fields *without* it — one extra struct per polymorphic base, shared by every
     * class that derives from it. Keeps the `_base_` subobject component that [ClassNaming.baseFieldName]
     * models inheritance with.
     */
    SPLIT_BASE,

    ;

    companion object {
        /** The option choosing the model, under one name and default for the stabs import and each class pass. */
        val OPTION = EnumOption(
            "Virtual function pointer model",
            "Where a polymorphic class's {vfptr} comes from. INHERITED keeps one on the root of each " +
                "hierarchy, shared through the base subobject — derived slots then sit past the end of " +
                "the root's vftable and virtual calls render as vfptr[N].field. SPLIT_BASE gives every " +
                "polymorphic class its own {vfptr} typed to its own vftable, embedding the base that holds " +
                "the vptr as that base's fields without it, so virtual calls resolve to named slots.",
            SPLIT_BASE,
        )

        /** Registers [OPTION] among an analyzer's [options]. */
        fun register(options: Options) = OPTION.register(options)

        /** The model the analyzer called [analyzer] is set to in [program]'s analysis options. */
        fun Program.vfptrModelOf(analyzer: String): VfptrModel =
            getOptions(Program.ANALYSIS_PROPERTIES).getOptions(analyzer)[OPTION]
    }
}
