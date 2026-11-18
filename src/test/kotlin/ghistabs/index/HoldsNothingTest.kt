package ghistabs.index

import ghidrakt.test.mustBeFalse
import ghidrakt.test.mustBeTrue
import ghistabs.parse.*
import ghistabs.test.dummyHarvester
import org.junit.jupiter.api.Test

/**
 * An empty class is often empty only through its bases: gcc 4.2.1's `allocator<T>`, `forward_iterator_tag` and
 * `__is_arithmetic<T>` hold nothing but an empty base, and Ghidra's one Undefined1 is all there is to them.
 */
class HoldsNothingTest {
    private fun lsym(index: Int, name: String) = StabRecord(index, StabType.N_LSYM, 0, 0, 0L, name)

    private val harvest = dummyHarvester().second.harvest(
        listOf(
            StabRecord(0, StabType.N_SO, 0, 0, 0L, "crypto_mi_test.cpp"),
            lsym(1, "char:t(0,2)=r(0,2);0;127;"),
            lsym(2, "input_iterator_tag:T(0,235)=s1;"),
            lsym(3, "forward_iterator_tag:T(0,237)=s1input_iterator_tag:(0,235),0,64;;"),
            lsym(4, "Flag:T(0,240)=s1on:(0,2),0,8;;"),
            lsym(5, "Flagged:T(0,241)=s1Flag:(0,240),0,64;;"),
            lsym(6, "Shape:T(0,242)=s4_vptr\$Shape:(0,243)=*(0,2),0,32;;"),
        ),
    )
    private val types = TypeGraph(harvest)

    private fun holdsNothing(n: Int) = types.holdsNothing(
        harvest.types.getValue(GlobalTypeId(SourceFile.CUSource("crypto_mi_test.cpp"), n)).body as TypeDecl.Aggregate,
    )

    @Test
    fun `a class whose only base is empty holds nothing`() {
        holdsNothing(235).mustBeTrue()
        holdsNothing(237).mustBeTrue()
    }

    @Test
    fun `a field, of its own or a base's, or a vptr, is something`() {
        holdsNothing(240).mustBeFalse()
        holdsNothing(241).mustBeFalse()
        holdsNothing(242).mustBeFalse()
    }
}
