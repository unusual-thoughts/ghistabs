package ghistabs.diagnose

import ghistabs.parse.LocalTypeId
import ghistabs.parse.Parser
import ghistabs.parse.SymbolDecl
import ghistabs.parse.mustBeOk
import ghistabs.test.*
import kotlinx.serialization.encodeToString
import org.junit.jupiter.api.Test

class DumpsTest {
    /**
     * A decl property named `type` collides with the class discriminator and throws at dump time; no
     * corpus fixture has a pointer to data member, so the regression dumps never reached `Member`.
     */
    @Test
    fun `a pointer to data member dumps`() {
        val sym = Parser("pmi:G20=*21=@22=xsA:,1").parseSymbol().mustBeOk()
        "TypeDecl.Member" mustBeIn dumpJson.encodeToString<SymbolDecl<LocalTypeId>>(sym)
    }
}
