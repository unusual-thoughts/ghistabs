package ghicpp.score

/**
 * The MinGW gcc 4.2.1 builds of crypto_mi_test's stripped twins, their stabs removed too, scored against the builds
 * they were stripped from: off their RTTI and as if they had none, with and without their runtime functions
 * named beforehand. The `_fullstabs` pair adds libstdc++'s own classes to what is described.
 */
class CryptoScorecardIntegrationTest : ScorecardFixtureTest() {
    override fun cases(): List<ScorecardCase> =
        listOf("crypto_mi_test_gcc421", "crypto_mi_test_gcc421_fullstabs").flatMap { twin ->
            Recovery.entries.flatMap { recovery ->
                listOf(false, true).map { labelled ->
                    ScorecardCase("${twin}_stripped.exe", recovery, "$twin.exe", labelled = labelled)
                }
            }
        }
}
