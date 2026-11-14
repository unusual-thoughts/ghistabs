package ghidrakt

// Throwaway: exercises CI annotations with many warnings and errors. Not for merging.

@Deprecated("test")
fun annotationTestOld(): Int = 1

fun annotationTestWarnings(): Int {
    var sum = 0
    sum += annotationTestOld() // warning 1
    sum += annotationTestOld() // warning 2
    sum += annotationTestOld() // warning 3
    sum += annotationTestOld() // warning 4
    sum += annotationTestOld() // warning 5
    sum += annotationTestOld() // warning 6
    sum += annotationTestOld() // warning 7
    sum += annotationTestOld() // warning 8
    sum += annotationTestOld() // warning 9
    sum += annotationTestOld() // warning 10
    sum += annotationTestOld() // warning 11
    sum += annotationTestOld() // warning 12
    return sum
}

fun annotationTestErrors() {
    val e1: Int = "not an int 1"
    val e2: Int = "not an int 2"
    val e3: Int = "not an int 3"
    val e4: Int = "not an int 4"
    val e5: Int = "not an int 5"
    val e6: Int = "not an int 6"
    val e7: Int = "not an int 7"
    val e8: Int = "not an int 8"
    val e9: Int = "not an int 9"
    val e10: Int = "not an int 10"
    val e11: Int = "not an int 11"
    val e12: Int = "not an int 12"
}
