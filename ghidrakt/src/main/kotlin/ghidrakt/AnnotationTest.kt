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

