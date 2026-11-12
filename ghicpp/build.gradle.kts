// The C++ extension: the class passes, the ABI readers, the gcc/MinGW fix-ups and the Class Hierarchy
// window, on any binary. It knows nothing of stabs; ghistabs bundles it.
plugins {
    id("ghidra-module")
    id("ghidra-extension")
}

dependencies {
    api(project(":ghidrakt"))
}
