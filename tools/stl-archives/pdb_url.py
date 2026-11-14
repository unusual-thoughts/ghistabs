"""Prints the symbol server URL of the PDB a PE file's CodeView record names."""
import sys

import pefile


def pdb_url(path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
    for entry in pe.DIRECTORY_ENTRY_DEBUG:
        cv = entry.entry
        if not hasattr(cv, "Signature_Data1"):
            continue
        name = cv.PdbFileName.rstrip(b"\0").decode().split("\\")[-1]
        guid = (cv.Signature_Data1.to_bytes(4, "big") + cv.Signature_Data2.to_bytes(2, "big")
                + cv.Signature_Data3.to_bytes(2, "big") + bytes([cv.Signature_Data4, cv.Signature_Data5])
                + bytes(cv.Signature_Data6)).hex().upper()
        return f"https://msdl.microsoft.com/download/symbols/{name}/{guid}{cv.Age:X}/{name}"
    raise SystemExit(f"{path}: no CodeView record")


if __name__ == "__main__":
    print(pdb_url(sys.argv[1]))
