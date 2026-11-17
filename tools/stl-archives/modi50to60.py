"""Rewrites a Visual C++ 5.0 PDB's module records (MODI50) as 6.0 ones (MODI_60_Persist), the way
microsoft-pdb's dbi.cpp converts them on read: Ghidra reads every new-header DBI's module records as
6.0 ones, so it misreads VC5's, which are 16 bytes shorter. Only the DBI stream changes; the small
('JG') MSF is laid out again around it.

    python3 modi50to60.py <in.pdb> <out.pdb>
"""
import struct, sys

src, dst = sys.argv[1], sys.argv[2]
d = open(src, 'rb').read()
MAGIC = b'Microsoft C/C++ program database 2.00\r\n\x1aJG\x00\x00'
assert d[:44] == MAGIC, 'not a small-MSF PDB'
ps, fpm, npages, dsize, unk = struct.unpack_from('<IHHII', d, 44)

def pages_of(size):
    return (size + ps - 1) // ps

dpages = struct.unpack_from('<%dH' % pages_of(dsize), d, 60)
dirb = b''.join(d[p * ps:(p + 1) * ps] for p in dpages)[:dsize]
nstreams = struct.unpack_from('<H', dirb, 0)[0]
off = 4
entries = []
for _ in range(nstreams):
    entries.append(struct.unpack_from('<Ii', dirb, off))
    off += 8
streams = []
for size, _ in entries:
    n = 0 if size == 0xffffffff else pages_of(size)
    pl = struct.unpack_from('<%dH' % n, dirb, off)
    off += 2 * n
    streams.append(None if size == 0xffffffff else b''.join(d[p * ps:(p + 1) * ps] for p in pl)[:size])

# The DBI stream: the new header, then the module records.
dbi = bytearray(streams[3])
sig, ver = struct.unpack_from('<iI', dbi, 0)
assert sig == -1 and ver < 19970606, 'not a pre-6.0 DBI'
cb_modi = struct.unpack_from('<i', dbi, 24)[0]
old = dbi[64:64 + cb_modi]
new = bytearray()
pos = 0
while pos < len(old):
    fixed = old[pos:pos + 48]
    pmod, = struct.unpack_from('<I', fixed, 0)
    sc40 = fixed[4:24]
    flags, sn, cb_syms, cb_lines, _cb_fpo, ifile_mac = struct.unpack_from('<HHiiiH', fixed, 24)
    names_at = pos + 48
    end = old.index(b'\0', names_at)
    end = old.index(b'\0', end + 1) + 1
    names = old[names_at:end]
    pos = (end + 3) & ~3
    rec = struct.pack('<I', 0) + sc40 + struct.pack('<II', 0, 0)            # SC: SC40 + data/reloc CRCs
    rec += struct.pack('<HHiiiHH', flags & 0x8001, sn, cb_syms, cb_lines, 0, ifile_mac, 0)
    rec += struct.pack('<III', 0, 0, 0)                                      # mpifileichFile, niSrcFile, niPdbFile
    rec += names
    rec += b'\0' * (-len(rec) % 4)
    new += rec
dbi[64:64 + cb_modi] = new
struct.pack_into('<i', dbi, 24, len(new))
streams[3] = bytes(dbi)

# Lay the MSF out again: header page, free page map page, the streams, then the directory.
out = [b'']  # page 0 written last
out.append(b'\xff' * ps)  # page 1: free page map, filled in below
page_lists = []
for s in streams:
    pl = []
    if s:
        for i in range(0, len(s), ps):
            pl.append(len(out))
            out.append(s[i:i + ps].ljust(ps, b'\0'))
    page_lists.append(pl)
dirn = struct.pack('<HH', len(streams), 0)
for (size, res), s in zip(entries, streams):
    dirn += struct.pack('<Ii', 0xffffffff if s is None else len(s), res)
for pl in page_lists:
    dirn += struct.pack('<%dH' % len(pl), *pl)
dir_pages = []
for i in range(0, len(dirn), ps):
    dir_pages.append(len(out))
    out.append(dirn[i:i + ps].ljust(ps, b'\0'))
total = len(out)
assert total < 0x10000
fpm_bits = bytearray(b'\xff' * ps)  # a set bit is a free page
for p in range(total):
    fpm_bits[p // 8] &= ~(1 << (p % 8))
out[1] = bytes(fpm_bits)
header = MAGIC + struct.pack('<IHHII', ps, 1, total, len(dirn), unk) + struct.pack('<%dH' % len(dir_pages), *dir_pages)
assert len(header) <= ps
out[0] = header.ljust(ps, b'\0')
open(dst, 'wb').write(b''.join(out))
print('%d bytes of module records became %d; %d pages' % (len(old), len(new), total))
