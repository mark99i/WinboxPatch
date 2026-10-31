#!/usr/bin/env python3
"""
build-patched-v4.py - deterministic build of patch set v4 (lineage v98).

    python build-patched-v4.py [base.exe] [out.exe]

Base: winbox64.v3.43p3.exe (patch set v3 = v83,
sha256 4c7223fdf60eb4293db413db712aa89a786180eff7074398630dfc21c6f29d6a).

Patch set v4 = v83 + two converter-slot fixes + version stamp 3.43.102.98
(recipe: ANALYSIS.md section 14). RouterOS 7.24+ left the 'bytes' and
'bigbytes' field converters with EMPTY parse/commit slots (vt+0x28 / vt+0x20)
while their formatters still work, so every editable bytes/bigbytes field is
shown red and edits never apply:

  1. frag4 ('bytes', u32): wire the converter slots to a WinBox4-grammar
     parser (KiB/MiB/GiB/TiB binary, k/M/G/T decimal, bare/B, empty=0,
     clamp 0xffffffff) and a number-style value-commit stub, both placed
     into free .wbox space at VA 0x657400..0x65781F.
  2. shm2 ('bigbytes', u64): same for the bigbytes converter - u64 parser
     (clamp 0xffffffffffffffff, wrap guards) + commit stub at VA
     0x638500..0x63891A. Fixes Container -> Shm Size (and tmpfs,
     memory-high/max, swap-max, disk File Size/Offset).
  3. Version stamp: ANSI titles + UTF-16 FileVersion/ProductVersion ->
     3.43.102.98 (VS_FIXEDFILEINFO untouched, as in the reference).

The bridges (0x485622 bytes / 0x485ddc bigbytes) and the rest of the
value-commit chain are NOT touched. All zones are disjoint from v3.

Output: winbox64.v3.43p4.exe, byte-identical to the reference build v98
(sha256 4b861b5a0508df19b93b888453a1072e94c8feddd760a3a6f7fa864c8b1de1dd).

The two converter blobs are not hardcoded: their assembly sources
(bytes_impl.S - the 'bytes' (u32) converter, bigbytes_impl.S - the
'bigbytes' (u64) converter; both kept verbatim from ANALYSIS-FRAG.md /
ANALYSIS-SHM.md section G.1) are assembled with the real GNU toolchain
by build-blobs.py (as + ld -Ttext + objcopy; preinstalled on the CI
runners, locally available via WSL or MinGW) into bytes_impl.bin /
bigbytes_impl.bin, which this script loads - run build-blobs.py first.
The blobs are not verified separately: the patched exe is verified as a
whole by its final SHA-256.
"""
import sys
import struct
import hashlib

BASE_SHA   = "4c7223fdf60eb4293db413db712aa89a786180eff7074398630dfc21c6f29d6a"
TARGET_SHA = "4b861b5a0508df19b93b888453a1072e94c8feddd760a3a6f7fa864c8b1de1dd"

NN = 98  # version number -> "WinBox 3.43.102.98"

# --- frag4: 'bytes' converter (vt 0x58F508) slots + blob ---
FRAG_SLOT_PARSE  = 0x101450      # VA 0x502050, vt+0x28 (parser)
FRAG_SLOT_COMMIT = 0x1013F0      # VA 0x501FF0, vt+0x20 (value-commit)
FRAG_PARSE_ORIG  = bytes.fromhex("31c0c39090")   # xor eax,eax; ret; nops
FRAG_COMMIT_ORIG = bytes.fromhex("c390909090")   # ret; nops
FRAG_PARSE_JMP   = bytes.fromhex("e9ab53150090") # jmp 0x657400
FRAG_COMMIT_JMP  = bytes.fromhex("e90b58150090") # jmp 0x657800
FRAG_OFF, FRAG_LEN = 0x24DA00, 0x419             # VA 0x657400..0x657818

# --- shm2: 'bigbytes' converter (vt 0x5948F8) slots + blob ---
SHM_SLOT_PARSE  = 0x10AEC0       # VA 0x50BAC0, vt+0x28 (parser)
SHM_SLOT_COMMIT = 0x10AE60       # VA 0x50BA60, vt+0x20 (value-commit)
SHM_PARSE_ORIG  = bytes.fromhex("31c0c39090")
SHM_COMMIT_ORIG = bytes.fromhex("c390909090")
SHM_PARSE_JMP   = bytes.fromhex("e93bca120090")  # jmp 0x638500
SHM_COMMIT_JMP  = bytes.fromhex("e99bce120090")  # jmp 0x638900
SHM_OFF, SHM_LEN = 0x22EB00, 0x41A              # VA 0x638500..0x638919

# --- untouched bridge sanity anchor ---
BRIDGE_OFF = 0x84A22
BRIDGE_ORIG = bytes.fromhex("80b99800")

# ---------------------------------------------------------------------------
# The two converter blobs, assembled by build-blobs.py from bytes_impl.S
# ('bytes', u32) and bigbytes_impl.S ('bigbytes', u64) into bytes_impl.bin
# and bigbytes_impl.bin next to this script - run build-blobs.py before
# this one (binutils is preinstalled on the GitHub CI runners; on Windows
# use WSL or MinGW-w64). The blobs are not verified separately: the final
# patched exe is checked as a whole by its SHA-256.
# ---------------------------------------------------------------------------
import os

_HERE = os.path.dirname(os.path.abspath(__file__))

def _load_bin(path, name):
    """Load a blob assembled by build-blobs.py (no embedded fallback)."""
    if not os.path.exists(path):
        print(f"FAIL: {name}: {path} not found - run 'python build-blobs.py' first")
        sys.exit(1)
    with open(path, "rb") as f:
        return f.read()

FRAG_BLOB = _load_bin(os.path.join(_HERE, "bytes_impl.bin"), "bytes")
SHM_BLOB = _load_bin(os.path.join(_HERE, "bigbytes_impl.bin"), "bigbytes")


def die(m):
    print(f"FAIL: {m}")
    sys.exit(1)

# ---------------------------------------------------------------- frag4
def apply_frag4(d):
    if d[FRAG_SLOT_PARSE:FRAG_SLOT_PARSE + 2] == b"\xe9" and \
       d[FRAG_OFF] == 0x53:
        print("  frag4: already in place")
        return
    if bytes(d[FRAG_SLOT_PARSE:FRAG_SLOT_PARSE + 5]) != FRAG_PARSE_ORIG:
        die(f"frag4 parse slot: {d[FRAG_SLOT_PARSE:FRAG_SLOT_PARSE + 5].hex()}")
    if bytes(d[FRAG_SLOT_COMMIT:FRAG_SLOT_COMMIT + 5]) != FRAG_COMMIT_ORIG:
        die(f"frag4 commit slot: {d[FRAG_SLOT_COMMIT:FRAG_SLOT_COMMIT + 5].hex()}")
    if d[FRAG_OFF:FRAG_OFF + FRAG_LEN].count(0) != FRAG_LEN:
        die("frag4 blob zone is not free")
    assert len(FRAG_BLOB) == FRAG_LEN
    d[FRAG_SLOT_PARSE:FRAG_SLOT_PARSE + 6] = FRAG_PARSE_JMP
    d[FRAG_SLOT_COMMIT:FRAG_SLOT_COMMIT + 6] = FRAG_COMMIT_JMP
    d[FRAG_OFF:FRAG_OFF + FRAG_LEN] = FRAG_BLOB
    print("  frag4: installed")

# ---------------------------------------------------------------- shm2
def apply_shm2(d):
    if d[SHM_SLOT_PARSE:SHM_SLOT_PARSE + 2] == b"\xe9" and \
       d[SHM_OFF] == 0x53:
        print("  shm2: already in place")
        return
    if bytes(d[SHM_SLOT_PARSE:SHM_SLOT_PARSE + 5]) != SHM_PARSE_ORIG:
        die(f"shm2 parse slot: {d[SHM_SLOT_PARSE:SHM_SLOT_PARSE + 5].hex()}")
    if bytes(d[SHM_SLOT_COMMIT:SHM_SLOT_COMMIT + 5]) != SHM_COMMIT_ORIG:
        die(f"shm2 commit slot: {d[SHM_SLOT_COMMIT:SHM_SLOT_COMMIT + 5].hex()}")
    if d[SHM_OFF:SHM_OFF + SHM_LEN].count(0) != SHM_LEN:
        die("shm2 blob zone is not free")
    assert len(SHM_BLOB) == SHM_LEN
    d[SHM_SLOT_PARSE:SHM_SLOT_PARSE + 6] = SHM_PARSE_JMP
    d[SHM_SLOT_COMMIT:SHM_SLOT_COMMIT + 6] = SHM_COMMIT_JMP
    d[SHM_OFF:SHM_OFF + SHM_LEN] = SHM_BLOB
    print("  shm2: installed")

# ---------------------------------------------------------------- versions
def bump_versions(d, nn):
    s = f"WinBox 3.43.102.{nn:02d}"      # ANSI titles
    s2 = f"3.43.102.{nn:02d}"            # UTF-16 fields (max 12 chars)
    assert len(s) <= 19 and len(s2) <= 12
    if not d[0x1379B9:0x1379B9 + 17].startswith(b"WinBox 3.43.102."):
        die(f"title1: {d[0x1379B9:0x1379D2]!r}")
    if not d[0x137FBC:0x137FBC + 17].startswith(b"WinBox 3.43.102."):
        die(f"title2: {d[0x137FBC:0x137FCD]!r}")
    d[0x1379B9:0x1379B9 + 24] = (s + " (%s)").encode() + b"\x00" * (24 - len(s) - 5)
    d[0x137FBC:0x137FBC + 19] = s.encode() + b"\x00" * (19 - len(s))
    # UTF-16 FileVersion / ProductVersion (VS_FIXEDFILEINFO untouched)
    R = 0x21C410
    seg = bytes(d[R:R + 0x2E8])
    nv = s2.encode("utf-16-le") + b"\x00" * (24 - len(s2) * 2)
    assert len(nv) == 24
    for key in (b"F\x00i\x00l\x00e\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00",
                b"P\x00r\x00o\x00d\x00u\x00c\x00t\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00"):
        j = seg.find(key + b"\x00\x00")
        if j < 0:
            die("no UTF-16 version block")
        v = j + len(key) + 2
        while seg[v] == 0:
            v += 1
        old = seg[v:v + 24].decode("utf-16-le").rstrip("\x00")
        if not old.startswith("3.43.102."):
            die(f"base UTF-16 version: {old}")
        d[R + v:R + v + 24] = nv
    print(f"  versions -> {s}")

# ---------------------------------------------------------------- verify
def verify(d):
    assert bytes(d[FRAG_SLOT_PARSE:FRAG_SLOT_PARSE + 6]) == FRAG_PARSE_JMP
    assert bytes(d[FRAG_SLOT_COMMIT:FRAG_SLOT_COMMIT + 6]) == FRAG_COMMIT_JMP
    assert d[FRAG_OFF:FRAG_OFF + FRAG_LEN] == FRAG_BLOB
    assert bytes(d[SHM_SLOT_PARSE:SHM_SLOT_PARSE + 6]) == SHM_PARSE_JMP
    assert bytes(d[SHM_SLOT_COMMIT:SHM_SLOT_COMMIT + 6]) == SHM_COMMIT_JMP
    assert d[SHM_OFF:SHM_OFF + SHM_LEN] == SHM_BLOB
    # jmp targets resolved from the slot positions (VA = file + 0x400C00)
    for slot, target in ((FRAG_SLOT_PARSE, 0x657400), (FRAG_SLOT_COMMIT, 0x657800),
                         (SHM_SLOT_PARSE, 0x638500), (SHM_SLOT_COMMIT, 0x638900)):
        va = slot + 0x400C00
        rel = struct.unpack("<i", d[slot + 1:slot + 5])[0]
        assert va + 5 + rel == target, hex(va + 5 + rel)
    assert bytes(d[BRIDGE_OFF:BRIDGE_OFF + 4]) == BRIDGE_ORIG  # bridge untouched
    assert d[0x1379B9:0x1379B9 + 24] == b"WinBox 3.43.102.98 (%s)\x00"
    assert d[0x137FBC:0x137FBC + 19] == b"WinBox 3.43.102.98\x00"

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "winbox64.v3.43p3.exe"
    out = sys.argv[2] if len(sys.argv) > 2 else "winbox64.v3.43p4.exe"
    blob = open(base, "rb").read()
    if len(blob) != 2418176:
        die(f"base size {len(blob)} != 2418176 (v83 lineage)")
    sha = hashlib.sha256(blob).hexdigest()
    if sha != BASE_SHA:
        die(f"base sha256 {sha} is not the v83 base")
    print(f"Input OK: {base} (v83)")
    d = bytearray(blob)
    apply_frag4(d)
    apply_shm2(d)
    bump_versions(d, NN)
    verify(d)
    result = bytes(d)
    open(out, "wb").write(result)
    out_sha = hashlib.sha256(result).hexdigest()
    print(f"Wrote: {out} ({len(result)} bytes)")
    print(f"  sha256: {out_sha}")
    if out_sha == TARGET_SHA:
        print("  byte-identical to the reference v98 build OK")
    else:
        print(f"  MISMATCH: expected {TARGET_SHA}")
        sys.exit(1)

if __name__ == "__main__":
    main()


