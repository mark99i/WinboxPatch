#!/usr/bin/env python3
"""
build-patched-v3.py - deterministic build of patch set v3 (lineage v83).

    python build-patched-v3.py [base.exe] [out.exe]

Base: winbox64.v3.43p2.exe (patch set v2 = v38,
sha256 8b0bc24fcfdbd7eee6109d4593ad3aedecb4fc28786133acc71ed051c61aea20).

Patch set v3 = v38 base + three functional tweaks + version stamp 3.43.102.83
(zones and byte dump: ANALYSIS.md section 10.3):
  1. Format Drive NULL-guard (.text 0xEE9B0 -> cave 0xEE9C4):
     fixes the Format Drive / Power Cycle crash on NULL rdx.
  2. Win11 wrapper alignment (.wbox 0x638000): sub/add rsp,8 so rsp is
     16-byte aligned at WinAPI calls (MOVAPS crash in CreateFileA on Win11);
     lea PNG-table disp 0xBC -> 0xC0; final jmp re-aimed to 0x4014C0.
  3. Switch icon (CHR): lazy getIcon blob (0x78 bytes, already re-aimed for
     basis 0x638300) at .wbox+0x300; icon slot 0x1A7200 -> 0x638300.
  4. Versions: ANSI titles + UTF-16 FileVersion/ProductVersion -> 3.43.102.83.
     VS_FIXEDFILEINFO is intentionally NOT touched (same as the reference).

Output: winbox64.v3.43p3.exe, byte-identical to the reference minimal-lineage
build v83 (sha256 4c7223fdf60eb4293db413db712aa89a786180eff7074398630dfc21c6f29d6a).
"""
import sys
import struct
import hashlib

BASE_SHA   = "8b0bc24fcfdbd7eee6109d4593ad3aedecb4fc28786133acc71ed051c61aea20"
TARGET_SHA = "4c7223fdf60eb4293db413db712aa89a786180eff7074398630dfc21c6f29d6a"

NN = 83  # version number -> "WinBox 3.43.102.83"

# --- zone 1: Format Drive NULL-guard (.text) ---
FD_SITE, FD_CAVE = 0xEE9B0, 0xEE9C4          # VA 0x4EF5B0 / 0x4EF5C4
FD_ORIG  = bytes.fromhex("8b4228")           # mov eax,[rdx+0x28]
FD_JUMP  = bytes.fromhex("eb1290")           # jmp 0x4EF5C4; nop
FD_GUARD = bytes.fromhex("4885d27501c38b4228ebe490")  # 12B cave guard

# --- zone 7: .wbox entry wrapper (RVA 0x238000 = file 0x22E600) ---
RAW   = 0x22E600
ENTRY = 0x4014C0                             # mainCRTStartup

# --- zone 8: Switch icon lazy getIcon, basis VA 0x638300 ---
GGET2_F   = RAW + 0x300                      # file 0x22E900
GGET2_VA  = 0x638300
SLOT_OFF  = 0x1A7200                         # .rdata icon slot (VA 0x5A8E00)
SLOT_ORIG = 0x522D80

# gget2 blob (0x78 bytes, byte dump of the v83 reference; the three absolute
# cache refs point to 0x638370 = basis+0x70, the call rel32 is already
# re-aimed for basis 0x638300 -> 0x43CE24).
GGET2_BLOB = bytes.fromhex(
    "488b41104885c0755d488b51084989d0"
    "49c1e820755081fa00000001724881fa"
    "000000087340833a06753b817a045377"
    "6974753266817a086368752a488b0425"
    "708363004885c0751d50b918000000e8"
    "d04ae0ff48890425708363004158488b"
    "042570836300c3" + "00" * 17
)

def die(m):
    print(f"FAIL: {m}")
    sys.exit(1)

def rel32(b):
    return struct.unpack("<i", b)[0]

assert len(GGET2_BLOB) == 0x78
assert GGET2_BLOB[0x4F] == 0xE8                                   # call
assert GGET2_VA + 0x54 + rel32(GGET2_BLOB[0x50:0x54]) == 0x43CE24  # re-aimed

# ---------------------------------------------------------------- zone 1
def apply_fd(d):
    if d[FD_SITE:FD_SITE + 3] == FD_JUMP and d[FD_CAVE:FD_CAVE + 12] == FD_GUARD:
        print("  FD-guard: already in place")
        return
    if d[FD_SITE:FD_SITE + 3] != FD_ORIG:
        die(f"FD site is not original: {d[FD_SITE:FD_SITE + 3].hex()}")
    if d[FD_CAVE:FD_CAVE + 12] != b"\x90" * 12:
        die("FD cave is occupied")
    d[FD_SITE:FD_SITE + 3] = FD_JUMP
    d[FD_CAVE:FD_CAVE + 12] = FD_GUARD
    print("  FD-guard: installed")

# ---------------------------------------------------------------- zone 7
def apply_align(d):
    if d[RAW + 0x1A:RAW + 0x1E] == bytes.fromhex("4883ec08"):
        print("  align: already in place")
        return
    if d[RAW + 0x08:RAW + 0x13] != bytes.fromhex("5356574154415541564157"):
        die(f"prolog: {d[RAW + 0x08:RAW + 0x13].hex()}")
    if d[RAW + 0x13:RAW + 0x1A] != bytes.fromhex("4881ec38030000"):
        die("no sub rsp,0x338 @ +0x13")
    if d[RAW + 0x220:RAW + 0x228].count(0) != 8:
        die("slack RAW+0x220 is not zeros")
    w = bytearray(d[RAW:RAW + 0x220])
    # prolog: sub rsp,0x338 ; sub rsp,8   (rsp 16-byte aligned at WinAPI calls)
    w[0x1A:0x1A] = bytes.fromhex("4883ec08")
    assert bytes(w[0x199:0x1A0]) == bytes.fromhex("4881c438030000")
    # epilog: add rsp,0x338 ; add rsp,8   (window overwrite, file does not grow)
    w[0x1A0:0x1A0] = bytes.fromhex("4883c408")
    # lea rax,[rip+TBL]: the first insert shifted it +4 (0xF1 -> 0xF5);
    # TBL moved +8 while rip moved +4 -> disp32 0xBC -> 0xC0
    assert bytes(w[0xF5:0xF8]) == bytes.fromhex("488d05")
    assert rel32(w[0xF8:0xFC]) == 0xBC
    w[0xF8:0xFC] = struct.pack("<i", 0xC0)
    # final jmp rel32: opcode moved +8, re-aim to ENTRY exactly
    assert w[0x1B7] == 0xE9, "no jmp @ +0x1B7"
    cur = 0x638000 + 0x1B7 + 5 + rel32(w[0x1B8:0x1BC])
    if cur not in (ENTRY, ENTRY + 8):
        die(f"jmp leads to {cur:#x}")
    w[0x1B8:0x1BC] = struct.pack("<i", ENTRY - (0x638000 + 0x1B7 + 5))
    d[RAW:RAW + 0x228] = w
    print("  align: installed")

# ---------------------------------------------------------------- zone 8
def apply_icon(d):
    if struct.unpack("<Q", d[SLOT_OFF:SLOT_OFF + 8])[0] == GGET2_VA and \
       d[GGET2_F] == 0x48:
        print("  Switch icon: already in place")
        return
    if d[GGET2_F:GGET2_F + 0x78].count(0) != 0x78:
        die("0x638300 region is not free")
    d[GGET2_F:GGET2_F + 0x78] = GGET2_BLOB
    cur = struct.unpack("<Q", d[SLOT_OFF:SLOT_OFF + 8])[0]
    if cur != SLOT_ORIG:
        die(f"slot {cur:#x} is not original")
    struct.pack_into("<Q", d, SLOT_OFF, GGET2_VA)
    print("  Switch icon: installed")

# ---------------------------------------------------------------- zones 2-5
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
    assert d[FD_SITE:FD_SITE + 3] == FD_JUMP
    assert d[FD_CAVE:FD_CAVE + 12] == FD_GUARD
    assert bytes(d[RAW + 0x1A:RAW + 0x1E]) == bytes.fromhex("4883ec08")
    assert bytes(d[RAW + 0x1A0:RAW + 0x1A4]) == bytes.fromhex("4883c408")
    assert rel32(d[RAW + 0xF8:RAW + 0xFC]) == 0xC0
    assert 0x638000 + 0x1BC + rel32(d[RAW + 0x1B8:RAW + 0x1BC]) == ENTRY
    assert struct.unpack("<Q", d[SLOT_OFF:SLOT_OFF + 8])[0] == GGET2_VA
    assert d[GGET2_F:GGET2_F + 0x78] == GGET2_BLOB
    assert GGET2_VA + 0x54 + rel32(d[GGET2_F + 0x50:GGET2_F + 0x54]) == 0x43CE24
    assert d[0x1379B9:0x1379B9 + 24] == b"WinBox 3.43.102.83 (%s)\x00"
    assert d[0x137FBC:0x137FBC + 19] == b"WinBox 3.43.102.83\x00"

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "winbox64.v3.43p2.exe"
    out = sys.argv[2] if len(sys.argv) > 2 else "winbox64.v3.43p3.exe"
    blob = open(base, "rb").read()
    if len(blob) != 2418176:
        die(f"base size {len(blob)} != 2418176 (v38 lineage)")
    sha = hashlib.sha256(blob).hexdigest()
    if sha != BASE_SHA:
        die(f"base sha256 {sha} is not the v38 base")
    print(f"Input OK: {base} (v38)")
    d = bytearray(blob)
    apply_fd(d)
    apply_align(d)
    apply_icon(d)
    bump_versions(d, NN)
    verify(d)
    result = bytes(d)
    open(out, "wb").write(result)
    out_sha = hashlib.sha256(result).hexdigest()
    print(f"Wrote: {out} ({len(result)} bytes)")
    print(f"  sha256: {out_sha}")
    if out_sha == TARGET_SHA:
        print("  byte-identical to the reference v83 build OK")
    else:
        print(f"  MISMATCH: expected {TARGET_SHA}")
        sys.exit(1)

if __name__ == "__main__":
    main()


