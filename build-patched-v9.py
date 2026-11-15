#!/usr/bin/env python3
"""
build-patched-v9.py - deterministic build of patch set v9.

    python build-patched-v9.py [base.exe] [out.exe]

Base:   winbox64.v3.43p8.exe (patch set v8,
        sha256 665f7420baf57ece3d5382f446e1d57b4e4a76e751d51552eb96024c2df11fff).
Output: winbox64.v3.43p9.exe, byte-identical to the known-good
        community-patched build (sha256
        6a7abd5094a8a2abc1c2c6a59e6d57a453d089695dd4000961163205d389a799,
        version stamp 3.43.104.3). File size unchanged; .text untouched,
        everything lives in .wbox.

Closed bugs:

  * Routing -> Settings -> Policy Rules: a RED mark on the first open (a
    race - the strict:1 validation fires before the chains arrive from
    the router; the second open is black thanks to the chain cache) plus
    "Error in - selection expected!" on Apply with an empty string (a
    local strict error before anything is sent - it blocked even a no-op
    Apply). Fixed by strict:1 -> min:1.

Restored functions:

  * The Ping/Traceroute field regression: in v8 the Interface/VRF
    injections were dead code (the fopen hook was retargeted to the
    Range-only jgmem cave; in v7 they worked through a disk write). v9
    brings them back in-memory: a unified cave performs the Ping
    (Interface, VRF) + Traceroute (Interface, VRF) injections
    piecewise-idempotently (reopening dialogs does not duplicate fields).

  * The jg field-change machinery is refactored: the dead disk-write-era
    code (the v3 stab at 0x65B400, which wrote +367B of Ping/TR
    injections ON DISK, polluted the cache, changed the md5 and broke
    idempotency) is fully cleaned. v9 is 100% in-memory: one unified
    cave, a Range pre-check (the marker gate activates the
    transformation only when 'bignumberrange' is really present in the
    buffer) and a piecewise fseek correction. The disk stays virgin
    (md5 before = after).

The Num Set Range and NTP display functions are inherited from v8
unchanged. Policy Rules min:1 is the only new jg-grammar edit
(same-length).

Components (delta v8 -> v9):

  * step 1 - three retargets inside the existing jgmem cave (0x659000,
    from v8): the after-path-gate / after-fread / after-transform flows
    leave into the new sub-caves.
  * step 2 - five new caves (assembled from the .s sources in the asm/
    folder):
      - unified12.s          @0x659560: the unified cave - the Ping
        (Interface/VRF) + Traceroute (Interface/VRF) field injections +
        the Policy Rules strict:1->min:1 same-length replacement; the
        buffer is scanned with findmarker; anti-dup gates (an Interface
        window check + a DSCP-context marker).
      - postrange3.s         @0x6598A0: the Range fread hook - it
        intercepts the original FREADFN, computes the call site and
        stores the Range boundary.
      - piecewise.s          @0x659920: the fseek correction - it
        compares the position against the Range zone boundaries
        (0x6598F8/FC/0x659900) and adds the accumulated insertions.
      - fseekfn_piecewise.s  @0x659C00: the cmr.jg piecewise transit -
        an item size check (<=0xF8), a byte copy into a stack buffer,
        CreateFileA("cmr.jg"), SetFilePointer, CloseHandle; returns into
        the unified cave.
      - range_precheck.s     @0x65A700: the Range marker gate - a
        findmarker for "bignumberrange',id:'q2c5504'" (28B); not found
        -> the FREADFN slot [0x659520]=0 (Range off); found -> continue
        into the jgmem cave.
  * step 3 - inline data: the marker string @0x65A750 (28B) and the
    0xFF filler @0x6598F8 (15B, the piecewise boundaries).
  * step 4 - dead-code cleanup of the disk-write era: the code stab
    (2463B) + the stab data (289B) + the CMR jg fragment (21B) -> zeros.
  * step 5 - version stamp 3.43.104.1 -> 3.43.104.3 (same-length).

Asserts: base sha256; the original bytes of every zone/hook before each
patch; the result sha256 (byte-exact reproducibility).
"""
import hashlib
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

BASE_SHA256 = "665f7420baf57ece3d5382f446e1d57b4e4a76e751d51552eb96024c2df11fff"
TARGET_SHA  = "6a7abd5094a8a2abc1c2c6a59e6d57a453d089695dd4000961163205d389a799"

# --- PE offsets ---
WBOX_FILE, WBOX_VA = 0x22E600, 0x638000

def wf(va):    # .wbox: VA -> file
    return WBOX_FILE + (va - WBOX_VA)


def die(m):
    print(f"FAIL: {m}")
    sys.exit(1)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def assemble(s_name, text_va):
    """as --64 -> ld -Ttext=<VA> -> objcopy -O binary -> bytes."""
    s_path = os.path.join(HERE, "asm", s_name)
    if not os.path.exists(s_path):
        die(f"cave source missing: {s_path}")
    with tempfile.TemporaryDirectory() as td:
        o = os.path.join(td, s_name.replace(".s", ".o"))
        e = o.replace(".o", ".elf")
        b = o.replace(".o", ".bin")
        for args in (["as", "--64", "-o", o, s_path],
                     ["ld", "-Ttext", hex(text_va), "-o", e, o],
                     ["objcopy", "-O", "binary", e, b]):
            r = subprocess.run(args, capture_output=True, text=True)
            if r.returncode:
                die(f"{s_name}: {args[0]}: {r.stderr[:300]}")
        return open(b, "rb").read()


def check(d, off, expect, what):
    cur = bytes(d[off:off + len(expect)])
    if cur != expect:
        die(f"{what}: bytes mismatch @0x{off:X}: {cur.hex()} != {expect.hex()}")
    print(f"  OK {what}: original @0x{off:X} confirmed")


def put(d, off, data, what):
    d[off:off + len(data)] = data
    print(f"  OK {what}: {len(data)}B embedded @0x{off:X}")


def e9(target, site):
    return b"\xE9" + struct.pack("<i", target - (site + 5))


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "winbox64.v3.43p8.exe")
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "winbox64.v3.43p9.exe")

    d = bytearray(open(src, "rb").read())
    if sha(d) != BASE_SHA256:
        die(f"base is not the canon! sha256={sha(d)}")
    print(f"Input OK: {src} (patch set v8, {len(d)} bytes)")
    n0 = len(d)

    # ============ step 1: retargets inside the jgmem cave (from v8) ============
    print("\n[1] Retargets inside the jgmem cave:")
    # 1a. After the path gate: xor r12d,r12d; lea rsi,... -> jmp to the
    # FSEEKFN piecewise cave. The flow leaves into the cmr.jg transit
    # (size check + CreateFileA + return).
    check(d, wf(0x6590D1), bytes.fromhex("4d31e4488d"),
          "path-gate tail (xor r12d; lea)")
    put(d, wf(0x6590D1), e9(0x659C00, 0x6590D1),
        "retarget -> FSEEKFN piecewise (0x659C00)")
    # 1b. After the fread substitution: cmp byte [rip+0x36E],... -> jmp to
    # the Range hook. The FREADFN interception for the Range call site.
    check(d, wf(0x65915A), bytes.fromhex("48833d6e03"),
          "fread tail (cmp byte [rip+])")
    put(d, wf(0x65915A), e9(0x6598A0, 0x65915A),
        "retarget -> Range hook (0x6598A0)")
    # 1c. After the transform: mov eax,edx; cmp rax,... -> jmp to
    # piecewise #2. The exit from the jgmem cave into the fseek
    # correction.
    check(d, wf(0x659369), bytes.fromhex("89d0483b05"),
          "transform tail (mov eax; cmp)")
    put(d, wf(0x659369), e9(0x659920, 0x659369),
        "retarget -> piecewise #2 (0x659920)")

    # ============ step 2: the new caves (5 .s) ============
    print("\n[2] New caves:")
    # Unified cave: the Ping/TR injections (Interface+VRF x2) + Policy
    # Rules strict:1->min:1 (same-length!). The zone is zero in v8
    # (beyond the code boundary of the jgmem cave 0x659000+1320B).
    cave = assemble("jg_unified_inject.s", 0x659560)
    check(d, wf(0x659560), b"\x00" * 0x20, "zone 0x659560 (zero)")
    put(d, wf(0x659560), cave, "unified cave (Ping/TR + strict:min:1)")

    # Range fread hook: push rax/rcx; compute the call site; store it.
    cave = assemble("range_boundary.s", 0x6598A0)
    check(d, wf(0x6598A0), b"\x00" * 0x20, "zone 0x6598A0 (zero)")
    put(d, wf(0x6598A0), cave, "Range fread hook")

    # Piecewise #2: the fseek correction by the Range zone boundaries.
    cave = assemble("fseek_correction.s", 0x659920)
    check(d, wf(0x659920), b"\x00" * 0x20, "zone 0x659920 (zero)")
    put(d, wf(0x659920), cave, "piecewise #2 (fseek correction)")

    # FSEEKFN piecewise: the cmr.jg transit (size check + CreateFileA +
    # SetFilePointer + CloseHandle; returns into the unified cave).
    cave = assemble("cmr_jg_transit.s", 0x659C00)
    check(d, wf(0x659C00), b"\x00" * 0x20, "zone 0x659C00 (zero)")
    put(d, wf(0x659C00), cave, "FSEEKFN piecewise (cmr.jg)")

    # Range pre-check: the marker gate (is "bignumberrange" in the buffer?).
    cave = assemble("range_marker_gate.s", 0x65A700)
    check(d, wf(0x65A700), b"\x00" * 0x20, "zone 0x65A700 (zero)")
    put(d, wf(0x65A700), cave, "Range pre-check (marker gate)")

    # ============ step 3: inline data ============
    print("\n[3] Data:")
    # The marker string for range_precheck (findmarker looks these 28B up
    # in the jg buffer).
    marker = b"bignumberrange',id:'q2c5504'"
    check(d, wf(0x65A750), b"\x00" * len(marker), "marker zone (zero)")
    put(d, wf(0x65A750), marker, f"'bignumberrange' marker ({len(marker)}B)")

    # The 0xFF filler: the piecewise zone boundaries (0x6598F8/FC/0x659900 -
    # qword values read by piecewise.s through cmp rax,[address]).
    ff15 = b"\xFF" * 15
    check(d, wf(0x6598F8), b"\x00" * 15, "zone 0x6598F8 (zero)")
    put(d, wf(0x6598F8), ff15, "0xFF filler (piecewise boundaries)")

    # ============ step 4: dead disk-write-era stab cleanup ============
    print("\n[4] Cleanup of the old v3 stab (disk-write era):")
    # Code stab (2463B): the push rbx,rsi,rdi,rbp,r12-r15 prologue of the
    # old jg_fields_cmr_gates cave - it wrote to disk (+367B), replaced in
    # v9 by the in-memory unified cave. Dead code since v8 (the fopen hook
    # was retargeted to 0x659000 there) - cleaned for hygiene.
    check(d, wf(0x65B400), bytes.fromhex("51525756534154415541564157"),
          "stab prologue (push cascade)")
    put(d, wf(0x65B400), b"\x00" * 2463, "code stab cleanup (2463B -> 0)")

    # Stab data (289B): "roteros.jg\0cmr.jg\0{name:'ARP'..."
    check(d, wf(0x65CE00), b"roteros.jg\x00cmr.jg\x00",
          "stab data (file names)")
    put(d, wf(0x65CE00), b"\x00" * 289, "stab data cleanup (289B -> 0)")

    # CMR jg fragment (21B): "[{name:'CMR Dashboard..."
    check(d, wf(0x65CF40), b"[{name:'CMR Dashboard", "CMR jg fragment")
    put(d, wf(0x65CF40), b"\x00" * 21, "CMR fragment cleanup (21B -> 0)")

    # ============ step 5: version 3.43.104.1 -> 3.43.104.3 ============
    print("\n[5] Version 3.43.104.3:")
    # ANSI titles (2 slots): same-length (104.1 -> 104.3).
    for off, old, new in [
        (0x1379B9, b"WinBox 3.43.104.1 (%s)", b"WinBox 3.43.104.3 (%s)"),
        (0x137FBC, b"WinBox 3.43.104.1",      b"WinBox 3.43.104.3"),
    ]:
        check(d, off, old, f"ANSI title @0x{off:X}")
        put(d, off, new + b"\x00", f"ANSI title -> '{new.decode()}'")
    # UTF-16 FileVersion/ProductVersion (2 slots): same-length.
    u16_old = "3.43.104.1".encode("utf-16-le")
    u16_new = "3.43.104.3".encode("utf-16-le")
    for off in (0x21C568, 0x21C69A):
        check(d, off, u16_old, f"UTF-16 version @0x{off:X}")
        put(d, off, u16_new, "UTF-16 -> '3.43.104.3'")

    # ============ final ============
    if len(d) != n0:
        die("size changed!")
    out_sha = sha(d)
    if out_sha != TARGET_SHA:
        die(f"REPRODUCIBILITY BROKEN! expected {TARGET_SHA}, got {out_sha}")
    open(out, "wb").write(d)
    print(f"\nWrote: {out}")
    print(f"  size  : {len(d)}")
    print(f"  sha256: {out_sha}")
    print("  byte-identical to the known-good community-patched build OK")


if __name__ == "__main__":
    main()
