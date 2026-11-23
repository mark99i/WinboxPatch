#!/usr/bin/env python3
"""
build-patched-v10.py - deterministic build of patch set v10.

    python build-patched-v10.py [base.exe] [out.exe]

Base:   winbox64.v3.43p9.exe (patch set v9,
        sha256 6a7abd5094a8a2abc1c2c6a59e6d57a453d089695dd4000961163205d389a799)
        plus the original winbox64.v3.43.exe in the repo root (the
        source of truth for the ESR restores; sha256 is verified too).
Output: winbox64.v3.43p10.exe, byte-identical to the known-good
        community-patched build (sha256
        448d32841bb9afa24435db7f78a650a8dfb54042c3ffef38efc94e5e9e8c2d8f,
        version stamp 3.43.104.4). File size unchanged; only the .text
        ESR sites and the .wbox range pre-check cave change.

Closed bugs:

  * ESR number grouping (a v99-era regression that survived through
    v115): the common number->string converter had been replaced
    in place with a CRT-free version that groups digits with a space
    every 3 ("65 536"). Intended for the Stats counters only, it hit
    EVERY numeric field: the Partition Offset "65 536" got a RED mark
    (validation rejects the space - the stock WB4-consistent
    semantics), the Disks "+" button broke (an add-abort on
    def:65536) and Apply threw "Error - number expected!". Fixed by
    restoring both ESR sites byte-exact from the ORIGINAL
    winbox64.v3.43.exe (the .text file offsets are identical between
    the original and the patched sets - verified via the PE headers);
    the grouping is gone completely (= WB4 behavior). Read-only
    counters ("1 176") use the native wb3 path and are not touched.

  * RouterOS 7.24.5 connections: the Range pre-check not-found branch
    (a 7.24 jg file carries no 'bignumberrange') jumped past the
    CloseHandle block (0x65915A-0x659186), leaving the jg file handle
    open -> a share-lock on roteros.jg -> "could not open" ->
    "Could not start plugins" -> disconnect. Fixed by reassembling
    the range pre-check cave: the not-found jmp now goes through the
    CloseHandle block (jmp 0x659187 -> 0x65915A, a 1-byte change
    inside the rel32).

Components (delta v9 -> v10):

  * step 1 - ESR(1) converter body @0x46BF23 (142B, .text file
    0x6B323): a byte-exact copy from the original binary.
  * step 2 - ESR(2) call site @0x46810F (12B, .text file 0x6750F):
    a byte-exact copy (mov r8d,0xA; call [IAT _ui64toa]).
  * step 3 - the Range pre-check cave @0x65A700 (65B, .wbox),
    reassembled from asm/range_marker_gate_p10.s (the 7.24 CloseHandle
    fix; the rest of the cave is identical to the v9 marker gate).
  * step 4 - version stamp 3.43.104.3 -> 3.43.104.4 (same-length,
    2 ANSI + 2 UTF-16 slots).

The original winbox64.v3.43.exe is the source of truth for the ESR
zones (no hardcoded hex strings).

Asserts: base and original-binary sha256; the original bytes of every
zone before each patch; the result sha256 (byte-exact
reproducibility).
"""
import hashlib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

BASE_SHA256   = "6a7abd5094a8a2abc1c2c6a59e6d57a453d089695dd4000961163205d389a799"
TARGET_SHA    = "448d32841bb9afa24435db7f78a650a8dfb54042c3ffef38efc94e5e9e8c2d8f"
VIRGIN_SHA256 = "5b41cf51fd81e8d082687f6b522159cf4aba22e6df8edc486721d4e09507b6e9"

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


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "winbox64.v3.43p9.exe")
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "winbox64.v3.43p10.exe")

    d = bytearray(open(src, "rb").read())
    if sha(d) != BASE_SHA256:
        die(f"base is not the canon! sha256={sha(d)}")
    print(f"Input OK: {src} (patch set v9, {len(d)} bytes)")
    n0 = len(d)

    # The original binary: the source of truth for the ESR restores.
    virgin = open(os.path.join(HERE, "winbox64.v3.43.exe"), "rb").read()
    if sha(virgin) != VIRGIN_SHA256:
        die(f"original binary is not the canon! sha256={sha(virgin)}")
    print(f"Original OK: winbox64.v3.43.exe ({len(virgin)} bytes)")

    # ============ step 1: ESR(1) converter body <- original ============
    print("\n[1] ESR(1) converter body (number->string):")
    # The .text file offsets are identical between the original and the
    # patched sets (both: file 0x400, VA 0x401000) -> copy by offset.
    ESR1_OFF, ESR1_LEN = 0x6B323, 142    # converter body @VA 0x46BF23
    virgin_esr1 = virgin[ESR1_OFF:ESR1_OFF + ESR1_LEN]
    # The base must hold the v99-era space-grouping converter here
    # (lea r13,[rsp+0x30]; call ...).
    check(d, ESR1_OFF, bytes.fromhex("4c8d6c2430"), "ESR(1) grouper prefix")
    put(d, ESR1_OFF, virgin_esr1, f"ESR(1) <- original ({ESR1_LEN}B)")
    assert bytes(d[ESR1_OFF:ESR1_OFF + ESR1_LEN]) == virgin_esr1

    # ============ step 2: ESR(2) call site <- original ============
    print("\n[2] ESR(2) call site:")
    ESR2_OFF, ESR2_LEN = 0x6750F, 12     # call site @VA 0x46810F
    virgin_esr2 = virgin[ESR2_OFF:ESR2_OFF + ESR2_LEN]
    # The base must hold the retarget to the grouper (mov r9,r8; call ...).
    check(d, ESR2_OFF, bytes.fromhex("4989c9e8"), "ESR(2) retarget prefix")
    # The original must be mov r8d,0xA + an IAT call (_ui64toa).
    assert virgin_esr2[:4] == bytes.fromhex("41b80a00"), \
        f"ESR(2) original unexpected: {virgin_esr2.hex()}"
    put(d, ESR2_OFF, virgin_esr2, f"ESR(2) <- original ({ESR2_LEN}B)")
    assert bytes(d[ESR2_OFF:ESR2_OFF + ESR2_LEN]) == virgin_esr2

    # ============ step 3: Range pre-check 7.24 fix (.wbox) ============
    print("\n[3] Range pre-check (7.24 CloseHandle fix):")
    # The cave is reassembled with the not-found jmp routed through the
    # CloseHandle block (0x659187 -> 0x65915A, a 1-byte change inside the
    # rel32); the rest is identical to the v9 marker gate. The zone holds
    # the v9 gate - the cave is rewritten over it in full (same 65B layout).
    cave = assemble("range_marker_gate_p10.s", 0x65A700)
    put(d, wf(0x65A700), cave[:65], "range pre-check + 7.24 fix (65B)")

    # ============ step 4: version 3.43.104.3 -> 3.43.104.4 ============
    print("\n[4] Version 3.43.104.4:")
    # ANSI titles (2 slots): same-length (104.3 -> 104.4).
    for off, old, new in [
        (0x1379B9, b"WinBox 3.43.104.3 (%s)", b"WinBox 3.43.104.4 (%s)"),
        (0x137FBC, b"WinBox 3.43.104.3",      b"WinBox 3.43.104.4"),
    ]:
        check(d, off, old, f"ANSI title @0x{off:X}")
        put(d, off, new + b"\x00", f"ANSI title -> '{new.decode()}'")
    # UTF-16 FileVersion/ProductVersion (2 slots): same-length.
    u16_old = "3.43.104.3".encode("utf-16-le")
    u16_new = "3.43.104.4".encode("utf-16-le")
    for off in (0x21C568, 0x21C69A):
        check(d, off, u16_old, f"UTF-16 version @0x{off:X}")
        put(d, off, u16_new, "UTF-16 -> '3.43.104.4'")

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
