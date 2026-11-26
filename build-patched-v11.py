#!/usr/bin/env python3
"""
build-patched-v11.py - deterministic build of patch set v11.

    python build-patched-v11.py [base.exe] [out.exe]

Base:   winbox64.v3.43p10.exe (patch set v10,
        sha256 448d32841bb9afa24435db7f78a650a8dfb54042c3ffef38efc94e5e9e8c2d8f).
Output: winbox64.v3.43p11.exe, byte-identical to the known-good
        community-patched build (sha256
        33a2e8061b589429fe25a49fec98a6ce2c75bbcef75aff96422b4f61d67144ba,
        version stamp 3.43.104.5). File size unchanged; the .text ESR
        sites stay virgin (the v10 invariant) - only the seven utf8e
        hook sites (<= 6B each, 25B total) are touched in .text.

New in v11 (esrc + utf8e):

  * ESR grouping of read-only counters (esrc): a single .rdata vtable
    slot swap (0x596CE0, the plain-u64 type slot) redirects the
    number->string conversion to a new cave (esrc_conv, 136B
    @0x65B500, assembled from asm/esrc_conv.s). The ESR algorithm:
    a div-10 loop, digit groups of 3, a space separator, CRT-free,
    the full u64 range, negatives handled exactly like the stock
    formatter. The old formatter 0x46BEFC and its thunk 0x46BFCC
    become dead code (left untouched). Read Ops 8.6e9 renders as
    "8 589 934 747". Unlike the v10 ESR restore (which removed the
    grouping from EVERY field to fix the editable-field regression),
    this targets the u64 type slot only - the read-only counters
    get the grouping back with zero .text edits.

  * "Use UTF-8" option (utf8e, conversion at the M2 boundary):
      - receive: UTF-8 -> ACP on the way into the model (storage_conv,
        hook @0x42AC14 in the M2 value decoder) - Russian comments
        written by WinBox 4 become readable;
      - send native-edit: ACP -> UTF-8 (conv_gwta @0x42F3C6, after
        GetWindowTextA; stub_dblres @0x42F3A0 doubles the edit-field
        reserve);
      - send canvas: ACP -> UTF-8 (cf286_hook @0x4CF286, gated by the
        caller return address 0x51EFF2) - a Russian WiFi SSID reaches
        the router as UTF-8;
      - menu: a "Use UTF-8" checkbox (id 0x99A) + utf8.dat persistence.
    OFF (the default) = byte-for-byte stock behavior.

Components (delta v10 -> v11):

  * step 1 - esrc: the .rdata vtable slot 0x596CE0 (file 0x1950E0):
    0x46BFCC -> 0x65B500 (8B; a 3-byte effective diff) + the esrc_conv
    cave (136B @0x65B500).
  * step 2 - utf8e: seven .text hooks (<= 6B each). Where the high
    rel32 bytes coincide with the original target, only the low bytes
    are rewritten (sizes 2/3B); otherwise a full e9/e8 encoding.
  * step 3 - utf8e: the cave @0x65B600 (assembled from
    asm/utf8_option.s). The .s output is 2645B with a 1090B zero tail
    - only the useful 1555B are embedded (the zero data cells are
    already zero in the zone).
  * step 4 - version stamp 3.43.104.4 -> 3.43.104.5 (same-length,
    2 ANSI + 2 UTF-16 slots).

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

BASE_SHA256 = "448d32841bb9afa24435db7f78a650a8dfb54042c3ffef38efc94e5e9e8c2d8f"
TARGET_SHA  = "33a2e8061b589429fe25a49fec98a6ce2c75bbcef75aff96422b4f61d67144ba"

# --- PE offsets ---
TEXT_VA, TEXT_FILE = 0x401000, 0x400
WBOX_FILE, WBOX_VA = 0x22E600, 0x638000

def tf(va):    # .text: VA -> file
    return va - TEXT_VA + TEXT_FILE

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
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "winbox64.v3.43p10.exe")
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "winbox64.v3.43p11.exe")

    d = bytearray(open(src, "rb").read())
    if sha(d) != BASE_SHA256:
        die(f"base is not the canon! sha256={sha(d)}")
    print(f"Input OK: {src} (patch set v10, {len(d)} bytes)")
    n0 = len(d)

    # ============ step 1: esrc (vtable slot + cave) ============
    print("\n[1] ESR (esrc): vtable slot + cave:")
    # The .rdata vtable slot 0x596CE0 (file 0x1950E0) is the plain-u64
    # type slot of the 0x596CC8 type table; it must point at the stock
    # thunk 0x46BFCC. Swap it to the esrc_conv cave (0x65B500): 8B
    # written, a 3-byte effective diff (cc bf 46 -> 00 b5 65).
    slot_off = 0x1950E0
    current_ptr = struct.unpack("<Q", bytes(d[slot_off:slot_off + 8]))[0]
    if current_ptr != 0x46BFCC:
        die(f"slot points at 0x{current_ptr:X}, not the thunk!")
    print("  OK vtable slot @0x596CE0: original -> 0x46BFCC (thunk)")
    put(d, slot_off, struct.pack("<Q", 0x65B500),
        "vtable slot -> 0x65B500 (esrc_conv)")

    # The esrc_conv cave (136B): the ESR div-10 grouping for the
    # read-only u64 counters. The zone is zero in v10 (the v9 stab
    # cleanup left the whole 0x65B400+ region zero).
    cave = assemble("esrc_conv.s", 0x65B500)
    if len(cave) != 136:
        die(f"esrc_conv: {len(cave)}B != 136B!")
    zone = bytes(d[wf(0x65B500):wf(0x65B500) + 136])
    if any(zone):
        die("zone 0x65B500 is not zero!")
    print("  OK zone 0x65B500: zero confirmed")
    put(d, wf(0x65B500), cave, "esrc_conv cave (ESR div-10, u64)")

    # ============ step 2: utf8e - the seven .text hooks ============
    print("\n[2] UTF-8 (utf8e): .text hooks:")
    # (VA, original hex, new hex, what). The 2/3-byte entries rewrite
    # only the low bytes of an existing rel32 - the high bytes already
    # coincide (both the old swap-cave targets and the new cave live in
    # 0x65Bxxx, sharing the same 0x00/0x1A/0x19/0x23 high bytes).
    hooks = [
        (0x42AC14, "e6460a",         "240c23",         "M2 decoder (storage_conv receive)"),
        (0x42F3A0, "4531c089da",     "e98bc42200",     "stub_dblres (send reserve x2)"),
        (0x42F3C6, "ff1504731c00",   "e8bcc5220090",   "conv_gwta (send native-edit)"),
        (0x4B41F9, "bb6f",           "5575",           "menu dispatcher"),
        (0x4B6256, "244e",           "a653",           "menu builder"),
        (0x4BC759, "98e9",           "30ef",           "menu writer (utf8.dat)"),
        (0x4CF286, "488b02448b",     "e916c81800",     "cf286_hook (send canvas/SSID)"),
    ]
    for va, orig_hex, new_hex, what in hooks:
        off = tf(va)
        check(d, off, bytes.fromhex(orig_hex), f"{what} (original)")
        put(d, off, bytes.fromhex(new_hex), f"{what} @0x{va:X}")

    # ============ step 3: utf8e - the cave ============
    print("\n[3] UTF-8 (utf8e): cave:")
    # The .s assembles to 2645B, but the 1090B tail is zero-initialized
    # data cells (.zero) - the zone already holds zeros there, so only
    # the useful 1555B are embedded (code + "Use UTF-8" + "\utf8.dat";
    # the trailing NUL and the data cells come from the zero zone).
    cave2 = assemble("utf8_option.s", 0x65B600)
    if len(cave2) < 1555:
        die(f"utf8_option: {len(cave2)}B < 1555B!")
    cave2 = cave2[:1555]
    zone2 = bytes(d[wf(0x65B600):wf(0x65B600) + 1555])
    if any(zone2):
        die("zone 0x65B600 is not zero!")
    print("  OK zone 0x65B600: zero confirmed")
    put(d, wf(0x65B600), cave2, "utf8_option cave (1555B)")

    # ============ step 4: version 3.43.104.4 -> 3.43.104.5 ============
    print("\n[4] Version 3.43.104.5:")
    # ANSI titles (2 slots): same-length (104.4 -> 104.5).
    for off, old, new in [
        (0x1379B9, b"WinBox 3.43.104.4 (%s)", b"WinBox 3.43.104.5 (%s)"),
        (0x137FBC, b"WinBox 3.43.104.4",      b"WinBox 3.43.104.5"),
    ]:
        check(d, off, old, f"ANSI title @0x{off:X}")
        put(d, off, new + b"\x00", f"ANSI title -> '{new.decode()}'")
    # UTF-16 FileVersion/ProductVersion (2 slots): same-length.
    u16_old = "3.43.104.4".encode("utf-16-le")
    u16_new = "3.43.104.5".encode("utf-16-le")
    for off in (0x21C568, 0x21C69A):
        check(d, off, u16_old, f"UTF-16 version @0x{off:X}")
        put(d, off, u16_new, "UTF-16 -> '3.43.104.5'")

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
