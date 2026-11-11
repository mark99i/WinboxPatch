#!/usr/bin/env python3
"""
build-patched-v8.py - deterministic build of patch set v8.

    python build-patched-v8.py [base.exe] [out.exe]

Base:   winbox64.v3.43p7.exe (patch set v7,
        sha256 f2e3e610618cbd0d79044d53005a679c421876b886a840c4e5f06febab5ad857).
Output: winbox64.v3.43p8.exe, byte-identical to the known-good
        community-patched build (sha256
        665f7420baf57ece3d5382f446e1d57b4e4a76e751d51552eb96024c2df11fff,
        version stamp 3.43.104.1). File size unchanged.

Patch set v8 = patch set v7 + five components (all new caves are assembled
from the .s sources in the asm/ folder with the real GNU toolchain):

  * step 1 - Win7 launch (DPI-fallback marker gate): Win7 has no
    GetDpiForWindow. The fallback path arms a marker; a bridge in the
    host function jumps to the fallback path ONLY when the marker is
    armed (on Win10 the fallback is unreachable -> stock behavior, so
    false positives on GetDpiForWindow()==0 of dying windows - the
    close-tool freeze - are excluded). Inline patches, three zones.
  * step 2 - new jg field types of RouterOS 7.25+ displayed (ntp_display.s,
    0x658100): fields of the new types bigfixedpoint (NTP Time/Offset/
    Delay/...) and bignumberrange (Range fields) are unknown to the stock
    type parser and get skipped -> dialogs without data. The cave masks
    the type names in the jg image to ones the client knows
    (bigfixedpoint -> bignumber, bignumberrange -> numberrange) -> the
    fields render. Hook: the terminal type-parser fallback at 0x4A28AA.
  * step 3 - Num Set -> Apply fix (jgmem_ntp.s, 0x659000): Apply rejects
    Range input on 7.25+ ("num range not specified") because the Range
    field became bignumberrange, which the client cannot assemble. The
    cave keeps a transformed in-memory image of roteros.jg (Range -> a
    tuple of two bignumber, +37B, idempotent; the on-disk file stays
    untouched) and serves it through fopen/fread/fseek/fclose
    interception (msvcrt fread returns ITEMS n/size, not bytes; the
    handle gate matches the roteros.jg path strictly and clears on
    fclose - msvcrt REUSES FILE* structs, otherwise foreign files and
    the icon PNG sprites receive foreign data -> icons/WiFi/PPP/IPv6
    disappear). The old file stab at 0x65B400 stays as dead code.
    Hook: the fopen site 0x4B7A17.
  * step 4 - heap protection (shield):
      a) class 1 - invalid frees at jg load (shield_class1.s, 0x658000,
         over the existing release-hook cave): address checks
         (sentinel/NULL/low/align/freed-fill/uninit-fill) plus the
         parse-arena signature in the hi-dword [rcx-4] (byte0 in
         {0x80,0x90} and byte1 in {0x06,0x07}; legit Win10 blocks have
         byte1=0x00).
      b) class 2 - double free in the Dashboard element builder
         (shield_points.s, 0x658500, three mini-caves at 0x658500/
         0x658590/0x658620): the builder frees one object at three
         points without ownership tracking. Each cave dedups by target:
         the target in a ring of recent frees with a fresh stamp
         (legit-free counter delta <= 16 = an instant burst = a true
         double free -> skip; delta > 16 = the block was reallocated in
         between - the open/close window pattern -> a legit free).
         Retargets: the release points 0x496F69/0x497013/0x497152.
  * step 5 - version stamp 3.43.103.77 -> 3.43.104.1 (two ANSI titles +
    two UTF-16 VERSIONINFO fields; the new string is 1 byte shorter, the
    tail stays NUL).

The shield .s sources emit their static-data map as zeros beyond the code
boundary - the blobs are truncated to the code part (the statics are zero
in the base image and filled at runtime), otherwise they would overwrite
the Win7 helper at 0x658700.

Asserts: base sha256; the original bytes of every zone/hook before each
patch; the result sha256 (reproducibility).
"""
import hashlib
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

BASE_SHA256 = "f2e3e610618cbd0d79044d53005a679c421876b886a840c4e5f06febab5ad857"
TARGET_SHA  = "665f7420baf57ece3d5382f446e1d57b4e4a76e751d51552eb96024c2df11fff"

# Win7-fix placement (helper + marker): behind the shield code boundary -
# the shield cave occupies 0x658000-0x65809E, the old spot 0x658050 is taken.
W7_HELPER_VA, W7_MARKER_VA = 0x658700, 0x658710

# --- PE offsets ---
TEXT_FILE, TEXT_VA = 0x400, 0x401000
WBOX_FILE, WBOX_VA = 0x22E600, 0x638000

def tf(va):    # .text: VA -> file
    return TEXT_FILE + (va - TEXT_VA)


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


def e8(target, site):
    return b"\xE8" + struct.pack("<i", target - (site + 5))


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "winbox64.v3.43p7.exe")
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "winbox64.v3.43p8.exe")

    d = bytearray(open(src, "rb").read())
    if sha(d) != BASE_SHA256:
        die(f"base is not the canon! sha256={sha(d)}")
    print(f"Input OK: {src} (patch set v7, {len(d)} bytes)")
    n0 = len(d)

    # ============ step 1: Win7 launch (DPI-fallback marker gate) ============
    print("\n[1] Win7 launch (marker gate):")
    # The GetDpiForWindow fallback return site (0x5315A4, 5B): in the base it
    # is a tail jmp 0x43C248 WITHOUT popping the call-ret -> an epilogue with
    # a shifted stack -> crash. Replacement: jmp to the helper - stack-
    # identical (jmp, NOT call: a call would return on the second unwind and
    # do a double pop rbp).
    check(d, tf(0x5315A4), bytes.fromhex("e99facf0ff"), "ret site (crash root)")
    put(d, tf(0x5315A4), e9(W7_HELPER_VA, 0x5315A4), "ret site -> jmp helper")
    # Helper (9B): arms the "fallback taken" marker; the ret pops the host
    # call-ret.
    check(d, wf(W7_HELPER_VA), b"\x00" * 9, "helper zone (zero)")
    helper = bytes.fromhex("c60425") + struct.pack("<I", W7_MARKER_VA) + b"\x01\xc3"
    put(d, wf(W7_HELPER_VA), helper,
        f"helper: mov byte [0x{W7_MARKER_VA:X}],1; ret")
    # Bridge in the NOP field of the host function (0x43C21F, was 10x90):
    # test the marker; jne 0x43C248. The jump happens ONLY on a real
    # fallback (Win7 - no API); on Win10 the marker stays 0 forever ->
    # stock behavior.
    check(d, tf(0x43C21F), b"\x90" * 10, "bridge field (NOP)")
    bridge = bytes.fromhex("f60425") + struct.pack("<I", W7_MARKER_VA) + \
        bytes.fromhex("0175" + "1f")
    put(d, tf(0x43C21F), bridge, "bridge: test marker; jne 0x43C248")

    # ============ step 2: new jg field types displayed ============
    print("\n[2] jg field types of 7.25+ (NTP display):")
    cave = assemble("ntp_display.s", 0x658100)
    check(d, wf(0x658100), b"\x00" * min(len(cave), 0x60), "zone 0x658100 (zero)")
    put(d, wf(0x658100), cave, "type-masking cave")
    # Site 0x4A28AA: in the base - the terminal fallback of the type parser
    # (skip the unknown field). Retarget to the cave 0x658100: the 7.25 type
    # names (bigfixedpoint->bignumber, bignumberrange->numberrange) are
    # replaced with ones known to the client BEFORE parsing -> the fields
    # render.
    check(d, tf(0x4A28AA), bytes.fromhex("e9800000009090"), "type parser hook (original)")
    put(d, tf(0x4A28AA), e9(0x658100, 0x4A28AA) + b"\x90\x90",
        "retarget -> cave 0x658100")

    # ============ step 3: Num Set -> Apply (in-memory jg image) ============
    print("\n[3] Apply fix (in-memory roteros.jg image):")
    cave = assemble("jgmem_ntp.s", 0x659000)
    check(d, wf(0x659000), b"\x00" * 0x20, "zone 0x659000 (zero)")
    put(d, wf(0x659000), cave, "jg image cave")
    # fopen hook 0x4B7A17: in the base it leads to the file stab (0x65B400,
    # which stays as dead code). Retarget to the cave 0x659000: the
    # roteros.jg image is kept in memory (Range bignumberrange->tuple, +37B,
    # idempotent; handle gate for the roteros path only + fclose clearing -
    # otherwise foreign files/icon sprites receive foreign data). The on-disk
    # file is not modified -> Apply accepts the input.
    r_old = struct.unpack_from("<i", d, tf(0x4B7A17) + 1)[0]
    if 0x4B7A17 + 5 + r_old != 0x65B400:
        die("fopen hook: target is not 0x65B400!")
    put(d, tf(0x4B7A17), e9(0x659000, 0x4B7A17), "retarget -> image cave")

    # ============ step 4: heap protection (shield) ============
    print("\n[4] Heap protection (class-1 shield + dedup points x3):")
    # The shield cave is written OVER the existing one (the release hook
    # 0x4cf0da is already in place in the base); the signature of the old
    # content is the badsize check (a leak source: it blocked legit frees).
    # The new cave: address checks + the arena signature only.
    check(d, wf(0x658034), bytes.fromhex("3d000008007708"),
          "old badsize shield signature")
    check(d, wf(0x658050), b"\x00" * 0x50,
          "zone behind the shield (zero - the Win7 helper moved to 0x658700)")
    # The .s emits the static-data map as zeros BEYOND the code boundary -
    # the blob is truncated to the code (the statics are zero in the base,
    # filled at runtime); without the truncation the Win7 helper (0x658700)
    # would be overwritten.
    cave = assemble("shield_class1.s", 0x658000)[:0xA0]
    put(d, wf(0x658000), cave, "class-1 shield cave (0x658000-0x6580A0)")
    check(d, wf(0x658500), b"\x00" * 0x20, "zone 0x658500 (zero)")
    # Statics (dedup ring/stamps/counters @0x658738-0x6587F8) are zero in the
    # base and filled at runtime - no copy needed; truncate to the code
    # boundary.
    cave = assemble("shield_points.s", 0x658500)[:0x1A0]
    put(d, wf(0x658500), cave, "dedup point caves x3 (0x658500-0x6586A0)")
    # Retarget the three release points of the object builder (in the base:
    # a direct call of the release) to the dedup caves:
    for site, cave_va in [(0x496F69, 0x658500), (0x497013, 0x658590),
                          (0x497152, 0x658620)]:
        r_old = struct.unpack_from("<i", d, tf(site) + 1)[0]
        if d[tf(site)] != 0xE8 or site + 5 + r_old != 0x4CF0DA:
            die(f"release point 0x{site:X}: not a call 0x4CF0DA!")
        put(d, tf(site), e8(cave_va, site),
            f"release 0x{site:X} -> cave 0x{cave_va:X}")

    # ============ step 5: version 3.43.103.77 -> 3.43.104.1 ============
    print("\n[5] Version 3.43.104.1:")
    # ANSI titles (2 slots): the new string is 1B shorter - the tail stays
    # NUL (a C string in a fixed-capacity field; the FFI scheme untouched).
    for off, old, new in [
        (0x1379B9, b"WinBox 3.43.103.77 (%s)", b"WinBox 3.43.104.1 (%s)"),
        (0x137FBC, b"WinBox 3.43.103.77",      b"WinBox 3.43.104.1"),
    ]:
        check(d, off, old, f"ANSI title @0x{off:X}")
        put(d, off, new + b"\x00", f"ANSI title -> '{new.decode()}'")
    # UTF-16 FileVersion/ProductVersion (2 slots): same (NUL tail).
    u16_old = "3.43.103.77".encode("utf-16-le")
    u16_new = "3.43.104.1".encode("utf-16-le") + b"\x00\x00"
    for off in (0x21C568, 0x21C69A):
        check(d, off, u16_old, f"UTF-16 version @0x{off:X}")
        put(d, off, u16_new, "UTF-16 -> '3.43.104.1'")

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
