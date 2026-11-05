#!/usr/bin/env python3
"""
build-patched-v7.py - deterministic build of patch set v7.

    python build-patched-v7.py [base.exe] [out.exe]

Base:   winbox64.v3.43p6.exe (patch set v6,
        sha256 bb46e3e83cff5bbb4098aba4e7960cd7bf71bf697ff9a580762c6718206fd256).
Output: winbox64.v3.43p7.exe, byte-identical to the known-good
        community-patched build (sha256
        f2e3e610618cbd0d79044d53005a679c421876b886a840c4e5f06febab5ad857,
        version stamp 3.43.103.77).

Patch set v7 = patch set v6 + six patch steps + a version stamp. All new
caves are assembled from the .s sources next to this script with the real
GNU toolchain (as + ld -Ttext + objcopy -O binary) - the same pipeline
as the v4 converter blobs:

  * step 1 - PE: the .wbox section grows by 64KB (SizeOfImage
    0x258000 -> 0x268000, VirtualSize/RawSize 0x20000 -> 0x30000, 64KB
    of zeros appended; the new free zone is VA 0x658000-0x668000).
  * step 2 - retire the v5 layer-3 Dashboard child-validation hook:
    the hook site 0x496F46 is restored to its pristine bytes and the
    leftover cave ranges are zeroed (the Dashboard is now handled by
    the step-4 free-shield).
  * step 3 - esr5 "Swap title order" (swap_title_order.s, 782B blob at
    0x65B07E, four retarget hooks at 0x4B41F8/0x4B6255/0x4BC758/0x4B478F):
    the window title is rebuilt on every menu refresh/toggle.
  * step 4 - CMR improvements: Dashboard free-shield
    (cmr_dashboard_fix.s, 68B at 0x658000): the hook at 0x4CF0DA validates
    the CRT allocation header at [buf-8] before free - the confirmed
    Dashboard crash fix.
  * step 5 - window title with a dynamic version (title_dynamic_version.s,
    145B at 0x657C00): replaces the previous title-tail mechanic at hook
    0x4B49F8; the " - WinBox " prefix is static and the version is copied
    from the PE title at 0x539BC3 on every call (NUL terminates the
    string), so the window title always matches the stamped version.
  * step 6 - jg stub (jg_fields_cmr_gates.s at 0x65B400, hook 0x4B7A17
    fopen): injects the missing Interface/VRF fields into the Ping and
    Traceroute dialogs of roteros.jg, applies the CMR type fixes to
    cmr.jg (drop-enmbools -> unwrap-tag -> tags-to-multi), closes the
    read handle before writing (sharing-violation fix) and gates every
    injection by scanning the dialog zone, so fields are never
    duplicated on repeated runs. The stab data at 0x65CE00 (340B from
    icons/cmr_icons.bin - the CMR-mechanics markers/templates, incl. the
    Dashboard icons) is restored after the stab code.
  * step 7 - version stamp 3.43.103.04 -> 3.43.103.63 (8 bytes: two
    .rdata title fields + two .rsrc VERSIONINFO fields).
  * step 8 - setversion (integrated as the setversion() function):
    103.63 -> 3.43.103.77 - ANSI titles + the UTF-16 FileVersion/
    ProductVersion fields of VERSIONINFO; the window title syncs
    automatically (the step-5 cave reads the PE title at 0x539BC3 on
    every call).

Requires GNU binutils (as/ld/objcopy) on PATH: preinstalled on the CI
Ubuntu runners; on Windows use WSL or MinGW-w64.
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

SRC_ESR5   = os.path.join(HERE, "asm", "swap_title_order.s")     # esr5 title swap
SRC_SHIELD = os.path.join(HERE, "asm", "cmr_dashboard_fix.s")    # CMR improvements: Dashboard free-shield
SRC_TITLE  = os.path.join(HERE, "asm", "title_dynamic_version.s")  # dynamic title
SRC_STAB   = os.path.join(HERE, "asm", "jg_fields_cmr_gates.s")  # jg fields + CMR + gates
DAT_ICONS  = os.path.join(HERE, "icons", "cmr_icons.bin")    # 340B stab data (CMR markers)

BASE_SHA    = "bb46e3e83cff5bbb4098aba4e7960cd7bf71bf697ff9a580762c6718206fd256"
TARGET_SHA  = "f2e3e610618cbd0d79044d53005a679c421876b886a840c4e5f06febab5ad857"
BASE_SIZE   = 2418176                 # 0x24E600
TARGET_SIZE = BASE_SIZE + 0x10000     # 0x25E600 (.wbox grows by 64KB)


def die(m):
    print(f"FAIL: {m}")
    sys.exit(1)


def ot(va):    # .text: VMA 0x401000 = file 0x400
    return 0x400 + (va - 0x401000)


def ow(va):    # .wbox: VMA 0x638000 = file 0x22E600
    return 0x22E600 + (va - 0x638000)


def asm(src, entry, va, tag):
    """Assemble a cave blob with the real GNU toolchain (as + ld + objcopy)."""
    with tempfile.TemporaryDirectory() as td:
        obj = os.path.join(td, tag + ".o")
        elf = os.path.join(td, tag + ".elf")
        bn = os.path.join(td, tag + ".bin")
        for args in (["as", "--64", "-o", obj, src],
                     ["ld", "-e", entry, "-Ttext", hex(va), "-o", elf, obj]):
            r = subprocess.run(args, capture_output=True, text=True)
            if r.returncode:
                die(f"{tag}: {' '.join(args[:2])} failed: {r.stderr[:300]}")
        subprocess.run(["objcopy", "-O", "binary", "--only-section=.text", elf, bn],
                       check=True)
        return open(bn, "rb").read()


def hook(f, va, opcode, target, tag, expect=None, total=5):
    """Retarget a call/jmp; asserts the expected base bytes and, for the
    esr5 hooks, that the target stays inside the esr5 blob zone."""
    old = bytes(f[ot(va):ot(va) + total])
    if expect and old != expect:
        die(f"{tag}: bytes at {va:#x} are {old.hex()}, expected {expect.hex()}")
    rel = target - (va + 5)
    f[ot(va):ot(va) + 5] = bytes([opcode]) + rel.to_bytes(4, "little")
    if total > 5:
        f[ot(va) + 5:ot(va) + total] = b"\x90" * (total - 5)
    if tag.startswith("esr5"):
        if not (0x65B07E <= target < 0x65B38C):
            die(f"{tag}: target {target:#x} is outside the esr5 blob zone")


def setversion(f, nn, scheme=103):
    """Integrated setversion (formerly setversion.py, scheme 3.43.<scheme>.<NN>):
    stamps the ANSI titles (0x1379b9, 24B, 'WinBox ... (%s)' and 0x137fbc,
    19B) and the UTF-16 FileVersion/ProductVersion fields of VERSIONINFO
    (@0x21C410). Touches nothing else; the window title syncs automatically -
    the step-5 cave reads the version from the PE title at 0x539BC3
    (= file 0x137fbc+7) on every call."""
    s = f"WinBox 3.43.{scheme}.{nn:02d}"       # ANSI titles
    s2 = f"3.43.{scheme}.{nn:02d}"             # UTF-16 field (max 12 chars)
    if len(s) > 19:
        die("title too long")
    if len(s2) > 12:
        die("UTF-16 version too long")
    pre = f"WinBox 3.43.{scheme}.".encode()
    if bytes(f[0x1379B9:0x1379B9 + len(pre)]) != pre:
        die(f"title1 is not {scheme}-scheme: {bytes(f[0x1379B9:0x1379D2])!r}")
    if bytes(f[0x137FBC:0x137FBC + len(pre)]) != pre:
        die(f"title2 is not {scheme}-scheme: {bytes(f[0x137FBC:0x137FCD])!r}")
    f[0x1379B9:0x1379B9 + 24] = (s + " (%s)").encode() + b"\x00" * (24 - len(s) - 5)
    f[0x137FBC:0x137FBC + 19] = s.encode() + b"\x00" * (19 - len(s))
    # UTF-16 FileVersion / ProductVersion (the FFI dwords stay untouched)
    R = 0x21C410
    seg = bytes(f[R:R + 0x2E8])
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
        if not old.startswith(f"3.43.{scheme}."):
            die(f"base UTF-16 version: {old}")
        f[R + v:R + v + 24] = nv

def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "winbox64.v3.43p6.exe")
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "winbox64.v3.43p7.exe")

    for p in (SRC_ESR5, SRC_SHIELD, SRC_TITLE, SRC_STAB, DAT_ICONS):
        if not os.path.exists(p):
            die(f"cave source missing: {p}")
    for tool in ("as", "ld", "objcopy"):
        if shutil.which(tool) is None:
            die(f"{tool} not found on PATH - install binutils "
                f"(on Windows: WSL or MinGW-w64)")

    base = open(src, "rb").read()
    h = hashlib.sha256(base).hexdigest()
    if h != BASE_SHA:
        die(f"input sha256 {h} is not the patch set v6 base")
    if len(base) != BASE_SIZE:
        die(f"input size {len(base)} != {BASE_SIZE}")
    print("Input OK: winbox64.v3.43p6.exe (patch set v6)")
    f = bytearray(base)

    # --- step 1: PE - grow .wbox by 64KB (new free zone 0x658000-0x668000) ---
    f[0xD2], f[0x372], f[0x37A] = 0x26, 0x03, 0x03
    f += b"\x00" * 0x10000
    print("  step 1: .wbox grown by 64KB (SizeOfImage 0x268000)")

    # --- step 2: retire the v5 layer-3 hook (0x496F46 -> pristine bytes) ---
    f[ot(0x496F46):ot(0x496F46) + 7] = bytes.fromhex("488b51084889cb")
    for va, ln in ((0x657890, 0x0E), (0x6578A0, 0x07), (0x6578A9, 0x06),
                   (0x6578AF, 0x02), (0x6578B2, 0x1C)):
        f[ow(va):ow(va) + ln] = b"\x00" * ln
    print("  step 2: v5 layer-3 hook retired (Dashboard now via the free-shield)")

    # --- step 3: esr5 "Swap title order" (swap_title_order.s, 782B) ---
    blob = asm(SRC_ESR5, "esr5", 0x65B07E, "esr5")
    if len(blob) != 0x30E:
        die(f"esr5 blob is {len(blob):#x} bytes, expected 0x30E")
    for va, ln in ((0x65B07E, 0x232), (0x65B2C0, 0x2F),
                   (0x65B300, 0x58), (0x65B380, 0xC)):
        if any(f[ow(va):ow(va) + ln]):
            die(f"esr5 zone {va:#x} is not free")
    f[ow(0x65B07E):ow(0x65B07E) + 0x232] = blob[0x000:0x232]
    f[ow(0x65B2C0):ow(0x65B2C0) + 0x2F] = blob[0x242:0x271]
    f[ow(0x65B300):ow(0x65B300) + 0x58] = blob[0x282:0x2DA]
    f[ow(0x65B380):ow(0x65B380) + 0xC] = blob[0x302:0x30E]
    hook(f, 0x4B41F8, 0xE9, 0x65B1B8, "esr5 dispatcher",
         expect=bytes.fromhex("6683fa0f0f87d7000000"), total=10)
    hook(f, 0x4B6255, 0xE8, 0x65B07E, "esr5 menurefresh",
         expect=bytes.fromhex("e8808e0100"))
    hook(f, 0x4BC758, 0xE8, 0x65B0F5, "esr5 reader",
         expect=bytes.fromhex("e8fc27ffff"))
    hook(f, 0x4B478F, 0xE9, 0x65B2C0, "esr5 gate",
         expect=bytes.fromhex("e8c0deffff"))
    print("  step 3: esr5 title swap installed (4 hooks)")

    # --- step 4: CMR improvements: Dashboard free-shield (cmr_dashboard_fix.s, 68B) ---
    shield = asm(SRC_SHIELD, "_start", 0x658000, "shield")
    f[ot(0x4CF0DA):ot(0x4CF0DA) + 7] = (bytes([0xE9])
                                        + (0x658000 - (0x4CF0DA + 5)).to_bytes(4, "little")
                                        + b"\x90\x90")
    f[ow(0x658000):ow(0x658000) + len(shield)] = shield
    print(f"  step 4: CMR improvements - Dashboard free-shield installed ({len(shield)}B)")


    # --- step 5: window title with a dynamic version (title_dynamic_version.s) ---
    title = asm(SRC_TITLE, "_start", 0x657C00, "title")
    f[ot(0x4B49F8):ot(0x4B49F8) + 8] = (bytes([0xE9])
                                        + (0x657C00 - (0x4B49F8 + 5)).to_bytes(4, "little")
                                        + b"\x90\x90\x90")
    # wipe the title zone of the previous mechanic first (0x657E00+ is the
    # live ENV cave of the 0x4302DA hook - do NOT touch it)
    f[ow(0x657C00):ow(0x657E00)] = b"\x00" * (0x657E00 - 0x657C00)
    f[ow(0x657C00):ow(0x657C00) + len(title)] = title
    print(f"  step 5: dynamic-version title installed ({len(title)}B)")

    # --- step 6: jg stub - Ping/Traceroute fields + CMR types + gates ---
    stab = asm(SRC_STAB, "jgpatch", 0x65B400, "stab")
    f[ot(0x4B7A17):ot(0x4B7A17) + 5] = (bytes([0xE9])
                                        + (0x65B400 - (0x4B7A17 + 5)).to_bytes(4, "little"))
    # zero the CODE zone only (up to 0x65CE00 - the data zone below stays)
    f[ow(0x65B400):ow(0x65CE00)] = b"\x00" * (0x65CE00 - 0x65B400)
    f[ow(0x65B400):ow(0x65B400) + len(stab)] = stab
    # stab data @0x65CE00 (340B: CMR-mechanics markers/templates - roteros.jg,
    # cmr.jg, ARP Ping, Interface, VRF, CMR Dashboard incl. its icons) -
    # restored after the stab (this is what keeps the CMR icons working)
    stab_data = open(DAT_ICONS, "rb").read()
    if len(stab_data) != 0x154:
        die(f"cmr_icons.bin is {len(stab_data):#x} bytes, expected 0x154")
    if any(f[ow(0x65CE00):ow(0x65CF54)]):
        die("the stab data zone @0x65CE00 is not free")
    f[ow(0x65CE00):ow(0x65CF54)] = stab_data
    f[ow(0x65CF54)] = 0x64       # canon trailing byte of the stab zone
    print(f"  step 6: jg stub installed ({len(stab)}B + 340B CMR data)")

    # --- step 7: version stamp 3.43.103.04 -> 3.43.103.63 ---
    for hi, lo in ((0x1379C9, 0x1379CA), (0x137FCC, 0x137FCD),
                   (0x21C57A, 0x21C57C), (0x21C6AC, 0x21C6AE)):
        f[hi], f[lo] = 0x36, 0x33        # '6', '3'
    print("  step 7: version stamp 3.43.103.63")

    # --- step 8: setversion -> final version stamp 3.43.103.77 ---
    setversion(f, 77, 103)
    print("  step 8: setversion -> 3.43.103.77")

    # --- sanity: the icon mechanics stay untouched ---
    outb = bytes(f)
    if outb[0x217AE0:0x21C40C] != base[0x217AE0:0x21C40C]:
        die("the .rsrc icon region changed")
    if outb[0x3AE78:0x3AED5] != base[0x3AE78:0x3AED5]:
        die("the icon loader ID changed")
    print("  sanity: icon mechanics untouched (== patch set v6)")

    # --- final verification ---
    if len(outb) != TARGET_SIZE:
        die(f"size mismatch: {len(outb)} != {TARGET_SIZE}")
    out_h = hashlib.sha256(outb).hexdigest()
    if out_h != TARGET_SHA:
        die(f"result does not match the known-good community-patched build "
            f"(expected {TARGET_SHA}, got {out_h})")
    open(out, "wb").write(outb)
    print(f"Wrote: {out} ({len(outb)} bytes)")
    print(f"  sha256: {out_h}")
    print("  byte-identical to the known-good community-patched build OK")


if __name__ == "__main__":
    main()
