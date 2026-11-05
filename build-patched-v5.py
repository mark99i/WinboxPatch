#!/usr/bin/env python3
"""
build-patched-v5.py - deterministic build of patch set v5.

Patch set v5 = patch set v4 (v98) plus initial RouterOS 7.26 / CMR support
(see ANALYSIS-726.md; file offsets, .text VMA 0x401000 = file 0x400,
.wbox VMA 0x638000 = file 0x22E600):

  * layer 1 - CMR table model-unfolding: RouterOS 7.26+CMR wraps the table
    properties (path, c: with the columns) into a model:{...} node; the
    'table' handler only looked for them on the node itself -> zero
    columns -> NULL-array clone crash (AV 0x47c65e) right after connect.
    The property-loop hook at VA 0x4A4A3E reroutes unknown properties to
    cave_model (VA 0x657820), which unwraps model nodes and re-enters the
    loop head (path/c keep working natively).
  * layer 2 - Dashboard NULL-resource guard: the virtual selector (edx=3)
    of Dashboard objects (class 0x5ABEC8) returns NULL/dangling; the hook
    at VA 0x49704A leads to cave_dash (VA 0x657860), which skips the
    resource read when rax==NULL (AV 0x49705B on opening CMR Dashboard).
  * layer 3 - Dashboard child validation: children fed to the notify loop
    (0x496F2E) carry a child-array at +0x8 instead of an nv::string;
    borrowing that garbage string corrupted the heap. cave_dash2
    (VA 0x657890) validates the string (non-NULL, inner pointer in the
    heap window, sane length) before the borrow and exits through the
    function epilogue on failure.
  * layer 4 - CMR menu icons: 9 icons rasterized from the webfig 7.26
    inline-SVG CSS into sprite cells 48,49,52-58 (row 1, 32-column grid)
    of icons16/24/32-cmr.png. The sprites replace the original webfig
    7.24.5 files in place inside .wbox: the new PNGs are smaller than the
    originals and the rest of each zone is zero-padded (the PNG parser
    stops at IEND; the startup extractor writes by the original sizes
    from its table, which stays valid).

No version-stamp change.

Input:  winbox64.v3.43p4.exe (patch set v4 = v98, sha256 4b861b5a...)
Output: winbox64.v3.43p5.exe, byte-identical to the known-good
        community-patched build (sha256 84999acf...).

The sprite sources icons16/24/32-cmr.png must sit in the icons/ folder
next to this script:
each is the new PNG plus zero padding, exactly the new zone content
(magic, IEND position and padding are verified below).
"""
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "winbox64.v3.43p4.exe")
OUT = os.path.join(HERE, "winbox64.v3.43p5.exe")

BASE_SHA    = "4b861b5a0508df19b93b888453a1072e94c8feddd760a3a6f7fa864c8b1de1dd"
TARGET_SHA  = "84999acf0cc20179ab8e77d0cb16e0cabd4fd756aafcebf946e790cc783016a7"
TARGET_SIZE = 2418176

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def die(m):
    print(f"FAIL: {m}")
    sys.exit(1)


def va2off_text(va):              # .text: VMA 0x401000 = file 0x400
    return 0x400 + (va - 0x401000)


def va2off_wbox(va):              # .wbox: VMA 0x638000 = file 0x22E600
    return 0x22E600 + (va - 0x638000)


# --- caves (.wbox, zero zone 0x657820..0x658000 behind the v4 frag blob) ---
CAVE_MODEL = bytes.fromhex(                      # 40B, VA 0x657820
    "3d65646f6d751c498b1424807a046c75124c89e2488d4c2428e872dce2ffe9d1"
    "d1e4ffe9f2d2e4ff")
CAVE_DASH = bytes.fromhex(                       # 35B, VA 0x657860
    "4989c64885c07416488b83a000000048398398000000498b16e9e0f7e3ffe9cc"
    "f8e3ff")
CAVE_DASH2 = bytes.fromhex(                      # 61B, VA 0x657890
    "488b51084885d27423488b02483d0000d8067218483d00000008731081380010"
    "000077084889cbe991f6e3ff4883c4485b5e5f5d415c415d415e415fc3")
assert len(CAVE_MODEL) == 40
assert len(CAVE_DASH) == 35
assert len(CAVE_DASH2) == 61

# --- sprite zones (.wbox): file offset, zone size, new PNG size, source ---
SPRITES = [
    (0x22F600, 25219, 20354, "icons16-cmr.png"),
    (0x235883, 41114, 34065, "icons24-cmr.png"),
    (0x23F91D, 56951, 48786, "icons32-cmr.png"),
]


def png_iend_end(data):
    """Offset just past the IEND chunk of a PNG, or None."""
    off = 8
    while off + 8 <= len(data):
        ln = int.from_bytes(data[off:off + 4], "big")
        typ = data[off + 4:off + 8]
        off += 12 + ln
        if typ == b"IEND":
            return off
    return None


def main():
    blob = open(SRC, "rb").read()
    h = hashlib.sha256(blob).hexdigest()
    if h != BASE_SHA:
        die(f"input sha256 {h} is not the v98 (patch set v4) base")
    if len(blob) != TARGET_SIZE:
        die(f"input size {len(blob)} != {TARGET_SIZE}")
    print("Input OK: winbox64.v3.43p4.exe (v98)")
    d = bytearray(blob)

    # --- layer 1: property loop -> cave_model (CMR table unfolding) ---
    HO = va2off_text(0x4A4A3E)
    if bytes(d[HO:HO + 6]) != bytes.fromhex("0f85f6000000"):
        die(f"hook1 original bytes: {bytes(d[HO:HO + 6]).hex()}")
    rel = 0x657820 - (0x4A4A3E + 6)
    assert rel == 0x1B2DDC
    d[HO:HO + 6] = b"\x0f\x85" + rel.to_bytes(4, "little")
    CO = va2off_wbox(0x657820)
    if any(d[CO:CO + 64]):
        die("cave_model zone is not free")
    d[CO:CO + 40] = CAVE_MODEL
    print("  layer 1: CMR table model-unfolding installed")

    # --- layer 2: Dashboard NULL-resource guard ---
    HO = va2off_text(0x49704A)
    if bytes(d[HO:HO + 17]) != bytes.fromhex(
            "4989c6488b83a000000048398398000000"):
        die(f"hook2 original bytes: {bytes(d[HO:HO + 17]).hex()}")
    rel = 0x657860 - (0x49704A + 5)
    assert rel == 0x1C0811
    d[HO:HO + 5] = b"\xe9" + rel.to_bytes(4, "little")
    d[HO + 5:HO + 17] = b"\x90" * 12
    CO = va2off_wbox(0x657860)
    if any(d[CO:CO + 64]):
        die("cave_dash zone is not free")
    d[CO:CO + 35] = CAVE_DASH
    print("  layer 2: Dashboard NULL-resource guard installed")

    # --- layer 3: Dashboard child validation ---
    HO = va2off_text(0x496F46)
    if bytes(d[HO:HO + 7]) != bytes.fromhex("488b51084889cb"):
        die(f"hook3 original bytes: {bytes(d[HO:HO + 7]).hex()}")
    rel = 0x657890 - (0x496F46 + 5)
    assert rel == 0x1C0945
    d[HO:HO + 5] = b"\xe9" + rel.to_bytes(4, "little")
    d[HO + 5:HO + 7] = b"\x90\x90"
    CO = va2off_wbox(0x657890)
    if any(d[CO:CO + 64]):
        die("cave_dash2 zone is not free")
    d[CO:CO + 61] = CAVE_DASH2
    print("  layer 3: Dashboard child validation installed")

    # --- layer 4: CMR icons (sprite zones replaced in place) ---
    for off, zone, png_len, name in SPRITES:
        data = open(os.path.join(HERE, "icons", name), "rb").read()
        if len(data) != zone:
            die(f"{name}: {len(data)} bytes, expected the {zone}-byte zone image")
        if data[:8] != PNG_MAGIC:
            die(f"{name}: not a PNG")
        iend = png_iend_end(data)
        if iend != png_len:
            die(f"{name}: IEND at {iend}, expected {png_len}")
        if any(data[iend:]):
            die(f"{name}: padding after IEND is not zero")
        if bytes(d[off:off + 8]) != PNG_MAGIC:
            die(f"sprite zone @0x{off:X} does not hold the original PNG")
        d[off:off + zone] = data
    print("  layer 4: CMR icons (cells 48,49,52-58) installed")

    # --- final verification ---
    if len(d) != TARGET_SIZE:
        die(f"size mismatch: {len(d)} != {TARGET_SIZE}")
    out_h = hashlib.sha256(bytes(d)).hexdigest()
    if out_h != TARGET_SHA:
        die(f"result does not match the known-good community-patched build "
            f"(expected {TARGET_SHA}, got {out_h})")
    open(OUT, "wb").write(bytes(d))
    print(f"Wrote: {OUT} ({len(d)} bytes)")
    print(f"  sha256: {out_h}")
    print("  byte-identical to the known-good patched build OK")


if __name__ == "__main__":
    main()

