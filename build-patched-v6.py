#!/usr/bin/env python3
"""
build-patched-v6.py - deterministic build of patch set v6.

    python build-patched-v6.py [base.exe] [out.exe]

Base:   winbox64.v3.43p5.exe (patch set v5,
        sha256 84999acf0cc20179ab8e77d0cb16e0cabd4fd756aafcebf946e790cc783016a7).
Output: winbox64.v3.43p6.exe, byte-identical to the known-good
        community-patched build
        (sha256 bb46e3e83cff5bbb4098aba4e7960cd7bf71bf697ff9a580762c6718206fd256,
        version stamp 3.43.103.04).

Patch set v6 = patch set v5 + three feature layers + a version stamp
(20 byte clusters, 748 changed bytes, file size unchanged; a
"what is this patch responsible for" description sits before every
entry of the PATCHES table below):

  * WiFi: an empty interworking.realms-raw is no longer submitted on save;
  * ENV:  the Container ENV corner TZ widget is hidden (DPI-invariant);
  * ESR:  usability set from the teslasystems build - Ctrl+wheel zoom,
          Stats counters >= 10^9 with thousands grouping, window title
          "... - RouterOS v<ros> via WinBox 3.43.103.04", Log Entry keeps
          its selection on focus loss, filter-value swap fix;
  * VER:  resource ProductVersion/FileVersion -> 3.43.103.04.

.wbox zone map after v6: CMR caves 0x657820-0x6578F0 (v5), WiFi stub
0x657900, ESR corridor + 'GetAncestor'/' via ' strings 0x657A00-0x657B64,
ENV stub 0x657E00. NEVER statically occupy 0x63891A-0x639000: those are
runtime cells written at startup by the base layers (crash lesson of esr3).
"""
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

BASE_SHA    = "84999acf0cc20179ab8e77d0cb16e0cabd4fd756aafcebf946e790cc783016a7"
TARGET_SHA  = "bb46e3e83cff5bbb4098aba4e7960cd7bf71bf697ff9a580762c6718206fd256"
TARGET_SIZE = 2418176


def die(m):
    print(f"FAIL: {m}")
    sys.exit(1)


def va_rd(off):    # .text/.rdata: VMA 0x401000 = file 0x400
    return off + 0x400C00


def va_wbox(off):  # .wbox: VMA 0x638000 = file 0x22E600
    return off + 0x409A00


# ============================================================================
# PATCHES: (file_off, orig_hex, new_hex, name). Each cluster replaces exactly
# its own size - the file does not grow (total: 748 changed bytes in 20
# clusters). The original bytes are verified before every write; an already
# installed patch is skipped (idempotency). What each patch is responsible
# for is described in the comment above its entry.
# ============================================================================

PATCHES = [
    # ------------------------------------------------------------ layer A: WiFi
    # WiFi: saving a WiFi object submitted an EMPTY interworking.realms-raw
    # (varnum 0xd00d) - the router discarded it.

    # A1. Wire-serializer array-branch hook (VA 0x429811). Responsible for
    # the entry point of the WiFi fix: the original branch prologue that
    # computes the value length (`mov rax,[rbp+0x18]; sub rax,[rbp+0x10]`)
    # is replaced with a `jmp` to the A2 stub (.wbox VA 0x657900) - without
    # rewriting the whole serialization branch.
    (0x028C11, "488b4518482b4510", "e9eae02200909090", "A1 wifi hook"),

    # A2. WiFi stub (.wbox VA 0x657900, 28B). Responsible for the filtering
    # itself: restores the original length computation, then - if the length
    # is 0 AND varnum(edx)==0xb000d00d (low part 0xd00d = realms-raw) -
    # tail-jmps to the standard skip-node path 0x4298FC: an empty realms-raw
    # is not encoded into the wire message at all and is not submitted on
    # save. Otherwise it returns to the original flow (hook+8): non-empty
    # user values are encoded as before.
    (0x24DF00, "00" * 28,
     "488b4518482b4510750d81fa0dd000b07505e9e51fddffe9fd1eddff",
     "A2 wifi stub"),

    # ------------------------------------------------------------- layer B: ENV
    # Container -> ENV: the corner TZ widget rendered incorrectly.

    # B1. Geometry-setter hook (VA 0x4302DA). Responsible for the entry
    # point of the ENV fix: the prologue of the geometry setter (3 pushes:
    # r14/rbp/r12) is replaced with a `jmp` to the B2 stub (.wbox VA
    # 0x657E00) - it is exactly this setter that decides which container
    # elements are laid out where.
    (0x02F6DA, "415641554154", "e9217b220090", "B1 env hook"),

    # B2. ENV stub envfix17 (.wbox VA 0x657E00, 68B). Responsible for
    # hiding the corner TZ widget: performs the 3 original pushes, then a
    # gate - if the object's vtable != 0x5A6138 (not an ENV widget) or
    # width*10 >= height*7 (a DPI-invariant "small corner" check), control
    # returns to the original flow (hook+6) and everything works as before;
    # only an ENV widget with the ratio w*10 < h*7 is skipped - the TZ
    # widget is neither laid out nor rendered.
    (0x24E400, "00" * 68,
     "41564155415448813938615a007530418b4008412b00458b500c452b5004"
     "6bc00a456bd2074439d07d15418128008000004181680800800000fe0561"
     "010000e99c84ddff",
     "B2 env stub"),

    # --------------------------------------------------- layer C: ESR set
    # usability patches from the teslasystems build (see the Credits).

    # C1. ESR(1): body of the new integer converter (.text VA 0x46BF23,
    # 142B). Responsible for displaying large counters: a div-10 loop with
    # digit grouping by 3 (',' separator), CRT-free (no sprintf/itoa),
    # correct for values >= 10^9 where the original CRT path broke.
    # Replaces the former converter piece (cmp rcx,0x3E7 + sprintf chains).
    (0x06B323,
     "4981f9e70300004c8d6c24307f11488d1572a20c004c89e9e808940600"
     "eb6f4981f93f420f007f24b9e80300004489c831d2f7f14c89e989542420"
     "4189c1488d1547a20c00e8db930600eb424c89c8b940420f0041bae80300"
     "00489948f7f94989c34c89c84889d148994589d949f7fa89c84c89e98954"
     "242831d241f7f2488d1512a20c0089442420e897930600",
     "4c8d6c2430e81000000041803800747e49ffcd41c645002deb744983c51b"
     "41c645000049bb04000000000000004c89c849b90a0000000000000049ff"
     "cb751249bb030000000000000049ffcd41c645002048ba00000000000000"
     "0049f7f14883c23049ffcd418855004885c077ccc39041554989d5e8a0ff"
     "ffff4c89e8415dc39090909090909090909090909090",
     "C1 esr1 number converter"),

    # C2. ESR(2): Stats call-site (VA 0x46810F). Responsible for wiring the
    # C1 converter into the Stats window: the counter-formatting call
    # (`mov r8d,10; call [CRT sprintf]`) is re-targeted to the C1+0x70
    # entry - the Stats counters get thousands grouping and no longer
    # break on values >= 10^9.
    (0x06750F, "41b80a000000ff1525e11800", "4989c9e87c3e000090909090",
     "C2 esr2 stats call-site"),

    # C3. ESR(3): title-tail hook (VA 0x4B49F8). Responsible for invoking
    # the title builder: the original window-title tail call
    # (`mov r9,rcx; call ...`) is replaced with `mov eax,0x531468;
    # call rax` - the title builder from the C8 slack code, which builds
    # the tail " - RouterOS v<router_version> via WinBox 3.43.103.04".
    (0x0B3DF8, "4c89f1e8daa60100", "b868145300ffd090", "C3 esr3 title hook"),

    # C4. ESR(3): title string in .rsrc (file 0x136B7C). Responsible for
    # the title-tail text: the ANSI string '- WinBox (64bit) v' is replaced
    # with '- RouterOS v' - the window title shows the RouterOS version
    # instead of the client name (the rest is appended by the C8 builder).
    (0x136B7C, "57696e426f7820283634626974292076",
     "526f757465724f532076000000000000", "C4 esr3 title string"),

    # C5. ESR(3): imm32 of the title separator piece (rsrc, 0x1379C7).
    # Responsible for the version inside the title-tail mechanics:
    # '2.98' -> '3.04' (in sync with the new version stamp 3.43.103.04).
    (0x1379C7, "322e3938", "332e3034", "C5 esr3 title imm32"),

    # C6. ESR(3): imm32 of the 'WinBox <version>' string (rsrc, 0x137FCA).
    # Responsible for the version in the 'WinBox 3.43.10?.??' title string:
    # '2.98' -> '3.04' (the string itself lives @VA 0x539BBC).
    (0x137FCA, "322e3938", "332e3034", "C6 esr3 winbox ver imm32"),

    # C7. ESR(4): wheel-jmp (VA 0x42DB20). Responsible for wheel zoom: the
    # Ctrl+MOUSEWHEEL filter branch (`mov rcx,[rip+..]; test rcx,rcx; je`)
    # is replaced with `mov r9d,0x5314BF; jmp r9` - straight into the zoom
    # wheel handler of the C8 slack code (VA 0x5314BF = slack+0x57):
    # Ctrl+scroll zooms the list instead of scrolling it.
    (0x02CF20, "488b0d81ee1b004885c9740c", "41b9bf14530041ffe1909090",
     "C7 esr4 wheel jmp"),

    # C8. ESR(4): slack code (.rdata VA 0x531468, 327B, 0x147B active).
    # Responsible for three things at once (by offset from the start):
    #   +0x00 - 7 thunk stubs + ret: calls into the original string
    #           functions with the right registers (used by the title
    #           builder);
    #   +0x57 - the zoom wheel handler: on WM_MOUSEWHEEL (0x20A) with Ctrl
    #           it zooms the window (GetAncestor -> the root window,
    #           then SendMessage-based zooming);
    #   +0xFD - the GetAncestor resolver: dynamically finds the function
    #           (LoadLibraryA/GetProcAddress, the string from C11) without
    #           touching the IAT, the result is cached;
    #   next  - the title builder for C3: reads the RouterOS version and
    #           builds the " via WinBox <version>" tail (the C12 separator).
    (0x130868, "00" * 327,
     "4c89f1b8daf04c00ffd04c89f1ba607b6500b8def24c00ffd04c89e1babc9b5300"
     "b8def24c00ffd04c89f14c89e2b852f44c00ffd04c89e1b8daf04c00ffd04c89f9"
     "4c89f2b852f44c00ffd04c89f1b8daf04c00ffd0c3554883ec40488bec418b442408"
     "3d0a020000741a488b0dceb40b004885c9488d65405d0f8450c6efffe93fc6efff"
     "4d8b4c2410664183f90875da498b0c24ba02000000ff1538661200488945204889"
     "c1488d552f41b811000000ff15d1500c00488b4d20ba1101000041b86c0000003c"
     "0d740641b8ef0300004d8b4c241049c1e910664585c9790341ffc041b900000000"
     "ff15fa510c00488d65405de931c6efff488d65405d554883ec40488bec48894d38"
     "ba007b6500ff15d44a0c004885c0741e488905b8651200488b4d38ba51515300ff15"
     "b94a0c004989c44885c0750a488d65405de99facf0ff488d65405dc3",
     "C8 esr4 slack code"),

    # C9. ESR(4): GetAncestor resolver hook (VA 0x43C21A). Responsible for
    # dropping the IAT dependency: the original `lea rdx,'GetAncestor';
    # call [rip+IAT]` is replaced with a `call` to the C8+0xFD resolver
    # (dynamic resolution + cache, see C11) - no import-table edits needed.
    (0x03B61A, "488d15308f0f00ff15299e1b004989c44885c07419",
     "e846530f0090909090909090909090909090909090", "C9 esr4 GA resolver hook"),

    # C10. ESR(4): the filter-value swap-function corridor (.wbox VA
    # 0x657A00, 126B, 0x7EB active). Responsible for filter-value: the two
    # swap functions (the getter/setter of the filter value) are copied and
    # rebased here from 0x638A00 - in their original place they overlapped
    # the runtime cells 0x63891A-0x639000 which are overwritten at startup
    # (the esr3 crash lesson).
    (0x24E000, "00" * 126,
     "498b4c2450e87886ddff84c0756f498b742448488b5e60498b7c2450488b7f48"
     "488d4f6048813968d253007405e8a876e7ff48895f6048c7466068d25300c3"
     "498b4c2448e83986ddff84c07530498b742450488b7648488b5e60498b7c2448"
     "488d4f6048813968d253007405e86976e7ff48895f6048c7466068d25300c3",
     "C10 esr4 filter corridor"),

    # C11. ESR(4): the 'GetAncestor' string + the GA cache start (.wbox VA
    # 0x657B00, 11B). Responsible for the resolver data of C9: the API
    # function name for LoadLibraryA/GetProcAddress.
    (0x24E100, "00" * 11, "476574416e636573746f72", "C11 esr4 GA string"),

    # C12. ESR(4): the ' via ' separator string (.wbox VA 0x657B60, 5B).
    # Responsible for the title text: the separator between
    # "RouterOS v<version>" and "WinBox <version>" in the window-title tail.
    (0x24E160, "00" * 5, "2076696120", "C12 esr4 via string"),

    # C13. ESR(5): Log Entry (VA 0x4445E6, 1B!). Responsible for the
    # selection visibility: the ES_NOHIDESELECTION flag is added to the
    # Message edit control's style (0x00 -> 0x01) - the selected line stays
    # visible after the control loses focus.
    (0x0439E6, "00", "01", "C13 esr5 logentry style"),

    # C14. ESR(6): filter-value swap-function retarget (VA 0x45676A).
    # Responsible for wiring up the C10 corridor: the original slot load
    # `mov rbx,[rax+0x150]` is replaced with `mov ebx,0x657A00` - the calls
    # go to the rebased copy from C10.
    (0x055B6A, "488b9850010000", "bb007a65009090", "C14 esr6 filter retarget"),

    # ----------------------------------------------------------- layer D: VER
    # Version stamp 3.43.103.04 in the resources (UTF-16 '2.98' -> '3.04').

    # D1. ProductVersion in VERSIONINFO (rsrc, file 0x21C576). Responsible
    # for the version on the Details tab of the file properties
    # (ProductVersion).
    (0x21C576, "32002e00390038", "33002e00300034", "D1 ver ProductVersion"),

    # D2. FileVersion in VERSIONINFO (rsrc, file 0x21C6A8). Responsible
    # for the version on the Details tab of the file properties
    # (FileVersion).
    (0x21C6A8, "32002e00390038", "33002e00300034", "D2 ver FileVersion"),
]

def main():
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "winbox64.v3.43p5.exe")
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "winbox64.v3.43p6.exe")

    blob = open(src, "rb").read()
    h = hashlib.sha256(blob).hexdigest()
    if h != BASE_SHA:
        die(f"input sha256 {h} is not the patch set v5 base")
    if len(blob) != TARGET_SIZE:
        die(f"input size {len(blob)} != {TARGET_SIZE}")
    print("Input OK: winbox64.v3.43p5.exe (patch set v5)")
    d = bytearray(blob)

    for off, orig, new, name in PATCHES:
        o, n = bytes.fromhex(orig), bytes.fromhex(new)
        if len(o) != len(n):
            die(f"{name}: orig/new length mismatch ({len(o)} != {len(n)} bytes)")
        cur = bytes(d[off:off + len(n)])
        if cur == n:
            print(f"  {name}: already in place")
            continue
        if cur != o:
            die(f"{name}: original bytes @0x{off:X} are {cur.hex()}")
        d[off:off + len(n)] = n
        print(f"  {name}: installed")

    # --- cross-references: hook targets computed from the written bytes ---
    def rel32(off):
        return struct.unpack("<i", d[off:off + 4])[0]

    xrefs = [
        ("A1 wifi hook -> A2 stub",      va_rd(0x28C11 + 5) + rel32(0x28C12), 0x657900),
        ("A2 wifi stub -> skip-node",    va_wbox(0x24DF00 + 0x17) + rel32(0x24DF00 + 0x13), 0x4298FC),
        ("A2 wifi stub -> hook+8",       va_wbox(0x24DF00 + 0x1C) + rel32(0x24DF00 + 0x18), va_rd(0x28C11 + 8)),
        ("B1 env hook -> B2 stub",       va_rd(0x2F6DA + 5) + rel32(0x2F6DB), 0x657E00),
        ("B2 env stub -> hook+6",        va_wbox(0x24E400 + 0x44) + rel32(0x24E400 + 0x40), va_rd(0x2F6DA + 6)),
        ("C2 stats call -> C1 entry+70", va_rd(0x67512 + 5) + rel32(0x67513), 0x46BF93),
        ("C3 title hook -> C8 slack",    struct.unpack("<I", d[0xB3DF9:0xB3DFD])[0], 0x531468),
        ("C7 wheel jmp -> C8 slack+57",  struct.unpack("<I", d[0x2CF22:0x2CF26])[0], 0x5314BF),
        ("C8 slack+57 is push rbp",      d[0x130868 + 0x57], 0x55),
        ("C9 GA hook -> C8 slack+FD",    va_rd(0x3B61A + 5) + rel32(0x3B61B), 0x531565),
        ("C14 filter -> C10 corridor",   struct.unpack("<I", d[0x55B6B:0x55B6F])[0], 0x657A00),
    ]
    for what, got, want in xrefs:
        if got != want:
            die(f"xref {what}: {got:#x} != {want:#x}")
    print(f"xrefs OK ({len(xrefs)} hook targets verified)")

    # --- final verification ---
    if len(d) != TARGET_SIZE:
        die(f"size mismatch: {len(d)} != {TARGET_SIZE}")
    out_h = hashlib.sha256(bytes(d)).hexdigest()
    if out_h != TARGET_SHA:
        die(f"result does not match the known-good community-patched build "
            f"(expected {TARGET_SHA}, got {out_h})")
    open(out, "wb").write(bytes(d))
    print(f"Wrote: {out} ({len(d)} bytes)")
    print(f"  sha256: {out_h}")
    print("  byte-identical to the known-good community-patched build OK")


if __name__ == "__main__":
    main()
