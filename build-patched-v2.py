#!/usr/bin/env python3
"""
build-patched-v2.py - deterministic build of patch set v2.

Patch set v2 = patch set v1 (RouterOS 7.25 compatibility, 12 byte patches)
plus the icon/version integration (consolidated from the whole icon-integration
development series into a single step):

  * new RWX section .wbox (RVA 0x238000, 0x20000 bytes) holding:
      - a 472-byte startup extractor (assembled from p1.s, see comments below)
      - icon sprites icons16/24/32.png (byte-identical to the RouterOS
        7.24.5 webfig files)
  * AddressOfEntryPoint is redirected to the extractor; it unpacks the three
    PNGs to %TEMP% (KERNEL32: CreateFileA/WriteFile/CloseHandle), wires the
    icon-loader fallback structures (VirtualProtect on the .rdata globals,
    P-slots/Q-structures in .wbox) and jumps to the original entry point
    (mainCRTStartup) - so WinBox finds its icons regardless of CWD
  * window titles and the VERSIONINFO resource are stamped 3.43.102.38
  * the Authenticode signature is dropped (unavoidable: the image grows)

Output: winbox64.v3.43p2.exe, byte-identical to the known-good community
patch set v2 build.
"""
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "winbox64.v3.43.exe")
OUT = os.path.join(HERE, "winbox64.v3.43p2.exe")

ORIG_SHA = "5b41cf51fd81e8d082687f6b522159cf4aba22e6df8edc486721d4e09507b6e9"
V17_SHA = "acfc8034b662cdabd4ead6a590194a2274dc41358f1b0cda71db9a752b2c4ea4"
TARGET_SHA = "8b0bc24fcfdbd7eee6109d4593ad3aedecb4fc28786133acc71ed051c61aea20"
TARGET_SIZE = 2418176  # 0x24E600


def sha(b):
    return hashlib.sha256(b).hexdigest()


def hx(s):
    return bytes.fromhex(s.replace(" ", "").replace("\n", ""))


# ----------------------------------------------------------------------------
# Patch set v1: the 12 RouterOS 7.25 compatibility patches (see README).
# (file_offset, expected_original_hex, patched_hex, name)
# ----------------------------------------------------------------------------
V1_PATCHES = [
    (0x0F991C, "76", "EB", "p1 version gate"),
    (0x0F9D91, "0F 84 13 01 00 00", "E9 14 01 00 00 90", "p2 skin skip"),
    (0x0A6D45, "E8 30 75 F9 FF", "E8 E7 5F 05 00", "p3a title cave call"),
    (0x0FCD31, "90 90 90 90 90 90 90 90 90 90 90 90 90 90",
     "48 85 D2 75 04 48 8B 53 18 E9 3B 15 F4 FF", "p3b title cave"),
    (0x0A1CAA, "48 8B 0D 4F B3 09 00", "E9 80 00 00 00 90 90", "p4a unknown field skip"),
    (0x09D0B8, "0F 85 8C 00 00 00", "0F 85 42 FF FF FF", "p4b conv degrade"),
    (0x09D14A, "48 8B 0D AF FE 09 00 48 8D 15 B4 8C 09 00 E8 2C 39",
     "4D 85 F6 75 1B 59 48 83 C4 38 5B 5E 5F 5D 41 5C 41 5D 41 5E 41 5F"
     " 48 83 C4 38 59 E9 C5 4B 00 00 E9 C1 A6 03 00", "p5 id-less guard cave"),
    (0x0A2B99, "E8 92 4C 03 00", "E8 AC A5 FF FF", "p5b call cave"),
    (0x082BA0, "C7 04 25 00 00 00 00 00 00 00 00 0F 0B",
     "EB 75 90 90 90 90 90 90 90 90 90 90 90", "p6 SlotRef defuse"),
    (0x082B24, "48 8B 0D D5 A4 0B 00",
     "48 81 3C 24 2B 14 4A 00 75 4E 59 48 83 EC 28 4C 89 EA 48 8D 4C 24 20"
     " E8 70 1D 00 00 48 8B 44 24 20 48 85 C0 74 29 49 89 C3 48 8B 08"
     " E8 CB 6D 00 00 3D 00 00 64 69 74 09 4C 89 D8 48 8B 40 08 EB E0"
     " 48 83 C4 28 B9 C0 00 00 00 E9 B8 DC 01 00 48 83 C4 28 E9 2E F1 01 00"
     " E9 96 00 00 00", "p7 id-check cave"),
    (0x0A0826, "B9 C0 00 00 00", "E8 F9 22 FE FF", "p7b call cave2"),
    (0x09D16F, "6D 8C 09 00 48 89 C1 E8 0E 39 03 00 BA 6F",
     "48 81 F9 00 00 01 00 72 0A E9 04 E9 FD FF", "p8 numeric-node cave"),
    (0x09D17D, "2C 00 00 48 89", "90 90 90 90 90", "p8b cave nop padding"),
    (0x09D182, "C1 E8 EA", "31 C0 C3", "p8c cave xor eax,eax; ret"),
    (0x0A01FC, "E8 80 B8 FD FF", "E8 6E CF FF FF", "p8d call cave3"),
    (0x0921EE, "C7 04 25 00 00 00 00 00 00 00 00 0F 0B",
     "31 C0 E9 06 01 00 00 90 90 90 90 90 90", "p9 cond defuse"),
    (0x09D185, "39 03 00 48 89 C1 E8 BF 3C 03 00 C7 04 25 00 00 00 00 00 00 00",
     "48 8B 14 C2 48 85 D2 75 08 59 FF C5 E9 B7 6A FE FF 89 6A 18 C3", "p10 NULL-slot cave"),
    (0x083C62, "48 8B 14 C2 89 6A 18", "E8 1E 95 01 00 90 90", "p10b call cave4"),
    (0x082B81, "0B 00 48 89 C1 E8 FE DE 04 00 BA 7B 03 00 00 48 89 C1 E8 DA DF",
     "48 8B 56 20 48 85 D2 75 04 48 8B 56 18 48 89 F9 E9 48 BB 04 00", "p11 title cave5"),
    (0x0A6820, "48 8B 56 20 48 89 F9 E8 B2 7E 02 00",
     "E8 5C C3 FD FF 90 90 90 90 90 90 90", "p11b call cave5 + nop"),
    (0x0A6519, "E8 C0 81 02 00", "E8 63 C6 FD FF", "p12 QS title"),
]

# ----------------------------------------------------------------------------
# The .wbox startup extractor (p1.bin, 472 bytes).
#
# Hand-assembled (x86-64) from the reference source p1.s (GNU as):
#   as -o p1.o p1.s && ld -Ttext=0x638000 -e _start -o p1.elf p1.o \
#     && objcopy -O binary p1.elf p1.bin
# Constants (image base 0x400000): GTPA/IAT_* = kernel32 import slots called
# via absolute indirect calls; NAMEBASE = "\icons16/24/32.png" fragments in
# .rdata; MK = runtime marker zone; PSLOTS/QBASE = fallback structures in
# .wbox; FBGLB = icon-loader fallback globals in .rdata (RO, made writable
# via VirtualProtect); ENTRY = original entry point (mainCRTStartup).
# ----------------------------------------------------------------------------
def build_p1_head():
    GTPA, IAT_CREATE, IAT_WRITE, IAT_CLOSE = 0x5F6078, 0x5F5F78, 0x5F6188, 0x5F5F68
    NAMEBASE, MK, PSLOTS, QBASE = 0x535204, 0x638800, 0x638A00, 0x638A20
    FBGLB, VP, ENTRY, BASE = 0x53DC40, 0x5F6170, 0x4014C0, 0x638000

    o = bytearray()

    def emit(*bs):
        o.extend(bs)

    def a32(v):
        return struct.pack("<I", v)

    def mark(n):  # mov byte ptr [MK+n], 1
        emit(0xC6, 0x04, 0x25)
        o.extend(a32(MK + n))
        emit(0x01)

    def call_abs(slot):
        emit(0xFF, 0x14, 0x25)
        o.extend(a32(slot))

    mark(0)                                        # extractor entered
    emit(0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57)  # push rbx,rsi,rdi,r12..r15
    emit(0x48, 0x81, 0xEC, 0x38, 0x03, 0x00, 0x00)  # sub rsp,0x338
    emit(0xB9, 0x04, 0x01, 0x00, 0x00)              # mov ecx,0x104
    emit(0x48, 0x89, 0xE2)                          # mov rdx,rsp
    call_abs(GTPA)                                  # call [GetTempPathA]
    mark(24)
    emit(0x48, 0x85, 0xC0)                          # test rax,rax
    jle = len(o); emit(0x0F, 0x8E, 0, 0, 0, 0)      # jle X_out
    emit(0x49, 0x89, 0xC5)                          # mov r13,rax (temp path len)
    emit(0xFC)                                      # cld
    emit(0x48, 0x8D, 0xBC, 0x24, 0x10, 0x01, 0x00, 0x00)  # lea rdi,[rsp+0x110]
    emit(0x48, 0x89, 0xE6)                          # mov rsi,rsp
    emit(0x48, 0x89, 0xC1)                          # mov rcx,rax
    emit(0xF3, 0xA4)                                # rep movsb (copy temp path)
    mark(32)
    # VirtualProtect(FBGLB, 0x30, PAGE_READWRITE, &old)
    emit(0x48, 0xC7, 0xC1); o.extend(a32(FBGLB))  # mov rcx,FBGLB
    emit(0xBA, 0x30, 0x00, 0x00, 0x00)              # mov edx,0x30
    emit(0x41, 0xB8, 0x04, 0x00, 0x00, 0x00)        # mov r8d,PAGE_READWRITE
    emit(0x4C, 0x8D, 0x8C, 0x24, 0x38, 0x02, 0x00, 0x00)  # lea r9,[rsp+0x238]
    emit(0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00)  # mov qword [rsp+0x20],0
    call_abs(VP)                                    # call [VirtualProtect]
    mark(36)
    emit(0x45, 0x31, 0xF6)                          # xor r14d,r14d (name offset)
    emit(0x31, 0xDB)                                # xor ebx,ebx (file index)
    L_file = len(o)
    emit(0x48, 0x8D, 0xBC, 0x24, 0x10, 0x01, 0x00, 0x00)  # lea rdi,[rsp+0x110]
    emit(0x4C, 0x01, 0xEF)                          # add rdi,r13 (append name)
    emit(0xBE); o.extend(a32(NAMEBASE))             # mov esi,NAMEBASE
    emit(0x4C, 0x01, 0xF6)                          # add rsi,r14
    emit(0xB9, 0x0C, 0x00, 0x00, 0x00)              # mov ecx,12
    emit(0xF3, 0xA4)                                # rep movsb
    emit(0xC6, 0x07, 0x00)                          # mov byte [rdi],0
    # CreateFileA(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)
    emit(0x48, 0x8D, 0x8C, 0x24, 0x10, 0x01, 0x00, 0x00)  # lea rcx,[rsp+0x110]
    emit(0xBA, 0x00, 0x00, 0x00, 0x40)              # mov edx,GENERIC_WRITE
    emit(0x45, 0x31, 0xC0)                          # xor r8d,r8d
    emit(0x45, 0x31, 0xC9)                          # xor r9d,r9d
    emit(0xC7, 0x44, 0x24, 0x20, 0x02, 0x00, 0x00, 0x00)  # [rsp+0x20]=CREATE_ALWAYS
    emit(0xC7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00)  # [rsp+0x28]=FILE_ATTRIBUTE_NORMAL
    emit(0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00)  # mov qword [rsp+0x30],0
    call_abs(IAT_CREATE)                            # call [CreateFileA]
    mark(48)
    emit(0x48, 0x85, 0xC0)                          # test rax,rax
    js = len(o); emit(0x0F, 0x88, 0, 0, 0, 0)       # js X_next
    emit(0x49, 0x89, 0xC4)                          # mov r12,rax (handle)
    lea_tbl = len(o)
    emit(0x48, 0x8D, 0x05, 0, 0, 0, 0)              # lea rax,[rip+TBL] (patched)
    emit(0x42, 0x8B, 0x14, 0x30)                    # mov edx,[rax+r14]      (sprite VA)
    emit(0x46, 0x8B, 0x44, 0x30, 0x04)              # mov r8d,[rax+r14+4]    (sprite size)
    emit(0x4C, 0x89, 0xE1)                          # mov rcx,r12
    emit(0x4C, 0x8D, 0x8C, 0x24, 0x30, 0x02, 0x00, 0x00)  # lea r9,[rsp+0x230]
    emit(0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00)  # mov qword [rsp+0x20],0
    call_abs(IAT_WRITE)                             # call [WriteFile]
    mark(52)
    emit(0x4C, 0x89, 0xE1)                          # mov rcx,r12
    call_abs(IAT_CLOSE)                             # call [CloseHandle]
    return o, jle, js, L_file, lea_tbl

def build_p1_tail(o, jle, js, L_file, lea_tbl):
    """Fallback structures + loop tail + TBL; returns the finished 472 bytes."""
    QBASE, PSLOTS, FBGLB, ENTRY, BASE = 0x638A20, 0x638A00, 0x53DC40, 0x4014C0, 0x638000

    def emit(*parts):
        for p in parts:
            if isinstance(p, int):
                o.append(p)
            else:
                o.extend(p)

    # fallback struct Q = QBASE + idx*0x140: [Q]=1, Q+4 = full path
    emit((0x41, 0xBF), struct.pack("<I", QBASE))   # mov r15d,QBASE
    emit((0x89, 0xD8))                              # mov eax,ebx
    emit((0x69, 0xC0, 0x40, 0x01, 0x00, 0x00))      # imul eax,eax,0x140
    emit((0x49, 0x01, 0xC7))                        # add r15,rax
    emit((0x41, 0xC7, 0x07, 0x01, 0x00, 0x00, 0x00))  # mov dword [r15],1
    emit((0x49, 0x8D, 0x7F, 0x04))                  # lea rdi,[r15+4]
    emit((0x48, 0x8D, 0xB4, 0x24, 0x10, 0x01, 0x00, 0x00))  # lea rsi,[rsp+0x110]
    emit((0x4C, 0x89, 0xE9))                        # mov rcx,r13
    emit((0x48, 0x83, 0xC1, 0x0D))                  # add rcx,13 (path+name length)
    emit((0xF3, 0xA4))                              # rep movsb
    # P-slot [PSLOTS+idx*8] = Q ; global [FBGLB+idx*0x10] = slot address
    emit(0x48, 0xC7, 0xC2, *struct.pack("<I", PSLOTS))  # mov rdx,PSLOTS
    emit((0x48, 0x8D, 0x04, 0xDA))                  # lea rax,[rdx+rbx*8]
    emit((0x4C, 0x89, 0x38))                        # mov [rax],r15
    emit(0x48, 0xC7, 0xC1, *struct.pack("<I", FBGLB))  # mov rcx,FBGLB
    emit((0x48, 0x89, 0xDA))                        # mov rdx,rbx
    emit((0x48, 0xC1, 0xE2, 0x04))                  # shl rdx,4
    emit((0x48, 0x01, 0xD1))                        # add rcx,rdx
    emit((0x48, 0x89, 0x01))                        # mov [rcx],rax
    X_next = len(o)
    emit((0x49, 0x83, 0xC6, 0x0C))                  # add r14,12
    emit((0xFF, 0xC3))                              # inc ebx
    emit((0x49, 0x83, 0xFE, 0x24))                  # cmp r14,36 (3 files)
    jb = len(o); emit((0x0F, 0x82, 0, 0, 0, 0))     # jb L_file
    # mark(56) - mov byte [MK+56],1
    emit((0xC6, 0x04, 0x25), struct.pack("<I", 0x638838), (0x01,))  # mov byte [MK+56],1
    X_out = len(o)
    emit((0x48, 0x81, 0xC4, 0x38, 0x03, 0x00, 0x00))  # add rsp,0x338
    emit((0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C))  # pop r15,r14,r13,r12
    emit((0x5F, 0x5E, 0x5B))                        # pop rdi,rsi,rbx
    # mark(64) - mov byte [MK+64],1
    emit((0xC6, 0x04, 0x25), struct.pack("<I", 0x638840), (0x01,))  # mov byte [MK+64],1
    jmp = len(o); emit((0xE9, 0, 0, 0, 0))          # jmp ENTRY
    TBL = len(o)
    struct.pack_into("<i", o, jle + 2, X_out - (jle + 6))
    struct.pack_into("<i", o, js + 2, X_next - (js + 6))
    struct.pack_into("<i", o, jb + 2, L_file - (jb + 6))
    struct.pack_into("<i", o, jmp + 1, ENTRY - (BASE + jmp + 5))
    # lea rax,[rip+TBL]: rip-relative disp32
    struct.pack_into("<i", o, lea_tbl + 3, (BASE + TBL) - (BASE + lea_tbl + 7))
    # TBL: (VA, size, size_hi) triples for icons16/24/32 sprites
    emit(struct.pack("<III", BASE + 0x1000, 25219, 0))
    emit(struct.pack("<III", BASE + 0x7283, 41114, 0))
    emit(struct.pack("<III", BASE + 0x1131D, 56951, 0))
    assert len(o) == 472, len(o)
    return bytes(o)


def build_p1():
    return build_p1_tail(*build_p1_head())

# ----------------------------------------------------------------------------
# Main build
# ----------------------------------------------------------------------------
def main():
    d = bytearray(open(SRC, "rb").read())
    if sha(d) != ORIG_SHA:
        sys.exit("Input is not the pristine winbox64.v3.43.exe (SHA-256 mismatch).")
    print("Input OK: winbox64.v3.43.exe")

    # --- Stage 1: patch set v1 (RouterOS 7.25 compatibility) ---
    for off, exp, new, name in V1_PATCHES:
        e, n = hx(exp), hx(new)
        cur = bytes(d[off:off + len(e)])
        if cur != e:
            sys.exit("ASSERT %s @0x%X: expected %s, got %s" % (name, off, e.hex(), cur.hex()))
        d[off:off + len(n)] = n
    if sha(d) != V17_SHA:
        sys.exit("Stage 1 (patch set v1) produced an unexpected binary.")
    print("Stage 1 OK: patch set v1 applied (compatibility base)")

    # --- Stage 2: drop the Authenticode signature (image must grow) ---
    del d[0x22E600:]                       # certificate was appended here
    d[0x128:0x130] = b"\x00" * 8           # zero Security DataDirectory
    struct.pack_into("<I", d, 0xD8, 0)     # CheckSum = 0

    # --- Stage 3: window titles (equal-or-shorter, in place) ---
    t1 = b"WinBox 3.43.102.38 (%s)\x00"
    t2 = b"WinBox 3.43.102.38\x00"
    assert d[0x1379B9:0x1379B9 + 26] == b"WinBox (64bit) v3.43 (%s)\x00"
    assert d[0x137FBC:0x137FBC + 21] == b"WinBox (64bit) v3.43\x00"
    d[0x1379B9:0x1379B9 + len(t1)] = t1    # trailing original NUL remains
    d[0x137FBC:0x137FBC + len(t2)] = t2

    # --- Stage 4: VERSIONINFO resource: '3.43' -> '3.43.102.38' ---
    # Resource at file 0x21C410 (leaf 0x1F56F0, size 0x2CC), manifest right
    # behind it (leaf 0x1F5700, data 0x21C6E0, size 0x7E8), .rsrc tail slack
    # is 0x138 zero bytes. String layout (relative offsets, verified):
    #   StringTable@0x80, FileVersion value@0x158, ProductVersion@0x27C,
    #   VarFileInfo@0x288. Each value grows by 14 bytes ('3.43\0' ->
    #   '3.43.102.38\0' in UTF-16); container lengths +28; the manifest and
    #   everything behind it shifts by +28 within the section slack.
    res = bytearray(d[0x21C410:0x21C410 + 0x2CC])
    manifest = bytes(d[0x21C6E0:0x21C6E0 + 0x7E8])
    assert res[0x158:0x158 + 10] == "3.43\x00".encode("utf-16le")
    assert res[0x27C:0x27C + 10] == "3.43\x00".encode("utf-16le")
    val = "3.43.102.38\x00".encode("utf-16le")
    assert len(val) == 24
    res[0x162:0x162] = b"\x00" * 14        # room for the longer FileVersion
    res[0x158:0x158 + 24] = val
    struct.pack_into("<H", res, 0x138, 0x38)   # FileVersion String wLength
    struct.pack_into("<H", res, 0x13A, 0x0C)   # .. wValueLength (wchars)
    res[0x294:0x294] = b"\x00" * 14        # room for the longer ProductVersion
    res[0x28A:0x28A + 24] = val
    struct.pack_into("<H", res, 0x266, 0x3C)   # ProductVersion String wLength
    struct.pack_into("<H", res, 0x268, 0x0C)   # .. wValueLength
    struct.pack_into("<H", res, 0x80, 0x222)   # StringTable wLength
    struct.pack_into("<H", res, 0x5C, 0x246)   # StringFileInfo wLength
    struct.pack_into("<H", res, 0x00, 0x2E8)   # root VS_VERSIONINFO wLength
    assert len(res) == 0x2E8
    # VS_FIXEDFILEINFO @+0x28: File/ProductVersionLS = 102<<16 | 38
    struct.pack_into("<I", res, 0x28 + 12, 0x00660026)
    struct.pack_into("<I", res, 0x28 + 20, 0x00660026)
    # rebuild the whole .rsrc data region: version(+28) + 4B gap + manifest(+28)
    region = bytes(res) + b"\x00" * 4 + manifest + b"\x00" * (0x138 - 0x1C)
    assert len(region) == 0xBF0
    d[0x21C410:0x21D000] = region
    struct.pack_into("<I", d, 0x1F56F0 + 4, 0x2E8)     # VERSION leaf: size
    struct.pack_into("<I", d, 0x1F5700, 0x2250E0 + 0x1C)  # MANIFEST leaf: data RVA
    # The reference build grows .rsrc by 28 zero bytes at its raw end, which
    # shifts the .reloc data +28; the 28 trailing (zero) bytes of .reloc are
    # then trimmed so the image stays 0x22E600 bytes before .wbox is appended.
    assert all(x == 0 for x in d[0x22E600 - 28:0x22E600])  # .reloc tail is padding
    d[0x21D000:0x21D000] = b"\x00" * 28
    del d[0x22E600:]
    assert len(d) == 0x22E600
    print("Stage 2-4 OK: signature dropped, titles + VERSIONINFO stamped 3.43.102.38")

    # --- Stage 5: PE header edits + .wbox section ---
    struct.pack_into("<H", d, 0x86, 13)             # NumberOfSections 12 -> 13
    struct.pack_into("<I", d, 0xA8, 0x238000)       # AddressOfEntryPoint -> .wbox
    struct.pack_into("<I", d, 0xD0, 0x258000)       # SizeOfImage
    d[0x368:0x368 + 40] = (b".wbox\x00\x00\x00"
                           + struct.pack("<IIII", 0x20000, 0x238000, 0x20000, 0x22E600)
                           + b"\x00" * 12
                           + struct.pack("<I", 0xE0000020))

    # --- Stage 6: .wbox content: extractor + icon sprites ---
    icons16 = open(os.path.join(HERE, "icons", "icons16.png"), "rb").read()
    icons24 = open(os.path.join(HERE, "icons", "icons24.png"), "rb").read()
    icons32 = open(os.path.join(HERE, "icons", "icons32.png"), "rb").read()
    assert (len(icons16), len(icons24), len(icons32)) == (25219, 41114, 56951)
    wbox = bytearray(0x20000)
    wbox[0:472] = build_p1()
    wbox[0x1000:0x1000 + len(icons16)] = icons16
    wbox[0x7283:0x7283 + len(icons24)] = icons24
    wbox[0x1131D:0x1131D + len(icons32)] = icons32
    d.extend(wbox)

    # --- Verification ---
    if len(d) != TARGET_SIZE:
        sys.exit("Size mismatch: %d != %d" % (len(d), TARGET_SIZE))
    h = sha(d)
    print("Output SHA-256: " + h)
    if h != TARGET_SHA:
        sys.exit("Result does not match the known-good patched build (expected %s)." % TARGET_SHA)
    open(OUT, "wb").write(d)
    print("Wrote: %s (%d bytes) - byte-identical to the known-good patched build" % (OUT, len(d)))


if __name__ == "__main__":
    main()



