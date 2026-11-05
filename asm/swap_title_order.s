# esr5.s - "Swap title order" (port of teslasystems ESR fix 7, evolution of esr5v3)
# Full reconstruction from an .s source (replaces copying zones from a reference).
# Byte reference: winbox64.v3.43-patched-v106-esr5v3.exe (live QA round-9; the
# v111final canon contains a -1B shift in the esr5 zones - see the map/report,
# the .s fixes that).
#
# MECHANICS (dossier /tmp/esr3party/REPORT.md round-6/8/9):
#   settings.dat {magic 0xAA555354 "TSU\xAA", flag, zeros} in the PROFILE folder
#   (%APPDATA%\Mikrotik\Winbox - 0x4AEF59 = profile-dir). Title word order:
#   flag=1 -> identity-first ("RouterOS ... via WinBox ..."), flag=0 -> stock.
#
#   menurefresh (0x65B07E) - called from the menu-build site 0x4B6255 (call-retarget):
#     destruct(r13) -> vt+0x28(ctrl 0x999) [drop the old item] ->
#     str-init "Swap title order" -> vt+0x18(menu, id 0x998, str, 0)
#     [RUNTIME creation of the checkbox item] -> destruct -> vt+0x38(0x998, flag&1)
#     [check mark per state]. Called both when the menu is built and after a toggle.
#
#   reader (0x65B0F5) - called from the login-builder site 0x4BC758 (call-retarget):
#     0x4AEF59() -> profile-dir -> 0x4B6C4C(path cell 0x65B348, dir,
#     "\settings.dat") -> CreateFileA(GENERIC_READ, OPEN_EXISTING) ->
#     ReadFile(8B) -> validation: n==8 AND dw[0]==0xAA555354 AND dw[1]&~1==0 ->
#     flag=[0x65B340]=low byte. No file/garbage = silent default.
#
#   dispatcher (0x65B1B8) - hook of the menu dispatcher 0x4B41F8 (jmp-retarget):
#     command 0x934 (emit of item 0x998: 0x998-0x64=0x934) -> xorb flag ->
#     orq dirty -> vt+0x38(0x998, flag&1) [update the check mark] -> 0x4B46E8
#     [stock title rebuild] -> jmp TRAMP (write-on-toggle, v2).
#     Other commands: cmp dx,0xf; ja 0x4B42D9 (default) / jmp 0x4B4202
#     (stock branch dx<=0xf) - passthrough unchanged.
#
#   writer (0x65B203) - write-on-toggle (invoked by the trampoline IMMEDIATELY
#     on toggle; v3 audit: the exit duplicate is gone, site 0x42DAFC stays pristine):
#     dirty([0x65B350])!=0 -> CreateFileA(path, GENERIC_WRITE, CREATE_ALWAYS) ->
#     WriteFile(8B {magic, flag}) -> CloseHandle -> release the path cell
#     (0x4CF0DA). Dead tail mov rcx,[0x53dc00] - NOP (v3).
#
#   gate (0x65B2C0) - hook of the title builder 0x4B478F (call->jmp):
#     flag==1 -> path A: 0x4B2654(rdx=rbp) + 0x4CF286(r12, r14) + jmp 0x4B47A2
#     (identity-first); flag!=1 -> path B: 0x4B2654(rbp) + jmp 0x4B4794
#     (stock user@host-first). Both tails are stock build sites.
#
#   trampoline (0x65B380, v2) - mov eax,writer; call rax; jmp 0x4B42D9:
#     after a toggle -> IMMEDIATE settings.dat write (independent of the
#     user exit route; Auto-Reconnect no longer eats persistence).
#
#   data: "Swap title order\0" @0x65B300 (item label); "\settings.dat\0"
#     @0x65B320 (the FULL string with a backslash - the esr2 lesson!); cells:
#     flag @0x65B340 (byte), path object @0x65B348, dirty @0x65B350.
#
# BUILD: as --64 -o esr5.o esr5.s && ld -Ttext=0x65B07E -o esr5.elf esr5.o
#   && objcopy -O binary esr5.elf esr5.bin  -> 0x30EB, byte-identical to the
#   reference (control: cmp esr5.bin <cut 0x65B07E..0x65B38C from v106-esr5v3>).
# HOOKS (in the build script): jmp 0x4B41F8->0x65B1B8 (+5 nop); call 0x4B6255->
#   0x65B07E; call 0x4BC758->0x65B0F5; jmp 0x4B478F->0x65B2C0. Site 0x2CEFC
#   (exit-writer) - do NOT touch (v3 audit: the duplicate is gone).

    .intel_syntax noprefix
    .code64
    .globl _start
_start:

# ======================= MENUREFRESH (0x65B07E) =======================
menurefresh:
    push    rbp
    sub     rsp, 0x20
    .byte 0x48, 0x8b, 0xec          # mov rbp,rsp (canon encoding)
    mov     eax, 0x4CF0DA
    call    rax                     # destruct(r13) - the old item string
    mov     rcx, QWORD PTR [r12+0x50]   # menu object
    mov     edx, 0x999             # ctrl 0x999
    mov     rax, QWORD PTR [rcx]
    call    QWORD PTR [rax+0x28]   # vt+0x28: drop/find the old item
    mov     r14, QWORD PTR [r12+0x50]   # menu object
    mov     edx, OFFSET STR_SWAP   # "Swap title order"
    mov     rcx, r13
    mov     rax, QWORD PTR [r14]
    mov     rsi, QWORD PTR [rax+0x18]   # vt+0x18 (create-item) -> rsi
    mov     eax, 0x4CF2DE
    call    rax                     # str-assign(r13, label)
    xor     r9d, r9d               # arg4 = 0
    mov     r8, r13                # arg3 = string
    mov     edx, 0x998             # arg2 = item ID
    mov     rcx, r14               # arg1 = menu
    call    rsi                     # vt+0x18: create checkbox item 0x998
    mov     rcx, r13
    mov     eax, 0x4CF0DA
    call    rax                     # destruct(r13)
    mov     rcx, QWORD PTR [r12+0x50]
    mov     edx, 0x998
    mov     r8d, OFFSET FLAG       # &flag cell
    mov     r8, QWORD PTR [r8]     # qword read of the cell
    and     r8, 1                  # flag&1
    mov     rax, QWORD PTR [rcx]
    call    QWORD PTR [rax+0x38]   # vt+0x38: set-check(0x998, flag&1)
    lea     rsp, [rbp+0x20]
    pop     rbp
    ret

# ======================= READER (0x65B0F5) =============================
reader:
    push    rbp
    sub     rsp, 0x60
    .byte 0x48, 0x8b, 0xec          # mov rbp,rsp (canon encoding)
    mov     eax, 0x4AEF59
    call    rax                     # profile-dir -> r14
    mov     rdx, r14               # dir
    mov     r8d, OFFSET STR_FILE    # "\settings.dat" (FULL - esr2 lesson)
    mov     ecx, OFFSET PATHC      # path cell 0x65B348
    mov     eax, 0x4B6C4C
    call    rax                     # path-join -> string object into the cell
    mov     ecx, DWORD PTR [rip+0x229]   # [0x65B348] - path object data
    add     rcx, 4                 # -> C-string (nv::string: buf at +4)
    mov     edx, 0x80000000        # GENERIC_READ
    mov     r8d, 1                 # share
    xor     r9, r9                 # lpSecurityAttributes=NULL
    mov     DWORD PTR [rsp+0x20], 3        # OPEN_EXISTING
    mov     DWORD PTR [rsp+0x28], 0x80     # FILE_ATTRIBUTE_NORMAL
    mov     QWORD PTR [rsp+0x30], 0        # hTemplate
    call    QWORD PTR [rip-0x651d8]        # CreateFileA (IAT 0x5f5f78)
    mov     QWORD PTR [rbp+0x58], rax      # hFile
    cmp     QWORD PTR [rbp+0x58], -1       # INVALID_HANDLE?
    je      L_rd_skip
    mov     rcx, QWORD PTR [rbp+0x58]      # hFile
    lea     rdx, [rbp+0x50]      # &n
    mov     r8d, 8                 # 8 bytes
    lea     r9, [rbp+0x4c]       # buffer
    mov     QWORD PTR [rsp+0x20], 0        # lpOverlapped
    call    QWORD PTR [rip-0x6507c]        # ReadFile (IAT 0x5f6100)
    test    eax, eax
    je      L_rd_close
    cmp     DWORD PTR [rbp+0x4c], 8        # n==8?
    jne     L_rd_close
    mov     rax, QWORD PTR [rbp+0x50]      # {dw[0]=magic, dw[1]=flag}
    cmp     eax, 0xAA555354        # magic "TSU\xAA"
    jne     L_rd_close
    ror     rax, 0x20              # swap the dwords -> al = flag byte
    mov     edx, eax
    .byte 0x81, 0xe2, 0xfe, 0xff, 0xff, 0xff   # and edx,0xFFFFFFFE (imm32 - canon encoding)
    test    edx, edx
    jne     L_rd_close
    mov     ecx, OFFSET FLAG
    mov     BYTE PTR [rcx], al     # flag = low byte of dw[1]
L_rd_close:
    mov     rcx, QWORD PTR [rbp+0x58]
    call    QWORD PTR [rip-0x6524a]        # CloseHandle (IAT 0x5f5f68)
L_rd_skip:
    lea     rsp, [rbp+0x60]
    pop     rbp
    ret

# ======================= DISPATCHER (0x65B1B8) =========================
dispatcher:
    cmp     dx, 0x934              # command of item 0x998 (0x998-0x64)
    je      L_toggle
    cmp     dx, 0xf                # stock menu-dispatcher range
    ja      0x4B42D9               # default tail
    jmp     0x4B4202               # stock branch dx<=0xf
L_toggle:
    xor     BYTE PTR [rip+0x16b], 1        # flip flag @0x65B340
    or      QWORD PTR [rip+0x173], 1       # dirty @0x65B350
    mov     r8b, BYTE PTR [rip+0x15c]      # flag
    mov     rcx, QWORD PTR [r12+0x50]
    mov     edx, 0x998
    mov     rax, QWORD PTR [rcx]
    call    QWORD PTR [rax+0x38]   # vt+0x38: update the item check mark
    mov     rcx, r12
    mov     eax, 0x4B46E8
    call    rax                     # stock title rebuild
    jmp     TRAMP                   # write-on-toggle (v2): immediate write

# ======================= WRITER (0x65B203) =============================
writer:
    push    rbp
    sub     rsp, 0x60
    .byte 0x48, 0x8b, 0xec          # mov rbp,rsp (canon encoding)
    cmp     DWORD PTR [rip+0x13e], 0       # dirty @0x65B350?
    je      L_wr_out
    mov     ecx, DWORD PTR [rip+0x12e]     # [0x65B348] path data
    add     rcx, 4                 # -> C-string
    mov     edx, 0x40000000        # GENERIC_WRITE
    xor     r8, r8                 # share=0
    xor     r9, r9                 # lpSecurityAttributes=NULL
    mov     DWORD PTR [rsp+0x20], 2        # CREATE_ALWAYS
    mov     DWORD PTR [rsp+0x28], 0x80     # FILE_ATTRIBUTE_NORMAL
    mov     QWORD PTR [rsp+0x30], 0        # hTemplate
    call    QWORD PTR [rip-0x652d0]        # CreateFileA (IAT 0x5f5f78)
    mov     QWORD PTR [rbp+0x58], rax      # hFile
    cmp     QWORD PTR [rbp+0x58], -1
    je      L_wr_out
    mov     DWORD PTR [rbp+0x50], 0xAA555354   # magic
    mov     ecx, DWORD PTR [rip+0xe0]      # flag @0x65B340
    mov     DWORD PTR [rbp+0x54], ecx      # {magic, flag} - 8B
    mov     rcx, QWORD PTR [rbp+0x58]
    lea     rdx, [rbp+0x50]
    mov     r8d, 8
    lea     r9, [rbp+0x4c]
    mov     QWORD PTR [rsp+0x20], 0
    call    QWORD PTR [rip-0x650fc]        # WriteFile (IAT 0x5f6188)
    mov     rcx, QWORD PTR [rbp+0x58]
    call    QWORD PTR [rip-0x65326]        # CloseHandle (IAT 0x5f5f68)
L_wr_out:
    mov     ecx, OFFSET PATHC
    call    0x4CF0DA               # release the path string (cell 0x65B348)
    nop                             # v3 audit: dead tail
    nop                             #   mov rcx,[0x53dc00] (7B) - NOP
    nop
    nop
    nop
    nop
    nop
    lea     rsp, [rbp+0x60]
    pop     rbp
    ret
    .zero 0xB                       # padding to the end of the TEXT2 blob (0x65B2AF)

# ============== TITLE-BUILDER GATE (0x65B2C0; aligned) =================
    .zero 0x10                      # gap 0x65B2B0-0x65B2BF (canon zeros)
gate:
    mov     eax, OFFSET FLAG       # 0x65B340
    cmp     BYTE PTR [rax], 1      # word order?
    jne     L_gate_B
    # path A: identity-first ("RouterOS ... via WinBox ...")
    mov     rdx, rbp
    call    0x4B2654               # stock builder (arg rbp)
    mov     rdx, r14
    mov     rcx, r12
    call    0x4CF286               # extra build step
    mov     rdx, r15
    jmp     0x4B47A2               # stock tail A
L_gate_B:
    # path B: stock user@host-first
    call    0x4B2654               # builder (arg rbp - already in rdx)
    jmp     0x4B4794               # stock tail B
    .zero 0x11                      # gap 0x65B2EF-0x65B2FF

# ======================= DATA (0x65B300) ================================
STR_SWAP:
    .ascii "Swap title order\0"
    .zero 0xF                       # 0x65B311-0x65B31F
STR_FILE:
    .ascii "\\settings.dat\0"       # FULL string (esr2 lesson!)
    .zero 0x12                      # 0x65B32E-0x65B33F
FLAG:                               # 0x65B340 - word-order flag byte
    .zero 8
PATHC:                              # 0x65B348 - path string object (cell)
    .zero 8
DIRTY:                              # 0x65B350 - write dirty flag
    .zero 8
    .zero 0x28                      # 0x65B358-0x65B37F

# ============== WRITE-ON-TOGGLE TRAMPOLINE (0x65B380, v2) ==============
TRAMP:
    mov     eax, OFFSET writer     # 0x65B203
    call    rax                     # IMMEDIATE settings.dat write
    jmp     0x4B42D9                # stock dispatcher tail
