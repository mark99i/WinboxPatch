# cave_v110v2 - title tail with a DYNAMIC version from the PE header
# On every call (ON branch) the VERSION is copied from the PE title
# @0x539BC3 (= 0x539BBC+7: the ANSI title "WinBox 3.43.103.NN", file
# 0x137fbc, where setversion writes; +7 skips the constant "WinBox "
# prefix) into the TSTR+10 buffer (max 12B, up to NUL - the NUL
# terminates the title right after the version).
# TSTR zone: the " - WinBox " prefix (10B, STATIC - user directive) + buffer.
# Benefit: setversion changes the PE title -> the window title stays in
# sync WITHOUT rebuilding the cave.
# ABI canon: assign-local -> append -> release-local (r14 = the stock
# release arg, r15 = the host title object); the copy is a byte-loop;
# rdi is callee-saved => push/pop, frame push(8)+sub(0x38)=0x40 = 0
# (mod16), the local object @ [rsp+0x10] stays aligned.
    .intel_syntax noprefix
    .code64
    .globl _start
_start:
    mov     rcx, r14                    # STOCK tail (stock replica):
    call    0x4cf0da                    #   release(r14) - always
    cmp     BYTE PTR [rip+TFLAG], 0     # title flag (default 1)
    je      L_out
    push    rdi                         # ABI: rdi is callee-saved (the copy uses it)
    sub     rsp, 0x38                   # frame: 8+0x38 = 0x40, a multiple of 16
    # --- DYNAMIC VERSION: copy the PE-title version into the TSTR+10 buffer ---
    mov     r8d, 0x539BC3               # source: 0x539BBC+7 (past "WinBox ")
    lea     rdi, QWORD PTR [rip+TSTR]   # destination: suffix zone
    add     rdi, 10                     # after the static " - WinBox " prefix
    xor     ecx, ecx
L_copy:
    mov     al, BYTE PTR [r8+rcx]
    test    al, al                      # up to NUL
    jz      L_cpd
    mov     BYTE PTR [rdi+rcx], al
    inc     rcx
    cmp     rcx, 12                     # strlen <= 12 (clamped)
    jb      L_copy
L_cpd:
    mov     BYTE PTR [rdi+rcx], 0       # NUL-terminate the buffer
    # --- stock mechanic (as in v110) ---
    lea     rcx, QWORD PTR [rsp+0x10]   # dst = the local string object
    lea     rdx, QWORD PTR [rip+TSTR]   # src = " - WinBox " + PE version
    call    0x4cf2de                    # assign(local, C-string)
    lea     rdx, QWORD PTR [rsp+0x10]   # rdx = &local (string object)
    mov     rcx, r15                    # r15 = the host title object
    call    0x4cf452                    # append(r15, local)
    lea     rcx, QWORD PTR [rsp+0x10]   # release the local buffer
    call    0x4cf0da
    add     rsp, 0x38
    pop     rdi
L_out:
    jmp     0x4b4a00                    # return to the host tail
    .align 8
TSTR:
    .ascii " - WinBox "                # static prefix (user directive)
    .byte 0,0,0,0,0,0,0,0,0,0,0,0         # 12B version buffer (filled on call)
    .byte 0, 0                          # padding
TFLAG:
    .byte 1
