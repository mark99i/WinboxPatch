# cmr_jg_transit.s - the FSEEKFN piecewise cave (187B @0x659C00)
# Extracted from winbox64.v3.43-v114-jgmem2d.exe, restored into an .s per
# the canon (caves >10B = .s sources, the winbox-ros7.25 README).
#
# Mechanics: an item size check (<=0xF8) -> a buffer copy of the item
#   (rdi..rdi+r12) into [rsp+0x30] -> append "cmr.jg\0" (movabs) ->
#   CreateFileA(GENERIC_READ, OPEN_EXISTING=7? shares=3) ->
#   INVALID_HANDLE(-1) -> exit; else SetFilePointer(h, 0, NULL, 0) -> on
#   fail -> CloseHandle+DeleteFileA; ok -> CloseHandle -> exit; add rsp;
#   jmp unified @0x659560.
#
# IAT: 0x5F5F78 = CreateFileA, 0x5F6018 = SetFilePointer, 0x5F5F68 =
#      CloseHandle, 0x5F5FA0 = DeleteFileA (absolute [disp32] forms,
#      objcopy-safe).

.intel_syntax noprefix
.code64
# Verification: as --64 + ld -Ttext=0x659C00 + objcopy -O binary -> 187B
# byte-for-byte OK (no .org - the base is set by ld -Ttext; .org creates
# padding in the objcopy binary)

fseekfn_piecewise:
    cmp  r12d, 0xF8                  # item size check
    ja   L_exit_far                  # >0xF8 -> to the exit (0x659cb6)

    sub  rsp, 0x140                  # a 320B buffer
    xor  r11d, r11d                  # index

L_copy_loop:                         # 0x659c17
    cmp  r11d, r12d
    jae  L_copy_done                 # 0x659c2a
    mov  al, byte ptr [rdi+r11]      # an item byte
    mov  byte ptr [rsp+r11+0x30], al # -> buffer
    inc  r11d
    jmp  L_copy_loop

L_copy_done:                         # 0x659c2a
    movabs rax, 0x676A2E726D63       # "cmr.jg\0"
    mov  qword ptr [rsp+r11+0x30], rax
    lea  rcx, [rsp+0x30]             # lpFileName
    mov  edx, 0x80000000             # GENERIC_READ
    mov  r8d, 0x7                    # OPEN_EXISTING
    xor  r9d, r9d                    # lpSecurityAttributes = NULL
    mov  dword ptr [rsp+0x20], 0x3   # share-mode stack (5th arg)
    mov  qword ptr [rsp+0x28], 0x0   # hTemplate = NULL
    call qword ptr [0x5F5F78]        # CreateFileA
    cmp  rax, 0xFFFFFFFFFFFFFFFF     # INVALID_HANDLE_VALUE?
    je   L_close_and_exit            # 0x659caf
    mov  qword ptr [rsp+0x138], rax  # save the handle
    mov  rcx, rax
    xor  edx, edx                    # pos lo = 0
    call qword ptr [0x5F6018]        # SetFilePointer
    test rax, rax
    jne  L_fail_path                 # 0x659ca0
    mov  rcx, qword ptr [rsp+0x138]
    call qword ptr [0x5F5F68]        # CloseHandle
    lea  rcx, [rsp+0x30]
    call qword ptr [0x5F5FA0]        # DeleteFileA
    jmp  L_close_and_exit

L_fail_path:                         # 0x659ca0
    mov  rcx, qword ptr [rsp+0x138]
    call qword ptr [0x5F5F68]        # CloseHandle

L_close_and_exit:                    # 0x659caf
    add  rsp, 0x140

L_exit_far:                          # 0x659cb6
    jmp  0x659560                    # return into the unified cave
