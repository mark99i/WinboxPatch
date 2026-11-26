# utf8_option.s - the "Use UTF-8" option (v116-utf8b): STORAGE conversion (v2)
#
# MECHANICS (Phase-0: tmp/alpha-rucomment/PHASE0-report.md):
#   The UTF8FLAG flag (a byte in .wbox): 0 = stock WB3 (a pure passthrough,
#   byte-for-byte), 1 = UTF-8 mode (like WB4 end-to-end).
#
#   DISPLAY (receive, UTF-8->ACP): the canvas-text shim entries - 0x439F9C
#   (the DrawTextExA branch: list cells, ";;;" comments) and 0x439E6A
#   (the TextOutA branch: headers/tree). Both take r9 = string-obj
#   ({u32 len, bytes@+4}, binary-safe) and THE SHIM BODY reads ONLY rax
#   (len=[rax], str=rax+4) + KEEPS rcx (ctx with hdc!) and rdx/r8 (coords!)
#   straight into the draw call. The conv_display CONTRACT: input r9 = obj; output
#   rax = block (TEMP with the conversion OR the original - THE MODEL IS NOT MUTATED!
#   the smoke-10 lesson: mutation = "0 items out of 8"); rcx/rdx/r8 are saved
#   by pushes and returned (the smoke-12/13/17 lessons: the shim body counts
#   on them AFTER our call; NO transfer via volatile regs -
#   MB2WC/WC2MB (DLL) clobber r10/r11!). Detection: only VALID UTF-8
#   (MB2WC CP_UTF8 + MB_ERR_INVALID_CHARS: invalid = cp1251-legacy ->
#   passthrough); ASCII -> no-op; len>512 -> no-op (the TEMP cap).
#
#   SEND (write, ACP->UTF-8): the native-edit value extraction point
#   0x42F3C6 call [GetWindowTextA] (IAT 0x5F66D0, trampoline 0x4BCA30) -
#   the SINGLE collection point of all edit fields (a live GW HIT, Phase-0).
#   The conv_gwta cave: calls the original GWTA -> gate -> a scan for >=0x80 ->
#   MB2WC(CP_ACP) -> WC2MB(CP_UTF8) into the buffer IN PLACE -> NUL -> returns
#   the NEW length in eax (the following code 0x42F3D2 `mov edx,eax` sets
#   the string-obj length - consistent!). COMPATIBILITY: stub_dblres doubles
#   the first reserve (0x42F3A0: xor r8d,r8d; mov edx,ebx -> 2*ebx):
#   resize(obj, 2*ebx, 0) -> data = 2*ebx bytes >= 2*len+2 (cp1251->UTF-8
#   max x2) OK.
#
#   MENU/PERSISTENCE (the blueprint swap_title_order.s @0x65B07E,
#   CHAINED - the canonical esr5 zones are not modified):
#   - menurefresh_utf8: called from site 0x4B6255 (a call retarget 0x65B07E ->
#     here): first the full swap-menurefresh (0x65B07E), then our own item
#     "Use UTF-8" (id 0x99A, ctrl 0x99B, command 0x936 = 0x99A-0x64).
#   - reader_utf8: called from site 0x4BC758 (a call retarget 0x65B0F5 -> here):
#     swap-reader (settings.dat) + reading utf8.dat {magic 0x55384655,
#     flag, zeros} from the profile folder (0x4AEF59 + 0x4B6C4C path-join).
#     No file/garbage/broken magic -> a silent default OFF.
#   - dispatcher_utf8: the NEW jmp target @0x4B41F8 (was -> 0x65B1B8):
#     command 0x936 -> toggle; the rest -> jmp 0x65B1B8 (the swap chain stays alive).
#     Toggle: flip the flag -> dirty -> vt+0x38 checkbox -> writer (an immediate
#     write) -> the stock tail 0x4B42D9.
#   - writer_utf8: dirty → CreateFileA(utf8.dat, CREATE_ALWAYS) →
#     WriteFile 8B {magic, flag} -> CloseHandle -> release the path cell.
#
#   CONVERTERS ALREADY IMPORTED (reused!): the MB2WC trampoline 0x4BCDE8
#   (IAT 0x5F60F0), the WC2MB trampoline 0x4BCDA0 (IAT 0x5F6180), the GWTA trampoline
#   0x4BCA30. File IAT: CreateFileA 0x5F5F78, ReadFile 0x5F6100,
#   WriteFile 0x5F6188, CloseHandle 0x5F5F68. All external calls use the
#   pattern mov eax,<addr>; call rax / call [rax] (no rel32 math).
#
# HOOKS (7, .text; the exact original bytes - in build_utf8a.py):
#   0x4B41F8: e9bb6f1a00+90×5 (jmp swap-dispatcher) → jmp dispatcher_utf8
#   0x4B6255: e8244e1a00 (call swap-menurefresh)      → call menurefresh_utf8
#   0x4BC758: e898e91900 (call swap-reader)           → call reader_utf8
#   0x439F9C: 4883ec48498b01 (sub rsp,0x48; mov rax,[r9]) → jmp stub_dispa+90×2
#   0x439E6A: 4883ec48498b01 (the same)                -> jmp stub_dispb+90x2
#   0x42F3A0: 4531c089da (xor r8d,r8d; mov edx,ebx)   → jmp stub_dblres
#   0x42F3C6: ff1504731c00 (call [GWTA])              → call conv_gwta+90
#
# BUILD: as --64 -o utf8a.o utf8a.s && ld -Ttext=0x65B600 -o utf8a.elf
#   utf8a.o && objcopy -O binary utf8a.elf utf8a.bin
#   (the hook symbols - readelf -s utf8a.elf; build_utf8a.py does it automatically)
#
# SAFETY: r9 is not touched in conv_display (the shim needs it after);
#   callee-saved (rbx/rdi/rsi/rbp/r12) are pushed/restored;
#   rsp==0 alignment on every call (the prologues are counted); ASCII no-op;
#   OFF = 1 cmp per call; cp1251-legacy passthrough (MB2WC detection).

    .intel_syntax noprefix
    .code64
    .globl _start
_start:

# ======================= MENUREFRESH_UTF8 ==============================
# utf8c fix: r13 is NOT touched after the swap cave (its teardown @0x65B0C8 already
# freed the r13 string - a repeated destruct = a double-free through the heap shield
# 0x658000 -> 0xC0000374 on Win10 3/3; wine masks it!). Our own static scratch
# MYSCRATCH: init(0x4CF23C) → str-assign → create-item → destruct —
# a fully balanced cycle, independent of r13.
menurefresh_utf8:
    push    rbp
    sub     rsp, 0x20
    mov     rbp, rsp
    mov     eax, 0x65B07E           # swap-menurefresh (the full functionality)
    call    rax
    mov     rcx, QWORD PTR [r12+0x50]   # the menu object
    mov     edx, 0x99B              # ctrl 0x99B
    mov     rax, QWORD PTR [rcx]
    call    QWORD PTR [rax+0x28]    # vt+0x28: remove the previous item
    mov     r14, QWORD PTR [r12+0x50]
    mov     rcx, OFFSET MYSCRATCH   # our scratch obj (a static cell)
    mov     eax, 0x4CF23C
    call    rax                     # init(MYSCRATCH) → empty-vt
    mov     rcx, OFFSET MYSCRATCH
    mov     edx, OFFSET STR_LABEL   # «Use UTF-8»
    mov     eax, 0x4CF2DE
    call    rax                     # str-assign(MYSCRATCH, the label)
    mov     rax, QWORD PTR [r14]
    mov     rsi, QWORD PTR [rax+0x18]   # vt+0x18 (create-item)
    xor     r9d, r9d                # arg4 = 0
    mov     r8, OFFSET MYSCRATCH    # arg3 = our string-obj
    mov     edx, 0x99A              # arg2 = item ID
    mov     rcx, r14                # arg1 = menu
    call    rsi                     # create the checkbox item 0x99A
    mov     rcx, OFFSET MYSCRATCH
    mov     eax, 0x4CF0DA
    call    rax                     # destruct(MYSCRATCH) - balanced
    mov     rcx, QWORD PTR [r12+0x50]
    mov     edx, 0x99A
    mov     eax, OFFSET UTF8FLAG
    movzx   r8d, BYTE PTR [rax]     # flag&1
    mov     rax, QWORD PTR [rcx]
    call    QWORD PTR [rax+0x38]    # vt+0x38: set-check(0x99A, flag)
    lea     rsp, [rbp+0x20]
    pop     rbp
    ret

# ======================= READER_UTF8 ==================================
reader_utf8:
    push    rbp
    sub     rsp, 0x60
    mov     rbp, rsp                    # the frame anchor
    mov     eax, 0x65B0F5           # swap-reader (settings.dat) - the chain
    call    rax
    # 0x4AEF59 is NOT called a second time (mid-function: it uses the rcx/r12
    # context of the login builder - a repeated call with a garbage rcx = a CRASH,
    # the smoke-1 lesson). The swap-reader leaves r14 = the profile-dir string-obj
    # (its own `mov rdx,r14` pattern after 0x4AEF59) - we use it!
    mov     rdx, r14                # dir (from the swap-reader)
    mov     r8d, OFFSET STR_FILE    # "\\utf8.dat" (the FULL string - the esr2 lesson!)
    mov     ecx, OFFSET PATHC       # MY path cell
    mov     eax, 0x4B6C4C
    call    rax                     # path-join -> the string into the cell
    mov     eax, OFFSET PATHC
    mov     rcx, QWORD PTR [rax]    # the path object block
    add     rcx, 4                  # -> the C string
    mov     edx, 0x80000000         # GENERIC_READ
    mov     r8d, 1                  # share
    xor     r9, r9
    mov     DWORD PTR [rsp+0x20], 3     # OPEN_EXISTING
    mov     DWORD PTR [rsp+0x28], 0x80  # FILE_ATTRIBUTE_NORMAL
    mov     QWORD PTR [rsp+0x30], 0     # hTemplate
    mov     eax, 0x5F5F78           # CreateFileA IAT
    call    QWORD PTR [rax]
    mov     QWORD PTR [rbp+0x58], rax   # hFile
    cmp     QWORD PTR [rbp+0x58], -1
    je      L_rd_skip
    mov     rcx, QWORD PTR [rbp+0x58]
    lea     rdx, [rbp+0x50]         # the 8B buffer {magic, flag}
    mov     r8d, 8
    lea     r9, [rbp+0x4c]          # &n
    mov     QWORD PTR [rsp+0x20], 0
    mov     eax, 0x5F6100           # ReadFile IAT
    call    QWORD PTR [rax]
    test    eax, eax
    je      L_rd_close
    cmp     DWORD PTR [rbp+0x4c], 8     # n==8?
    jne     L_rd_close
    mov     rax, QWORD PTR [rbp+0x50]
    cmp     eax, 0x55384655         # the "U8FU" magic (OURS - not settings.dat!)
    jne     L_rd_close
    ror     rax, 0x20               # al = the flag byte dw[1]
    mov     edx, eax
    and     edx, 0xFFFFFFFE         # dw[1]&~1 == 0?
    test    edx, edx
    jne     L_rd_close
    mov     ecx, OFFSET UTF8FLAG    # the rcx scratch (al preserved - the blueprint canon)
    mov     BYTE PTR [rcx], al      # flag = the low byte of dw[1]
L_rd_close:
    mov     rcx, QWORD PTR [rbp+0x58]
    mov     eax, 0x5F5F68           # CloseHandle IAT
    call    QWORD PTR [rax]
L_rd_skip:
    lea     rsp, [rbp+0x60]
    pop     rbp
    ret

# ======================= DISPATCHER_UTF8 ==============================
dispatcher_utf8:
    cmp     dx, 0x936               # the 0x99A item command (0x99A-0x64)
    je      L_utf8_toggle
    jmp     0x65B1B8                # the chain -> the swap dispatcher (stock)
L_utf8_toggle:
    mov     eax, OFFSET UTF8FLAG
    xor     BYTE PTR [rax], 1       # flip
    mov     eax, OFFSET DIRTY
    or      QWORD PTR [rax], 1      # dirty
    mov     rcx, QWORD PTR [r12+0x50]
    mov     edx, 0x99A
    mov     eax, OFFSET UTF8FLAG
    movzx   r8d, BYTE PTR [rax]     # flag&1
    mov     rax, QWORD PTR [rcx]
    call    QWORD PTR [rax+0x38]    # update the checkbox
    mov     eax, OFFSET writer_utf8
    call    rax                     # the IMMEDIATE utf8.dat write
    jmp     0x4B42D9                # the stock dispatcher tail

# ======================= WRITER_UTF8 ==================================
writer_utf8:
    push    rbp
    sub     rsp, 0x60
    mov     rbp, rsp                    # the frame anchor
    mov     eax, OFFSET DIRTY
    cmp     DWORD PTR [rax], 0
    je      L_wr_out
    mov     eax, OFFSET PATHC
    mov     rcx, QWORD PTR [rax]
    add     rcx, 4                  # the path C string
    mov     edx, 0x40000000         # GENERIC_WRITE
    xor     r8, r8
    xor     r9, r9
    mov     DWORD PTR [rsp+0x20], 2     # CREATE_ALWAYS
    mov     DWORD PTR [rsp+0x28], 0x80
    mov     QWORD PTR [rsp+0x30], 0
    mov     eax, 0x5F5F78           # CreateFileA IAT
    call    QWORD PTR [rax]
    mov     QWORD PTR [rbp+0x58], rax
    cmp     QWORD PTR [rbp+0x58], -1
    je      L_wr_out
    mov     DWORD PTR [rbp+0x50], 0x55384655   # magic
    mov     eax, OFFSET UTF8FLAG
    mov     ecx, DWORD PTR [rax]    # flag (a dword read - the canon high zeros)
    mov     DWORD PTR [rbp+0x54], ecx
    mov     rcx, QWORD PTR [rbp+0x58]
    lea     rdx, [rbp+0x50]
    mov     r8d, 8
    lea     r9, [rbp+0x4c]
    mov     QWORD PTR [rsp+0x20], 0
    mov     eax, 0x5F6188           # WriteFile IAT
    call    QWORD PTR [rax]
    mov     rcx, QWORD PTR [rbp+0x58]
    mov     eax, 0x5F5F68           # CloseHandle IAT
    call    QWORD PTR [rax]
L_wr_out:
    # utf8d fix: destruct(PATHC) is REMOVED! Toggle #2 arrived with an empty
    # cell (toggle #1 freed the block; the rebuild happens only at login) ->
    # CreateFileA(empty) fail -> destruct(empty cell) through the heap shield
    # 0x658000 = 0xC0000374 on Win10 (epsilon utf8c_crash_off.dmp).
    # The new model: the pathc block lives the WHOLE session (we write on every toggle -
    # the path is always valid!), the rebuild/replacement happens at the next login (the reader
    # calls 0x4B6C4C -> assign replaces the block, the old one frees itself).
    lea     rsp, [rbp+0x60]
    pop     rbp
    ret

# ======================= STUB_DBLRES (send reserve ×2) ================
stub_dblres:
    xor     r8d, r8d                # was @0x42F3A0
    lea     edx, [ebx+ebx]          # the 2x reserve (capacity for UTF-8)
    jmp     0x42F3A5                # → mov rcx,r14; call 0x4CF7E0

# ======================= STORAGE_CONV (UTF-8->ACP, M2->model) ============
# A call-site hook 0x42AC13 (call 0x4CF2FE -> the assign wrapper -> 0x4CF14C):
# the SINGLE found (by the live ASSIGN HIT trace) entry of M2 strings into the model
# (the value decoder: rcx=dest obj, rdx=src, r8=end). The conversion HERE =
# the whole model (the list + dialog boxes + send defaults) sees a consistent
# ACP; the utf8a display hooks are REMOVED (no double conversion needed; the model is already ACP).
# Gate safety: a call-site gate by the very address (no other
# 0x4CF14C users - numbers/files/internal strings - are NOT touched!);
# ASCII no-op; invalid UTF-8 (cp1251-legacy, binary data) ->
# passthrough (MB_ERR_INVALID_CHARS); len <= 512 (the TEMP cap).
# Tail-call: after the conversion we call the original wrapper 0x4CF2FE with
# (dest, TEMP+4, TEMP+4+newlen) - 0x4CF14C sets len and copies by itself.
storage_conv:
    push    rbx
    push    rdi
    push    rsi
    push    rbp
    push    r12
    push    r13
    sub     rsp, 0x48               # rsp==0 (entry==8, 6 pushes=48, 0x48)
    mov     rsi, rcx                # dest string-obj
    mov     rdi, rdx                # src
    mov     rbx, r8                 # end
    mov     eax, OFFSET UTF8FLAG
    cmp     BYTE PTR [rax], 1
    jne     L_st_plain
    mov     r12, rbx
    sub     r12, rdi                # len = end - src
    test    r12, r12
    je      L_st_plain
    cmp     r12, 512                # the TEMP cap
    ja      L_st_plain
    mov     rcx, rdi
L_st_scan:
    cmp     rcx, rbx
    jae     L_st_plain              # ASCII → no-op
    movzx   edx, BYTE PTR [rcx]
    cmp     edx, 0x80
    jae     L_st_conv
    inc     rcx
    jmp     L_st_scan
L_st_conv:
    # wlen = MB2WC(CP_UTF8, MB_ERR_INVALID_CHARS, src, len, NULL, 0)
    mov     ecx, 65001
    mov     edx, 8
    mov     r8, rdi
    mov     r9d, r12d
    mov     QWORD PTR [rsp+0x20], 0
    mov     QWORD PTR [rsp+0x28], 0
    mov     eax, 0x4BCDE8
    call    rax
    test    eax, eax
    je      L_st_plain              # invalid -> cp1251/binary -> passthrough
    mov     rbp, rax                # wlen
    lea     rax, [rbp+rbp]
    add     rax, 0x40
    and     rax, -16
    mov     r13, rax                # the dynamic frame size
    sub     rsp, r13
    # MB2WC phase 2: (CP_UTF8, 0, src, len, wbuf, wlen)
    mov     ecx, 65001
    xor     edx, edx
    mov     r8, rdi
    mov     r9d, r12d
    lea     rax, [rsp+0x40]
    mov     QWORD PTR [rsp+0x20], rax
    mov     QWORD PTR [rsp+0x28], rbp
    mov     eax, 0x4BCDE8
    call    rax
    # WC2MB: (CP_ACP, 0, wbuf, wlen, TEMP+4, 512, NULL, NULL)
    xor     ecx, ecx
    xor     edx, edx
    lea     r8, [rsp+0x40]
    mov     r9d, ebp
    mov     eax, OFFSET TEMP
    lea     rax, [rax+4]
    mov     QWORD PTR [rsp+0x20], rax
    mov     QWORD PTR [rsp+0x28], 512
    mov     QWORD PTR [rsp+0x30], 0
    mov     QWORD PTR [rsp+0x38], 0
    mov     eax, 0x4BCDA0
    call    rax
    test    eax, eax
    je      L_st_dynplain
    mov     r8d, eax                # newlen
    mov     rcx, rsi                # dest
    mov     edx, OFFSET TEMP
    add     edx, 4                  # rdx = TEMP+4 (src)
    add     r8, rdx                 # r8 = TEMP+4+newlen (end)
    add     rsp, r13
    add     rsp, 0x48
    pop     r13
    pop     r12
    pop     rbp
    pop     rsi
    pop     rdi
    pop     rbx
    mov     eax, 0x4CF2FE           # the original assign wrapper (tail)
    jmp     rax
L_st_dynplain:
    add     rsp, r13
L_st_plain:
    mov     rcx, rsi
    mov     rdx, rdi
    mov     r8, rbx
    add     rsp, 0x48
    pop     r13
    pop     r12
    pop     rbp
    pop     rsi
    pop     rdi
    pop     rbx
    mov     eax, 0x4CF2FE
    jmp     rax

# ======================= CONV_GWTA (ACP→UTF-8, send) ==================
# Replaces call [GetWindowTextA] @0x42F3C6. Entry like GWTA: rcx=hwnd,
# rdx=buf, r8d=maxcount. Returns eax = the length (CONVERTED when ON).
conv_gwta:
    push    rbx
    push    rdi
    push    rsi
    push    rbp
    push    r12
    sub     rsp, 0x40               # rsp≡0
    mov     rdi, rdx                # buf
    mov     rsi, r8                 # maxcount (cap/2)
    mov     rbx, rcx                # hwnd
    mov     eax, 0x4BCA30           # the GWTA trampoline (original)
    call    rax                     # -> eax = the ACP length, buf NUL-terminated
    mov     ebx, eax                # the default length (returned on no-op)
    mov     eax, OFFSET UTF8FLAG
    cmp     BYTE PTR [rax], 1
    jne     L_cg_out
    test    ebx, ebx
    je      L_cg_out
    cmp     ebx, 0x8000
    ja      L_cg_out
    lea     rax, [rdi]
    lea     rcx, [rdi+rbx]          # end
L_cg_scan:
    cmp     rax, rcx
    jae     L_cg_out                # ASCII -> no-op (return the original length)
    movzx   edx, BYTE PTR [rax]
    cmp     edx, 0x80
    jae     L_cg_conv
    inc     rax
    jmp     L_cg_scan
L_cg_conv:
    # wlen = MB2WC(CP_ACP, 0, buf, len, NULL, 0)
    xor     ecx, ecx
    xor     edx, edx
    mov     r8, rdi
    mov     r9d, ebx
    mov     QWORD PTR [rsp+0x20], 0
    mov     QWORD PTR [rsp+0x28], 0
    mov     eax, 0x4BCDE8
    call    rax
    test    eax, eax
    je      L_cg_out
    mov     r12d, eax               # wlen
    lea     rax, [r12+r12]
    add     rax, 0x40
    and     rax, -16
    mov     rbp, rax                # the dynamic frame size
    sub     rsp, rbp
    # MB2WC phase 2: (CP_ACP, 0, buf, len, wbuf, wlen)
    xor     ecx, ecx
    xor     edx, edx
    mov     r8, rdi
    mov     r9d, ebx
    lea     rax, [rsp+0x40]
    mov     QWORD PTR [rsp+0x20], rax
    mov     QWORD PTR [rsp+0x28], r12
    mov     eax, 0x4BCDE8
    call    rax
    # WC2MB: (CP_UTF8, 0, wbuf, wlen, dst=buf, cb=2*maxcount, NULL, NULL)
    mov     ecx, 65001
    xor     edx, edx
    lea     r8, [rsp+0x40]
    mov     r9d, r12d
    mov     QWORD PTR [rsp+0x20], rdi   # dst = buf
    lea     rax, [rsi+rsi]          # cb = 2*maxcount (the reserve is doubled!)
    mov     QWORD PTR [rsp+0x28], rax
    mov     QWORD PTR [rsp+0x30], 0
    mov     QWORD PTR [rsp+0x38], 0
    mov     eax, 0x4BCDA0
    call    rax
    test    eax, eax
    je      L_cg_dynout
    mov     BYTE PTR [rdi+rax], 0   # NUL-termination (the following code expects it)
    add     rsp, rbp                # eax = newlen - the RETURN
    add     rsp, 0x40
    pop     r12
    pop     rbp
    pop     rsi
    pop     rdi
    pop     rbx
    ret
L_cg_dynout:
    add     rsp, rbp
L_cg_out:
    mov     eax, ebx                # the original ACP length
    add     rsp, 0x40
    pop     r12
    pop     rbp
    pop     rsi
    pop     rdi
    pop     rbx
    ret

# ======================= CF286_CONV (canvas send, ACP→UTF-8) ===========
# An entry hook 0x4CF286 (assign-obj: rcx=dest, rdx=src_obj - 281 callers!).
# GATE BY RETURN ADDRESS: [0x428000..0x429300) = the canvas field
# handler zone (49 callers of the 0x427FCE finder; the live rwatch trace: the SSID goes
# through the handler with call 0x4CF286 @0x428F3A, bt 0x428F3F). The other 279
# callers (internal copies, the model etc.) are NOT touched.
# Conversion: the canvas editor stores the text in ACP (the user types cp1251)
# -> on extraction into the value-rec we convert to a TEMP-obj (UTF-8) -> wire.
# Gates: flag ON + len <= 512 + bytes >=0x80 (ASCII/numbers = no-op).
# RECEIVE of the canvas fields is NOT covered yet (the SSID field shows raw
# UTF-8/mojibake when ON) - a separate task (Phase-2).
cf286_hook:
    # GATE: ONLY the call site proven by the live trace (LATE HIT #3389)
    # 0x51EFED inside the vtable wrapper 0x51EFE0 (get-value: rdx+0x60-obj ->
    # assign). The get direction is guaranteed (the wrapper always puts
    # the widget-obj into rdx/src). The other 280 callers - a pure passthrough.
    # (38 similar wrappers in .text - extend the gate only per QA data!)
    mov     rax, [rsp]
    cmp     rax, 0x51EFF2            # the ret after the call @0x51EFED
    jne     L_c2_orig
    mov     rax, OFFSET UTF8FLAG
    cmp     BYTE PTR [rax], 1
    jne     L_c2_orig
    push    rbx
    push    rdi
    push    rsi
    push    rbp
    push    r12
    sub     rsp, 0x40                # rsp==0 (entry==8, 5 pushes=40, 0x40)
    mov     rbx, rcx                 # dest obj
    mov     rdi, rdx                 # src obj (editor)
    mov     rax, QWORD PTR [rdi]     # block
    mov     esi, DWORD PTR [rax]     # len
    test    esi, esi
    je      L_c2_plain
    cmp     esi, 512
    ja      L_c2_plain
    lea     rcx, [rax+4]             # src
    lea     rax, [rcx+rsi]           # end
L_c2_scan:
    cmp     rcx, rax
    jae     L_c2_plain               # ASCII → no-op
    movzx   edx, BYTE PTR [rcx]
    cmp     edx, 0x80
    jae     L_c2_conv
    inc     rcx
    jmp     L_c2_scan
L_c2_conv:
    # wlen = MB2WC(CP_ACP, 0, src, len, NULL, 0)
    xor     ecx, ecx
    xor     edx, edx
    mov     r8, QWORD PTR [rdi]
    add     r8, 4
    mov     r9d, esi
    mov     QWORD PTR [rsp+0x20], 0
    mov     QWORD PTR [rsp+0x28], 0
    mov     eax, 0x4BCDE8
    call    rax
    test    eax, eax
    je      L_c2_plain
    mov     r12d, eax                # wlen
    lea     rax, [r12+r12]
    add     rax, 0x40
    and     rax, -16
    mov     rbp, rax                 # the dynamic frame size
    sub     rsp, rbp
    # MB2WC phase 2: (ACP, 0, src, len, wbuf, wlen)
    xor     ecx, ecx
    xor     edx, edx
    mov     r8, QWORD PTR [rdi]
    add     r8, 4
    mov     r9d, esi
    lea     rax, [rsp+0x40]
    mov     QWORD PTR [rsp+0x20], rax
    mov     QWORD PTR [rsp+0x28], r12
    mov     eax, 0x4BCDE8
    call    rax
    # WC2MB: (CP_UTF8, 0, wbuf, wlen, TEMPBLOCK+4, 512, 0, 0)
    mov     ecx, 65001
    xor     edx, edx
    lea     r8, [rsp+0x40]
    mov     r9d, r12d
    mov     eax, OFFSET TEMPBLOCK
    lea     rax, [rax+4]
    mov     QWORD PTR [rsp+0x20], rax
    mov     QWORD PTR [rsp+0x28], 512
    mov     QWORD PTR [rsp+0x30], 0
    mov     QWORD PTR [rsp+0x38], 0
    mov     eax, 0x4BCDA0
    call    rax
    test    eax, eax
    je      L_c2_dynplain
    mov     rcx, OFFSET TEMPBLOCK
    mov     DWORD PTR [rcx], eax    # TEMPBLOCK.len = newlen
    mov     rax, OFFSET TEMPOBJ
    mov     QWORD PTR [rax], rcx    # TEMPOBJ.block = TEMPBLOCK
    mov     rdi, OFFSET TEMPOBJ     # src_obj := TEMP-obj
L_c2_dynplain:
    add     rsp, rbp
L_c2_plain:
    mov     rcx, rbx                # dest
    mov     rdx, rdi                # src_obj (TEMP or the original)
    add     rsp, 0x40
    pop     r12
    pop     rbp
    pop     rsi
    pop     rdi
    pop     rbx
    mov     rax, QWORD PTR [rdx]    # the replaced instruction 1 (48 8B 02)
    mov     r8d, DWORD PTR [rax]    # the replaced instruction 2 (44 8B 00)
    jmp     0x4CF28C                # the continuation of 0x4CF286
L_c2_orig:                          # outside the zone/OFF: a pure passthrough
    mov     rax, QWORD PTR [rdx]
    mov     r8d, DWORD PTR [rax]
    jmp     0x4CF28C

# ======================= DATA ==========================================
STR_LABEL:
    .ascii "Use UTF-8\0"
    .zero 7
STR_FILE:
    .ascii "\\utf8.dat\0"           # the FULL string with the backslash (the esr2 lesson)
    .zero 5
UTF8FLAG:                           # the flag byte (0 = stock WB3)
    .zero 8
PATHC:                              # the path string-obj (a cell)
    .zero 8
DIRTY:                              # the write dirty flag
    .zero 8
TEMP:                               # the static conversion buffer {len,data[512]}
    .zero 0x210
MYSCRATCH:                          # our menu-item string-obj (the utf8c fix)
    .zero 8
TEMPOBJ:                            # canvas-send TEMP string-obj (utf8e)
    .zero 8
TEMPBLOCK:                          # {u32 len, data[512]}
    .zero 0x204
