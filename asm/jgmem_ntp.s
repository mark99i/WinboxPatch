# jgmem_ntp.s - the in-memory roteros.jg transformation cave (the Apply
# fix).
# Position: 0x659000 (under the fopen hook 0x4B7A17 retarget - the
# builder does the e9 patch; the old file stab 0x65B400 stays as dead
# code).
#
# WHAT IT DOES: Apply in the Num Set dialogs rejects Range input on
# 7.25+ ("num range not specified") - the Range field became the
# bignumberrange type, which the client cannot assemble. The cave:
#  - on fopen(roteros.jg): reads the file, builds a transformed in-
#    memory IMAGE (Range: bignumberrange -> a tuple of two bignumber,
#    +37B, idempotent - an already-transformed marker), keeps the image
#    for the session;
#  - serves the subsequent fread calls from the image (the msvcrt
#    items semantics: fread returns ITEMS n/size, not bytes - divide!);
#  - the handle gate matches the roteros.jg path STRICTLY + clears
#    ROS_HND on fclose: msvcrt REUSES FILE* structs - without the
#    clearing the icon sprites and foreign jg files receive foreign
#    data (icons/WiFi/PPP/IPv6 disappear);
#  - the on-disk file is NOT touched (virgin, re-downloading stays
#    intact).
#
# CANON: the fread/fclose IAT patches through slots; the image lives
# for the session (never freed!); the +37B insertion shifts the tail -
# reads go through the image only (not by the original offsets!).
.intel_syntax noprefix
.code64
.globl jgpatch
jgpatch:
    push rcx
    push rdx
    push rdi
    push rsi
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x48           # 9 pushes + 0x48 = 144 == 0 (mod16), call-site entry rsp==0
    mov  [rsp+0x30], rcx            # path
    # --- path-scan: "roteros.jg" (the only gate; cmr.jg and the rest - the untouched original) ---
    mov  rdi, rcx
    xor  r12, r12
L_ps:
    cmp  byte ptr [rdi+r12], 0
    je   L_orig
    lea  rsi, [rip+FJG]
    xor  r13, r13
L_pc:
    mov  rax, r12
    add  rax, r13
    mov  dl, [rdi+rax]
    cmp  dl, [rsi+r13]
    jne  L_pn
    inc  r13
    cmp  r13, 10
    jb   L_pc
    jmp  RT_BEGIN                   # roteros.jg -> read+transform
L_pn:
    inc  r12
    jmp  L_ps

# ================= READ THE FILE INTO THE IMAGE (as-is jgmem) =================
RT_BEGIN:
    mov  rcx, [rsp+0x30]
    mov  edx, 0x80000000            # GENERIC_READ
    xor  r8d, r8d
    xor  r9d, r9d
    mov  dword ptr [rsp+0x20], 3    # OPEN_EXISTING
    mov  qword ptr [rsp+0x28], 0
    call QWORD PTR [0x5f5f78]       # CreateFileA
    cmp  rax, -1
    je   L_orig
    mov  rbx, rax
    mov  qword ptr [rip+HND], rax
    mov  ecx, 0x200000
    call 0x4d53a0                   # malloc(2MB)
    test rax, rax
    je   L_cl
    mov  r14, rax
    mov  rcx, rbx
    mov  rdx, r14
    mov  r8d, 0x200000
    lea  r9, [rsp+0x38]
    mov  qword ptr [rsp+0x20], 0
    call QWORD PTR [0x5f6100]       # ReadFile (single)
    movsxd r15, dword ptr [rsp+0x38]
    test r15, r15
    jle  L_close

# ================= RANGE-TUPLE TRANSFORMATION (the only one) =================
    # idempotency: OLD (113B) already in the image -> skip
    xor  r12, r12
    lea  rsi, [rip+F_OLDRANGE]
    mov  rcx, 113
    call FIND_M
    test rax, rax
    jnz  L_rewrite
    # search NEW (76B)
    xor  r12, r12
    lea  rsi, [rip+F_NEWRANGE]
    mov  rcx, 76
    call FIND_M
    test rax, rax
    jz   L_rewrite                  # no marker - the image stays untouched
    mov  rbx, rax                   # the NEW position
    lea  rdx, [rbx+76]              # end of NEW = tail start
    mov  rcx, r15
RT_sh:
    cmp  rcx, rdx
    jbe  RT_shd
    mov  al, [r14+rcx-1]
    mov  [r14+rcx-1+37], al
    dec  rcx
    jmp  RT_sh
RT_shd:
    lea  rsi, [rip+F_OLDRANGE]
    xor  r13, r13
RT_ins:
    mov  dl, [rsi+r13]
    lea  rax, [rbx+r13]
    mov  [r14+rax], dl
    inc  r13
    cmp  r13, 113
    jb   RT_ins
    add  r15, 37                    # LEN += 37
    mov  QWORD PTR [rip+INSERT_POS], rbx   # insertion position (original coords)
    mov  QWORD PTR [rip+DELTA], 37

# ================= STASH + IAT PATCH (as-is jgmem) =================
L_rewrite:
    cmp  qword ptr [rip+HND], 0
    je   L_rw1
    mov  rcx, qword ptr [rip+HND]
    mov  qword ptr [rip+HND], 0
    call QWORD PTR [0x5f5f68]       # CloseHandle (share=0 -> the file is free for the original fopen)
L_rw1:
    mov  rcx, rbx
    call QWORD PTR [0x5f5f68]
    mov  qword ptr [rip+ROS_IMG], r14
    mov  qword ptr [rip+ROS_LEN], r15
    mov  qword ptr [rip+ROS_POS], 0
    cmp  qword ptr [rip+IATDONE], 0
    jne  L_orig
    mov  rax, QWORD PTR [0x5f62a8]
    mov  QWORD PTR [rip+ORIGFREAD], rax
    mov  QWORD PTR [0x5f62a8], offset FREADFN
    mov  rax, QWORD PTR [0x5f62b8]
    mov  QWORD PTR [rip+ORIGFSEEK], rax
    mov  QWORD PTR [0x5f62b8], offset FSEEKFN
    mov  rax, QWORD PTR [0x5f6270]
    mov  QWORD PTR [rip+ORIGFCLOSE], rax
    mov  QWORD PTR [0x5f6270], offset FCLOSEFN
    mov  qword ptr [rip+IATDONE], 1
    jmp  L_orig_ros                 # the image LIVES for the session - NEVER freed!
L_close:
    cmp  qword ptr [rip+HND], 0
    je   L_close_rbx
    mov  rcx, qword ptr [rip+HND]
    mov  qword ptr [rip+HND], 0
    call QWORD PTR [0x5f5f68]
    jmp  L_free
L_close_rbx:
    mov  rcx, rbx
    call QWORD PTR [0x5f5f68]
L_free:
    mov  rcx, r14
    call 0x4d5408
L_orig:
    add  rsp, 0x48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    pop  rdx
    pop  rcx
    call QWORD PTR [0x5f6290]       # original fopen
    jmp  0x4b7a1c                   # WITHOUT writing ROS_HND (v5: foreign jg must not capture the gate!)
L_orig_ros:
    add  rsp, 0x48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    pop  rdx
    pop  rcx
    call QWORD PTR [0x5f6290]       # original fopen
    mov  qword ptr [rip+ROS_HND], rax   # the roteros.jg path ONLY!
    jmp  0x4b7a1c
L_cl:
    mov  rcx, qword ptr [rip+HND]
    test rcx, rcx
    jne  L_cl2
    mov  rcx, rbx
L_cl2:
    call QWORD PTR [0x5f5f68]
    jmp  L_orig

# ============ FIND_M: rsi=marker, rcx=mlen; r12=start,r15=size,r14=buf → rax=pos|0 ============
FIND_M:
    xor  rax, rax
FM_l:
    cmp  r12, r15
    jae  FM_done
    lea  rdi, [r14+r12]
    xor  r13, r13
FM_c:
    mov  dl, [rdi+r13]
    cmp  dl, [rsi+r13]
    jne  FM_n
    inc  r13
    cmp  r13, rcx
    jb   FM_c
    mov  rax, r12
    ret
FM_n:
    inc  r12
    jmp  FM_l
FM_done:
    ret

# ================= FREADFN (IAT interception, in-memory substitution; ROS ONLY) =================
# callee entry (rsp=8 mod 16): rcx=buf rdx=size r8=count r9=FILE*
FREADFN:
    push rbp
    mov  rbp, rsp
    sub  rsp, 0x20                # locals: [rbp-0x10]=buf, [rbp-0x18]=n
    mov  QWORD PTR [rbp-0x10], rcx   # buf
    mov  r10, QWORD PTR [rip+ROS_HND]
    test r10, r10
    je   FR_pass
    cmp  r9, r10
    jne  FR_pass
    # our file: n = min(rdx*r8, LEN-POS)
    mov  rax, rdx
    imul rax, r8
    mov  rcx, QWORD PTR [rip+ROS_LEN]
    sub  rcx, QWORD PTR [rip+ROS_POS]
    cmp  rax, rcx
    jbe  FR_have
    mov  rax, rcx
FR_have:
    test rax, rax
    jz   FR_zero
    mov  QWORD PTR [rbp-0x18], rax   # n
    push rdi
    push rsi
    mov  rsi, QWORD PTR [rip+ROS_IMG]
    add  rsi, QWORD PTR [rip+ROS_POS]
    mov  rdi, QWORD PTR [rbp-0x10]   # buf
    mov  rcx, QWORD PTR [rbp-0x18]   # n
    cld
    rep  movsb
    pop  rsi
    pop  rdi
    add  QWORD PTR [rip+ROS_POS], rax
    # === RETURN IN ITEMS (the MSVCRT fread semantics: ret = n/size)! ===
    # rdx = size (not clobbered: rep movsb touches only rcx/rsi/rdi; rcx after movsb=0)
    test rdx, rdx
    je   FR_zret             # size=0 -> 0 items
    mov  rcx, rdx            # rcx = size
    xor  edx, edx            # the high part of the dividend
    div  rcx                 # rax = n / size = FULL items
    jmp  FR_ret
FR_zret:
    xor  eax, eax
    jmp  FR_ret
FR_zero:
    xor  eax, eax
FR_ret:
    leave
    ret
FR_pass:
    leave
    jmp  QWORD PTR [rip+ORIGFREAD]   # clean passthrough (the stack restored)

# ================= FSEEKFN (IAT [0x5f62b8]; the icon PNG reader calls fseek(CUR,+4)!) =================
# fseek(FILE*, long off, int whence): rcx=FILE*, edx=off(32!), r8d=whence
# Our file -> apply the seek to ROS_POS (with a +DELTA correction for SET past the insertion point).
FSEEKFN:
    mov  rax, QWORD PTR [rip+ROS_HND]
    test rax, rax
    je   FS_pass
    cmp  rcx, rax
    jne  FS_pass
    cmp  r8d, 1
    je   FS_cur
    cmp  r8d, 2
    je   FS_end
    # --- SEEK_SET: POS = off + (off >= INSERT_POS ? DELTA : 0) ---
    mov  eax, edx
    cmp  rax, QWORD PTR [rip+INSERT_POS]
    jae  FS_add
    jmp  FS_set
FS_add:
    add  rax, QWORD PTR [rip+DELTA]
FS_set:
    mov  QWORD PTR [rip+ROS_POS], rax
    jmp  FS_clamp
FS_cur:
    movsxd rax, edx
    add  rax, QWORD PTR [rip+ROS_POS]
    mov  QWORD PTR [rip+ROS_POS], rax
    jmp  FS_clamp
FS_end:
    movsxd rax, edx
    add  rax, QWORD PTR [rip+ROS_LEN]
    mov  QWORD PTR [rip+ROS_POS], rax
FS_clamp:
    test rax, rax
    jns  FS_c1
    xor  eax, eax
    mov  QWORD PTR [rip+ROS_POS], rax
    jmp  FS_ok
FS_c1:
    cmp  rax, QWORD PTR [rip+ROS_LEN]
    jbe  FS_ok
    mov  rax, QWORD PTR [rip+ROS_LEN]
    mov  QWORD PTR [rip+ROS_POS], rax
FS_ok:
    xor  eax, eax
    ret
FS_pass:
    jmp  QWORD PTR [rip+ORIGFSEEK]

# ================= FCLOSEFN (IAT [0x5f6270]): clearing ROS_HND =================
# THE ICON REGRESSION ROOT: msvcrt REUSES FILE* structs! After fclose(roteros.jg)
# the same FILE* is handed to icons16.png -> the FREADFN gate falsely matches -> the PNG reader
# receives jg-image data -> "sprite 32 icons" fail -> the icons disappear.
# Fix: on closing OUR file we clear ROS_HND (the gate no longer fires).
# fclose(FILE*): rcx=FILE*. Tail-jmp passthrough (like FSEEKFN).
FCLOSEFN:
    mov  rax, QWORD PTR [rip+ROS_HND]
    test rax, rax
    je   FC_pass
    cmp  rcx, rax
    jne  FC_pass
    xor  eax, eax
    mov  QWORD PTR [rip+ROS_HND], rax
FC_pass:
    jmp  QWORD PTR [rip+ORIGFCLOSE]

    .align 16
FJG:       .ascii "roteros.jg\0"
F_NEWRANGE: .ascii "{name:'Range',type:'bignumberrange',id:'q2c5504',highid:'q2c5505',width:200}"
F_OLDRANGE: .ascii "{name:'Range',type:'tuple',sep:'-',width:200,c:[{type:'bignumber',id:'q2c5504'},{type:'bignumber',id:'q2c5505'}]}"
    .align 16
HND:
    .quad 0

    .align 16
ROS_HND:  .quad 0
ROS_IMG:  .quad 0
ROS_LEN:  .quad 0
ROS_POS:  .quad 0
IATDONE:  .quad 0
ORIGFREAD: .quad 0
ORIGFSEEK: .quad 0
ORIGFCLOSE: .quad 0
INSERT_POS: .quad 0xFFFFFFFFFFFFFFFF   # insertion position (original coords); max = no transformation
DELTA:     .quad 0
