# jg_unified_inject.s - THE UNIFIED CAVE @0x659560: the v104 Ping+Traceroute fields
# AFTER the stock Range.
# Architecture: the stock jgmem is NOT touched (the
# Range block 0x6590D1-0x65915A works as in the original - Range+slots+
# FSEEKFN = a coherent stock machine!); the trampoline @0x65915A (8B cmpq
# -> e9+3nop) -> THIS cave -> a replica of the CloseHandle block
# (0x65915A-0x659186 - MANDATORY before jmp 0x659187, otherwise a
# share-lock!) -> jmp 0x659187.
# The FSEEK slots 0x659520/0x659528 are NOT touched (the stock Range
# block writes them).
# Anti-dup: I1 - the "name:'Interface'" gate in a 160B window back; I2 -
# the DSCP-context marker (the marker itself disappears after the
# insertion -> a repeat = a no-op).
.intel_syntax noprefix
.code64
.set CHA, 0x5F5F68     # CloseHandle

.globl unified2
unified2:
    # ===== STRICT FIX: Policy Rules strict:1 -> strict:0 (1B!) =====
    # strict = the main candidate for the red mark (alpha's T2 test!)
    # Packet Mark (without strict) works -> Policy Rules (with strict) red
    # Change 1->0 = the minimal isolating test!
    xor  r12, r12
    lea  rsi, [rip+U_STRMARK]   # combo marker (17B)
    mov  rcx, 17
    call 0x65929C               # FIND -> rax = position
    test rax, rax
    jz   U_no_strict_fix        # not found -> skip
    
    # Check the context: it must be a Policy Rules sub-field (s2c2f08 nearby)
    # Simple approach: just replace ALL strict:1 -> strict:0
    # (in the 7.25 jg strict:1 appears in several places - check!)
    
    # REPLACEMENT: "strict:1" -> "min:1   " (8B same-length!)
    # min:1 = empty strings forbidden (a non-empty validation)
    # 3 padding spaces (the parser ignores them, as g82 proved)
    lea  rbx, [r14+rax]         # buffer + marker position
    # "strict:1" starts at offset 9 from the marker start (s2c2f08',)
    lea  rdi, [rbx+9]           # the "strict:1" position
    lea  rsi, [rip+U_MINREPL]  # "min:1   " (8B)
    mov  rcx, 8
    rep  movsb                   # copy 8B over "strict:1"
    
U_no_strict_fix:
    # ===== I1: Ping VRF+Interface (183B) before {name:'ARP Ping' =====
    xor  r12, r12
    lea  rsi, [rip+U_M1]
    mov  rcx, 36
    call 0x65929C
    test rax, rax
    jz   U_I2                      # no Ping -> to Traceroute
    mov  rbx, rax
    # gate: is Interface already there? (a 160B window back)
    mov  r8, rbx
    sub  r8, 300                 # extended window (was 160 - the old injections sit further!)
    jle  U_I1_ins
    mov  rdi, rbx
U_g1:
    cmp  r8, rdi
    jae  U_I1_ins
    lea  rax, [r14+r8]
    lea  rsi, [rip+U_G1]
    xor  r13, r13
U_gc1:
    mov  dl, [rax+r13]
    cmp  dl, [rsi+r13]
    jne  U_gn1
    inc  r13
    cmp  r13, 16
    jb   U_gc1
    jmp  U_I2                      # Interface already there -> skip Ping
U_gn1:
    inc  r8
    jmp  U_g1
U_I1_ins:
    mov  [0x6598F8], rbx    # save the I1 position for the post-Range correction
    mov  rcx, r15                  # shift the tail +183
U_sh1:
    cmp  rcx, rbx
    jbe  U_sh1d
    mov  dl, [r14+rcx-1]
    lea  rax, [rcx-1+183]
    mov  [r14+rax], dl
    dec  rcx
    jmp  U_sh1
U_sh1d:
    lea  rsi, [rip+U_N1]
    xor  r13, r13
U_cp1:
    mov  dl, [rsi+r13]
    lea  rax, [rbx+r13]
    mov  [r14+rax], dl
    inc  r13
    cmp  r13, 183
    jb  U_cp1
    add  r15, 183
    # ===== I2: Traceroute Interface+VRF (182B combined) =====
U_I2:
    xor  r12, r12
    lea  rsi, [rip+U_M2]
    mov  rcx, 19                  # marker length = 19B
    call 0x65929C
    test rax, rax
    jz   U_torange                 # no marker -> to Range
    mov  rbx, rax
    add  rbx, 6                   # SKIP "ab'}]}" - the injection goes AFTER the group closes!
    mov  rcx, r15                  # shift +182
U_sh2:
    cmp  rcx, rbx
    jbe  U_sh2d
    mov  dl, [r14+rcx-1]
    lea  rax, [rcx-1+182]
    mov  [r14+rax], dl
    dec  rcx
    jmp  U_sh2
U_sh2d:
    lea  rsi, [rip+U_N2]
    xor  r13, r13
U_cp2:
    mov  dl, [rsi+r13]
    lea  rax, [rbx+r13]
    mov  [r14+rax], dl
    inc  r13
    cmp  r13, 182
    jb  U_cp2
    add  r15, 182
    mov  [0x6598FC], rbx
    sub  qword ptr [0x6598FC], 183  # I2 in original coords
U_torange:
    # the Range pre-check in a separate cave @0x65A700
    jmp  0x65A700

.align 8
U_STRMARK: .ascii "s2c2f08',strict:1"  # 17B unique combo marker!
U_M1:  .ascii "{name:'ARP Ping',type:'bool',id:'bb'\0"
U_G1:  .ascii "name:'Interface'\0"
U_M2:  .ascii "ab'}]},{name:'DSCP'\0"
U_N1:  .ascii "{name:'VRF',type:'opt',c:[{type:'enm',id:'u10',values:{type:'dynamic',path:[ 20,101 ]}}]},{name:'Interface',type:'opt',c:[{type:'enm',id:'ua',values:{type:'dynamic',path:[ 20,0 ]}}]},"
U_N2:  .ascii ",{name:'Interface',type:'opt',c:[{type:'enm',id:'uc',values:{type:'dynamic',path:[ 20,0 ]}}]},{name:'VRF',type:'opt',c:[{type:'enm',id:'ud',values:{type:'dynamic',path:[ 20,101 ]}}]}"

U_MINREPL:  .ascii "min:1   "  # the 8B strict:1 replacement!
