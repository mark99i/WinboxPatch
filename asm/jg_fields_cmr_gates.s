# jgpatch_v2 - common stab v2: ping+traceroute injection (4 insertions,
#   positions per the user reference: Interface after Src. Address, VRF
#   after DSCP) + CMR transformation (as-is cmr6b).
# VA 0x65B400. Hook fopen 0x4b7a17 (unchanged).
# Positions (user directive 2026-11-04):
#   PING:       Interface before {Packet Size u3} (i.e. right after Src. Address);
#              VRF     before {Dont Fragment} (find id:'u12' after Packet Size -> next {name:').
#   TRACEROUTE: Interface before {DSCP u6} (find Traceroute To -> id:'u8' -> next {name:');
#              VRF     before {name:'udp' (cond tail).
# Gates: ping = "id:'ua'" (any old/new ping injection); tr = "id:'u12',values:".
# id space: ping {Interface=ua, VRF=u10}; traceroute {Interface=u12, VRF=u11} (u10 is taken by Max Hops).
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
    sub  rsp, 0x48           # 9 pushes + 0x48 = 144 == 0 (mod16)
    mov  [rsp+0x30], rcx            # path
    # --- path-scan: "roteros.jg" ---
    mov  rdi, rcx
    xor  r12, r12
L_ps:
    cmp  byte ptr [rdi+r12], 0
    je   L_cmr_ps
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
    jmp  PINGV2
L_pn:
    inc  r12
    jmp  L_ps
    # --- path-scan: "cmr.jg" ---
L_cmr_ps:
    mov  rdi, [rsp+0x30]
    xor  r12, r12
L_cps:
    cmp  byte ptr [rdi+r12], 0
    je   L_orig
    lea  rsi, [rip+FCMR]
    xor  r13, r13
L_cpc:
    mov  rax, r12
    add  rax, r13
    mov  dl, [rdi+rax]
    cmp  dl, [rsi+r13]
    jne  L_cpn
    inc  r13
    cmp  r13, 6
    jb   L_cpc
    jmp  CMR
L_cpn:
    inc  r12
    jmp  L_cps

# ================= PING+TRACEROUTE v2 =================
PINGV2:
    mov  rcx, [rsp+0x30]
    mov  edx, 0x80000000
    xor  r8d, r8d
    xor  r9d, r9d
    mov  dword ptr [rsp+0x20], 3
    mov  qword ptr [rsp+0x28], 0
    call QWORD PTR [0x5f5f78]
    cmp  rax, -1
    je   L_orig
    mov  rbx, rax
    mov  qword ptr [rip+HND], rax
    mov  ecx, 0x200000
    call 0x4d53a0
    test rax, rax
    je   L_cl
    mov  r14, rax
    mov  rcx, rbx
    mov  rdx, r14
    mov  r8d, 0x200000
    lea  r9, [rsp+0x38]
    mov  qword ptr [rsp+0x20], 0
    call QWORD PTR [0x5f6100]
    movsxd r15, dword ptr [rsp+0x38]
    test r15, r15
    jle  L_close
    # --- PING GATE (zone-based, v3): ANY name:'Interface' inside the
    #     Ping dialog window ({name:'Ping To' .. {name:'Traceroute To'}) = duplicate -> skip ---
    xor  r12, r12
    lea  rsi, [rip+M_PTO]
    mov  rcx, 15                    # FULL marker {name:'Ping To' (15B!
                                     # 12B caught PoE 'Ping To IP4' -> false zone)
    call FIND_M
    test rax, rax
    jz   PING_DONE                # no Ping dialog - do not touch
    mov  r12, rax
    push r12                      # SAVE the zone start (FIND_M moves r12!)
    lea  rsi, [rip+M_TT]
    mov  rcx, 21
    call FIND_M
    test rax, rax
    jz   PING_POP                 # no Traceroute -> pop and skip
    mov  rbx, r15                 # save the file size
    mov  r15, rax                 # r15 = end of the Ping zone
    pop  r12                      # RESTORE the zone start (otherwise an empty range!)
    lea  rsi, [rip+M_IF]
    mov  rcx, 16
    call FIND_M
    mov  r15, rbx                 # restore the size
    test rax, rax
    jnz  PING_DONE                # Interface already in the zone (ours/old/native) -> skip
    jmp  PING_GO
PING_POP:
    pop  r12
    jmp  PING_DONE
PING_GO:
    # (gate passed: no Interface in the Ping zone) ---
    xor  r12, r12
    lea  rsi, [rip+M_ARP]
    mov  rcx, 16
    call FIND_M
    test rax, rax
    jz   PING_DONE                # no marker - do not touch ping
    mov  rbx, rax
    mov  rcx, r15
PA_sh:
    cmp  rcx, rbx
    jbe  PA_shd
    mov  al, [r14+rcx-1]
    mov  [r14+rcx-1+183], al
    dec  rcx
    jmp  PA_sh
PA_shd:
    lea  rsi, [rip+NODE_IFP]
    xor  r13, r13
PA_ins:
    mov  dl, [rsi+r13]
    lea  rax, [rbx+r13]
    mov  [r14+rax], dl
    inc  r13
    cmp  r13, 93
    jb   PA_ins
    lea  rsi, [rip+NODE_VRFP]
    xor  r13, r13
PA_ins2:
    mov  dl, [rsi+r13]
    lea  rax, [rbx+93]
    add  rax, r13
    mov  [r14+rax], dl
    inc  r13
    cmp  r13, 90
    jb   PA_ins2
    add  r15, 183
PING_DONE:
    # --- TR GATE (zone-based, v3): ANY name:'Interface' in the Traceroute window (+1500B) ---
    xor  r12, r12
    lea  rsi, [rip+M_TT]
    mov  rcx, 21
    call FIND_M
    test rax, rax
    jz   L_rewrite                # no Traceroute - do not touch
    mov  r12, rax
    lea  rax, [r12+1500]
    mov  rbx, r15
    cmp  rax, r15
    jb   TR_L1
    mov  rax, r15
TR_L1:
    mov  r15, rax                 # r15 = end of the window
    lea  rsi, [rip+M_IF]
    mov  rcx, 16
    call FIND_M
    mov  r15, rbx
    test rax, rax
    jnz  L_rewrite                # Interface already in the window -> skip
    # --- TR 1: Traceroute To -> id:'u8' -> next {name:' (=DSCP) -> NODE_IFT (94B, id u12) ---
    xor  r12, r12
    lea  rsi, [rip+M_TT]
    mov  rcx, 21
    call FIND_M
    test rax, rax
    jz   L_rewrite
    mov  r12, rax
    lea  rsi, [rip+M_U8]
    mov  rcx, 7
    call FIND_M
    test rax, rax
    jz   L_rewrite
    mov  r12, rax
    lea  rsi, [rip+M_FIELD]
    mov  rcx, 7
    call FIND_M
    test rax, rax
    jz   L_rewrite
    mov  rbx, rax
    mov  rcx, r15
TI_sh:
    cmp  rcx, rbx
    jbe  TI_shd
    mov  al, [r14+rcx-1]
    mov  [r14+rcx-1+94], al
    dec  rcx
    jmp  TI_sh
TI_shd:
    lea  rsi, [rip+NODE_IFT]
    xor  r13, r13
TI_ins:
    mov  dl, [rsi+r13]
    lea  rax, [rbx+r13]
    mov  [r14+rax], dl
    inc  r13
    cmp  r13, 94
    jb   TI_ins
    add  r15, 94
    # --- TR 2: {name:'udp' -> NODE_VRFT (90B, id u11) ---
    mov  r12, rbx
    lea  rsi, [rip+M_UDP]
    mov  rcx, 11
    call FIND_M
    test rax, rax
    jz   L_rewrite
    mov  rbx, rax
    mov  rcx, r15
TV_sh:
    cmp  rcx, rbx
    jbe  TV_shd
    mov  al, [r14+rcx-1]
    mov  [r14+rcx-1+90], al
    dec  rcx
    jmp  TV_sh
TV_shd:
    lea  rsi, [rip+NODE_VRFT]
    xor  r13, r13
TV_ins:
    mov  dl, [rsi+r13]
    lea  rax, [rbx+r13]
    mov  [r14+rax], dl
    inc  r13
    cmp  r13, 90
    jb  TV_ins
    add  r15, 90
    jmp  L_rewrite

# ================= CMR FUNCTION (as-is cmr6b) =================
CMR:
    mov  rcx, [rsp+0x30]
    mov  edx, 0x80000000
    xor  r8d, r8d
    xor  r9d, r9d
    mov  dword ptr [rsp+0x20], 3
    mov  qword ptr [rsp+0x28], 0
    call QWORD PTR [0x5f5f78]
    cmp  rax, -1
    je   L_orig
    mov  rbx, rax
    mov  qword ptr [rip+HND], rax
    mov  ecx, 0x200000
    call 0x4d53a0
    test rax, rax
    je   L_cl
    mov  r14, rax
    mov  rcx, rbx
    mov  rdx, r14
    mov  r8d, 0x200000
    lea  r9, [rsp+0x38]
    mov  qword ptr [rsp+0x20], 0
    call QWORD PTR [0x5f6100]
    movsxd r15, dword ptr [rsp+0x38]
    test r15, r15
    jle  L_close
    mov  r12, 0
P2_loop:
    call FIND_ENM
    test rax, rax
    jz   P2_done
    mov  r12, rax
    mov  r13, r12
    inc  r13
    mov  rcx, 1
P2_scan:
    cmp  r13, r15
    jae  P2_done
    mov  dl, [r14+r13]
    cmp  dl, 0x27
    jne  P2_nb
    inc  r13
P2_str:
    cmp  r13, r15
    jae  P2_done
    mov  dl, [r14+r13]
    cmp  dl, 0x27
    je   P2_stre
    inc  r13
    jmp  P2_str
P2_stre:
    inc  r13
    jmp  P2_scan
P2_nb:
    cmp  dl, 0x7b
    jne  P2_nb2
    inc  rcx
    jmp  P2_next
P2_nb2:
    cmp  dl, 0x7d
    jne  P2_next
    dec  rcx
    test rcx, rcx
    jz   P2_del
    jmp  P2_next
P2_next:
    inc  r13
    jmp  P2_scan
P2_del:
    test r12, r12
    je   P2_nprec
    cmp  byte ptr [r14+r12-1], 0x2c
    jne  P2_nprec
    dec  r12
    jmp  P2_domove
P2_nprec:
    lea  rax, [r13+1]
    cmp  rax, r15
    jae  P2_domove
    cmp  byte ptr [r14+rax], 0x2c
    jne  P2_domove
    inc  r13
P2_domove:
    mov  rdx, r13
    inc  rdx
    mov  r8, r15
    sub  r8, rdx
    jle  P2_shr
    mov  rcx, r14
    add  rcx, r12
    mov  rdx, r14
    add  rdx, r13
    inc  rdx
    cmp  r8, r15
    ja   L_close
    call QWORD PTR [0x5f6338]
P2_shr:
    mov  rax, r13
    inc  rax
    sub  rax, r12
    sub  r15, rax
    jmp  P2_loop
P2_done:
    mov  r12, 0
P3_loop:
    call FIND_TAG
    test rax, rax
    jz   P3_done
    mov  r12, rax
    lea  r13, [rax+15]
    mov  rcx, 1
P3_scan:
    cmp  r13, r15
    jae  P3_done
    mov  dl, [r14+r13]
    cmp  dl, 0x27
    jne  P3_nb
    inc  r13
P3_str:
    cmp  r13, r15
    jae  P3_done
    mov  dl, [r14+r13]
    cmp  dl, 0x27
    je   P3_stre
    inc  r13
    jmp  P3_str
P3_stre:
    inc  r13
    jmp  P3_scan
P3_nb:
    cmp  dl, 0x5b
    je   P3_up
    cmp  dl, 0x7b
    je   P3_up
    cmp  dl, 0x5d
    je   P3_dn
    cmp  dl, 0x7d
    je   P3_dn
    jmp  P3_next
P3_up:
    inc  rcx
    jmp  P3_next
P3_dn:
    dec  rcx
    test rcx, rcx
    jz   P3_close
    jmp  P3_next
P3_next:
    inc  r13
    jmp  P3_scan
P3_close:
    cmp  r13, r15
    jae  P3_done
    cmp  byte ptr [r14+r13+1], 0x7d
    jne  P3_next2
    mov  rcx, r14
    add  rcx, r12
    mov  rdx, r14
    lea  rax, [r12+15]
    add  rdx, rax
    mov  r8, r13
    sub  r8, rax
    jle  P3_skip
    cmp  r8, r15
    ja   L_close
    call QWORD PTR [0x5f6338]
P3_skip:
    mov  rcx, r14
    lea  rax, [r13-15]
    add  rcx, rax
    mov  rdx, r14
    lea  rax, [r13+2]
    add  rdx, rax
    mov  r8, r15
    sub  r8, rax
    jle  P3_shr
    cmp  r8, r15
    ja   L_close
    call QWORD PTR [0x5f6338]
P3_shr:
    sub  r15, 17
    jmp  P3_loop
P3_next2:
    inc  r13
    jmp  P3_scan
P3_done:

    # --- PASS 1: "type:'tags'" -> "type:'multi'" (right to left, +1B) ---
    mov  r12, r15
P1_find:
    test r12, r12
    jz   L_rewrite
    dec  r12
    lea  rax, [r14+r12]
    lea  rsi, [rip+FTAGS]
    xor  r13, r13
P1_cmp:
    mov  dl, [rax+r13]
    cmp  dl, [rsi+r13]
    jne  P1_find
    inc  r13
    cmp  r13, 11
    jb   P1_cmp
    mov  rcx, r15
P1_sh:
    cmp  rcx, r12
    jbe  P1_shd
    mov  al, [r14+rcx-1]
    mov  [r14+rcx], al
    dec  rcx
    jmp  P1_sh
P1_shd:
    lea  rsi, [rip+FMULTI]
    lea  rax, [r14+r12]
    xor  r13, r13
P1_ins:
    mov  dl, [rsi+r13]
    mov  [rax+r13], dl
    inc  r13
    cmp  r13, 12
    jb   P1_ins
    inc  r15
    cmp  r12, 12
    jb   L_rewrite
    sub  r12, 12
    jmp  P1_find
    jmp  L_rewrite

# ================= REWRITE/FINALIZE (as-is cmr6b) =================
L_rewrite:
    cmp  qword ptr [rip+HND], 0
    je   L_rw1
    mov  rcx, qword ptr [rip+HND]
    mov  qword ptr [rip+HND], 0
    call QWORD PTR [0x5f5f68]
L_rw1:
    mov  rcx, [rsp+0x30]
    mov  edx, 0x40000000
    xor  r8d, r8d
    xor  r9d, r9d
    mov  dword ptr [rsp+0x20], 2
    mov  qword ptr [rsp+0x28], 0
    call QWORD PTR [0x5f5f78]
    cmp  rax, -1
    je   L_free
    mov  rbx, rax
    mov  rcx, rbx
    mov  rdx, r14
    mov  r8, r15
    lea  r9, [rsp+0x38]
    mov  qword ptr [rsp+0x20], 0
    call QWORD PTR [0x5f6188]
    mov  rcx, rbx
    call QWORD PTR [0x5f5f68]
    jmp  L_free
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
    call QWORD PTR [0x5f6290]
    jmp  0x4b7a1c
L_cl:
    mov  rcx, qword ptr [rip+HND]
    test rcx, rcx
    jne  L_cl2
    mov  rcx, rbx
L_cl2:
    call QWORD PTR [0x5f5f68]
    jmp  L_orig

# ============ FIND_M: rsi=marker, rcx=mlen; r12=start,r15=size,r14=buf -> rax=pos|0 ============
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

# ============ CMR helpers (as-is) ============
FIND_ENM:
    xor  rax, rax
FE_l:
    cmp  r12, r15
    jae  FE_done
    lea  rdi, [r14+r12]
    lea  rsi, [rip+FENM]
    xor  r13, r13
FE_c:
    mov  dl, [rdi+r13]
    cmp  dl, [rsi+r13]
    jne  FE_n
    inc  r13
    cmp  r13, 16
    jb   FE_c
    mov  rax, r12
    ret
FE_n:
    inc  r12
    jmp  FE_l
FE_done:
    ret
FIND_TAG:
    xor  rax, rax
FG_l:
    cmp  r12, r15
    jae  FG_done
    lea  rdi, [r14+r12]
    lea  rsi, [rip+FTAGN]
    xor  r13, r13
FG_c:
    mov  dl, [rdi+r13]
    cmp  dl, [rsi+r13]
    jne  FG_n
    inc  r13
    cmp  r13, 15
    jb   FG_c
    mov  rax, r12
    ret
FG_n:
    inc  r12
    jmp  FG_l
FG_done:
    ret

    .align 16
FJG:    .ascii "roteros.jg\0"
FCMR:   .ascii "cmr.jg\0"
M_PTO:  .ascii "{name:'Ping To'\0"
M_IF:   .ascii "name:'Interface'\0"
M_ARP:  .ascii "{name:'ARP Ping'\0"
M_FIELD:.ascii "{name:'\0"
M_TT:   .ascii "{name:'Traceroute To'\0"
M_U8:   .ascii "id:'u8'\0"
M_UDP:  .ascii "{name:'udp'\0"
NODE_IFP:  .ascii "{name:'Interface',type:'opt',c:[{type:'enm',id:'ua',values:{type:'dynamic',path:[ 20,0 ]}}]},"
NODE_VRFP: .ascii "{name:'VRF',type:'opt',c:[{type:'enm',id:'u10',values:{type:'dynamic',path:[ 20,101 ]}}]},"
NODE_IFT:  .ascii "{name:'Interface',type:'opt',c:[{type:'enm',id:'u12',values:{type:'dynamic',path:[ 20,0 ]}}]},"
NODE_VRFT: .ascii "{name:'VRF',type:'opt',c:[{type:'enm',id:'u11',values:{type:'dynamic',path:[ 20,101 ]}}]},"
FTAGS:  .ascii "type:'tags'"
FMULTI: .ascii "type:'multi'"
FENM:   .ascii "{type:'enmbools'"
FTAGN:  .ascii "{type:'tag',c:["
    .align 16
HND:
    .quad 0
