# shield_points.s - the release-point dedup caves x3 (class 2: double
# free).
# Position: 0x658500, entries 0x658500/0x658590/0x658620 (step 0x90),
# code up to 0x6586A0. Embedded under the three release points of the
# dialog object builder (0x496F69/0x497013/0x497152 - the builder does
# the e8-retargets).
#
# WHAT IT DOES: the Dashboard element builder frees one object at three
# points without ownership tracking - a repeat pass with the same object
# = a double free (the Win10 heap detects it -> 0xc0000374). Each point
# cave:
#  - looks the target ([rcx]) up in the ring-8 of recent targets;
#  - on a match compares the STAMP (the legit-free counter at push
#    time): delta<=16 = an instant repeat burst = a true double free ->
#    skip; delta>16 = the block was reallocated by the heap (a mass of
#    other frees passed between the free and the re-free - the window
#    open/close pattern) -> a LEGIT free runs (leak protection on
#    window cycles);
#  - a free target -> push into the ring + stamp + the stock free
#    through the trampoline.
#
# STATICS (zeros in the base, runtime-filled; the map for dumps):
#  RIDX 0x658738, RING 0x658740 (8x8B), STAMPS 0x658780 (8x4B
#  lo-dword), counters 0x6587A0-0x6587F8: C_PASS 0x6587D8, C_DUP_TRUE
#  0x6587E0, C_DUP_STALE 0x6587E8, C_UNIQ 0x6587F0.
#  NOTE (telemetry-only wart): stamp slots 4-7 overlap the diagnostic
#  counters at the start of 0x6587A0 - their readings get distorted;
#  the critical delta-dedup counters are outside the overlap.
#
# CANON: the stamp instructions carry REX prefixes (47 8b 4c 13 40 /
# 45 89 4c 13 40) - verify against the gas reference (manual REX
# encoding = mines); external targets are absolute symbols; rip
# references are by labels through .org.
.intel_syntax noprefix
.code64

.set SENT, 0x53D268
.set FREE_TRAMP, 0x4D5408

.globl points
points:
    # ===== cave 1 (e8-retarget from 0x496F69) =====
    mov  rax, QWORD PTR [rcx]           # 48 8b 01       target
    cmp  rax, SENT                      # 48 3d …        sentinel?
    je   L1_dup
    lea  r11, [rip+RING]                # 4c 8d 1d …
    mov  r10d, 56                       # 41 ba 38 …     slot offset 7*8
L1_scan:
    cmp  QWORD PTR [r11+r10*1], rax     # 4b 39 04 13
    je   L1_match
    sub  r10d, 8                        # 41 83 ea 08
    jns  L1_scan
    jmp  L1_push                        # not found -> push+free
L1_match:                               # target in the ring -> delta check
    mov  edx, DWORD PTR [rip+C_PASS]    # clock
    mov  r9d, DWORD PTR [r11+r10*1+0x40] # 47 8b 4c 13 40  slot stamp
    sub  edx, r9d                       # 44 29 ca       Δ
    cmp  edx, 16                        # burst window
    jbe  L1_dup                         # delta<=16 -> a true double-free
    inc  DWORD PTR [rip+C_DUP_STALE]    # delta>16 -> realloc'd: a former false-skip
L1_push:
    lea  r11, [rip+RIDX]
    mov  edx, DWORD PTR [r11]           # slot = RIDX&7 (before the inc)
    inc  DWORD PTR [r11]
    and  edx, 7
    shl  edx, 3
    lea  r11, [rip+RING]
    mov  QWORD PTR [r11+rdx*1], rax     # push the target
    mov  r9d, DWORD PTR [rip+C_PASS]
    mov  DWORD PTR [r11+rdx*1+0x40], r9d # 45 89 4c 13 40  stamp
    inc  DWORD PTR [rip+C_UNIQ]
    mov  rcx, rax                       # rcx = target
    jmp  FREE_TRAMP                     # the real free (tail)
L1_dup:
    inc  DWORD PTR [rip+C_DUP_TRUE]
    ret

    .org 0x90
    # ===== cave 2 (e8-retarget from 0x497013) =====
    mov  rax, QWORD PTR [rcx]
    cmp  rax, SENT
    je   L2_dup
    lea  r11, [rip+RING]
    mov  r10d, 56
L2_scan:
    cmp  QWORD PTR [r11+r10*1], rax
    je   L2_match
    sub  r10d, 8
    jns  L2_scan
    jmp  L2_push
L2_match:
    mov  edx, DWORD PTR [rip+C_PASS]
    mov  r9d, DWORD PTR [r11+r10*1+0x40]
    sub  edx, r9d
    cmp  edx, 16
    jbe  L2_dup
    inc  DWORD PTR [rip+C_DUP_STALE]
L2_push:
    lea  r11, [rip+RIDX]
    mov  edx, DWORD PTR [r11]
    inc  DWORD PTR [r11]
    and  edx, 7
    shl  edx, 3
    lea  r11, [rip+RING]
    mov  QWORD PTR [r11+rdx*1], rax
    mov  r9d, DWORD PTR [rip+C_PASS]
    mov  DWORD PTR [r11+rdx*1+0x40], r9d
    inc  DWORD PTR [rip+C_UNIQ]
    mov  rcx, rax
    jmp  FREE_TRAMP
L2_dup:
    inc  DWORD PTR [rip+C_DUP_TRUE]
    ret

    .org 0x120
    # ===== cave 3 (e8-retarget from 0x497152) =====
    mov  rax, QWORD PTR [rcx]
    cmp  rax, SENT
    je   L3_dup
    lea  r11, [rip+RING]
    mov  r10d, 56
L3_scan:
    cmp  QWORD PTR [r11+r10*1], rax
    je   L3_match
    sub  r10d, 8
    jns  L3_scan
    jmp  L3_push
L3_match:
    mov  edx, DWORD PTR [rip+C_PASS]
    mov  r9d, DWORD PTR [r11+r10*1+0x40]
    sub  edx, r9d
    cmp  edx, 16
    jbe  L3_dup
    inc  DWORD PTR [rip+C_DUP_STALE]
L3_push:
    lea  r11, [rip+RIDX]
    mov  edx, DWORD PTR [r11]
    inc  DWORD PTR [r11]
    and  edx, 7
    shl  edx, 3
    lea  r11, [rip+RING]
    mov  QWORD PTR [r11+rdx*1], rax
    mov  r9d, DWORD PTR [rip+C_PASS]
    mov  DWORD PTR [r11+rdx*1+0x40], r9d
    inc  DWORD PTR [rip+C_UNIQ]
    mov  rcx, rax
    jmp  FREE_TRAMP
L3_dup:
    inc  DWORD PTR [rip+C_DUP_TRUE]
    ret

# --- statics (labels at exact VAs via .org; zeros in the base) ---
    .org 0x238
RIDX: .long 0
    .org 0x240
RING: .quad 0
      .quad 0
      .quad 0
      .quad 0
      .quad 0
      .quad 0
      .quad 0
      .quad 0
    .org 0x280
STAMPS: .quad 0
        .quad 0
        .quad 0
        .quad 0
        .quad 0
        .quad 0
        .quad 0
        .quad 0
# NOTE - the documented 12e wart: STAMPS (0x658780+0x40) COVERS
# C_SENT..C_ALIGN (0x6587A0-0x6587B8) - stamp slots 4-7 write OVER the
# diagnostic counters (a single assert range in the gen zone hid
# this!). The CRITICAL ones (C_PASS 0x6587D8, C_DUP_*/C_UNIQ 0x6587E0+)
# are OUTSIDE the overlap. In the .s: C_SENT..C_ALIGN = ALIASES to the
# stamp slots (the same zero bytes):
C_SENT  = STAMPS + 0x20    # 0x6587A0 (= slot 4)
C_NULL  = STAMPS + 0x28    # 0x6587A8 (= slot 5)
C_LOW   = STAMPS + 0x30    # 0x6587B0 (= slot 6)
C_ALIGN = STAMPS + 0x38    # 0x6587B8 (= slot 7)
    .org 0x2C0
C_ARENA: .long 0
    .org 0x2C8
C_FEEE:  .long 0
    .org 0x2D0
C_BADF:  .long 0
    .org 0x2D8
C_PASS:  .long 0
    .org 0x2E0
C_DUP_TRUE: .long 0
    .org 0x2E8
C_DUP_STALE: .long 0
    .org 0x2F0
C_UNIQ: .long 0
