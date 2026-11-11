# shield_class1.s - the heap protection cave, class 1 (invalid frees at
# jg load).
# Position: 0x658000 (embedded OVER the existing cave under the release
# hook 0x4cf0da; the code boundary is 0x6580A0 - behind it statics/the
# Win7 helper, the builder truncates the bin).
#
# WHAT IT DOES: intercepts every release call and decides whether to
# reach free:
#  - the 0x53D268 sentinel ("not owned" - the native move-constructor
#    semantics of the client) -> skip;
#  - NULL/low addresses (<0x10000), odd (misaligned) -> skip;
#  - freed/uninitialized memory corruption markers (0xFEEEFEEE/
#    0xBAADF00D) -> skip;
#  - the PARSE-ARENA signature in the hi-dword [rcx-4]: byte0 in
#    {0x80,0x90} and byte1 in {0x06,0x07} (jg-loader chain entries;
#    legit Win10 blocks have byte1=0x00) -> skip;
#  - otherwise -> the stock free through the trampoline.
#
# CANON: external targets are absolute symbols (.set, rel32 right in
# the bytes, no relocations); rip references to statics are by LABELS
# through .org only (otherwise gas gives an absolute [disp32] form with
# a broken target); the arena checks are byte forms (cmp/and r8b imm8 -
# the 32-bit forms are 7B longer and do not match).
.intel_syntax noprefix
.code64

.set SENTINEL,  0x53D268
.set FREE_TRAMP, 0x4D5408

.globl shield_cave
shield_cave:
    mov  rcx, QWORD PTR [rcx]        # 48 8b 09       block from the wrapper object
    mov  eax, SENTINEL               # b8 68 d2 53 00
    cmp  rcx, rax                    # 48 39 c1
    je   L_sent                      # heap sentinel
    test rcx, rcx
    je   L_null                      # NULL
    cmp  rcx, 0x10000
    jb   L_low                       # below the heap
    test cl, 0xf
    jne  L_align                     # misaligned
    # --- arena signature: hi-dword [rcx-4] ---
    # BYTE forms (cmp/and r8b - imm8 without sign
    # extension; the 32-bit forms give an 81 encoding +7B and do NOT match
    # the reference!):
    mov  r8d, DWORD PTR [rcx-0x4]    # 44 8b 41 fc
    shr  r8d, 24                     # byte0 -> low byte
    and  r8b, 0xF0                   # 41 80 e0 f0     high nibble
    cmp  r8b, 0x80                   # 41 80 f8 80     0x80..0x8F
    je   L_a2
    cmp  r8b, 0x90                   # 41 80 f8 90     0x90..0x9F
    je   L_a2
    jmp  L_noflags                   # byte0 miss -> final marker checks
L_a2:
    mov  r8d, DWORD PTR [rcx-0x4]    # re-read
    shr  r8d, 16                     # byte1
    and  r8b, 0xFE                   # 41 80 e0 fe     without the low bit
    cmp  r8b, 0x06                   # 41 80 f8 06     0x06/0x07
    je   L_arena                     # a valid Win10-LFH entry -> skip
L_noflags:
    mov  r8d, DWORD PTR [rcx-0x8]    # lo-dword of the header
    cmp  r8d, 0xFEEEFEEE
    je   L_feee                      # already freed
    cmp  r8d, 0xBAADF00D
    je   L_badf                      # uninit
    # --- clean: legit free ---
    inc  DWORD PTR [rip+C_PASS]      # the delta-dedup clock!
    jmp  FREE_TRAMP                  # tail, zero depth
L_sent:
    inc  DWORD PTR [rip+C_SENT]
    ret
L_null:
    inc  DWORD PTR [rip+C_NULL]
    ret
L_low:
    inc  DWORD PTR [rip+C_LOW]
    ret
L_align:
    inc  DWORD PTR [rip+C_ALIGN]
    ret
L_arena:
    inc  DWORD PTR [rip+C_ARENA]
    ret
L_feee:
    inc  DWORD PTR [rip+C_FEEE]
    ret
L_badf:
    inc  DWORD PTR [rip+C_BADF]
    ret

# --- counter statics (labels at exact VAs via .org; zeros in the base) ---
# rip-relative to a LABEL (not an absolute!) - otherwise gas gives an
# absolute [disp32] form with a broken target (a diff lesson!):
    .org 0x7A0
C_SENT:  .long 0
    .org 0x7A8
C_NULL:  .long 0
    .org 0x7B0
C_LOW:   .long 0
    .org 0x7B8
C_ALIGN: .long 0
    .org 0x7C0
C_ARENA: .long 0
    .org 0x7C8
C_FEEE:  .long 0
    .org 0x7D0
C_BADF:  .long 0
    .org 0x7D8
C_PASS:  .long 0
