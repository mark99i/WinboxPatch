# ============================================================================
# esrc_conv.s - v116-esrc: a vtable-swap of the u64 type slot to the ESR grouper
# ============================================================================
# DESIGN (the vtable-swap interpretation of the ESR author):
#   Slot 0x596CE0 (.rdata, file 0x1950E0) = +0x18 of the type table 0x596CC8
#   (the plain-u64 type). WAS: -> thunk 0x46BFCC; NOW: -> esrc_conv @0x65B500.
#   = ONE pointer swap (8B) in .rdata; .text stays 100% VIRGIN.
#   The old thunk+converter (0x46BFCC/0x46BEFC) become dead code
#   (untouched - the only caller of the converter was the thunk, the only
#   caller of the thunk is this slot; verified by xref scans).
#
# CONTRACT (a thunk 0x46BFCC replacement; called by the dispatcher 0x472D62 as
#   [box-vt+0x18](rcx=str_obj, rdx=box, r8=&value)):
#     1. value = [r8]                     (thunk: mov rdx,[r8])
#     2. r12 = rcx (str_obj)              (thunk: mov r12,rcx)
#     3. ESR grouping (the NEW-hex core from PATCHES-v99-to-v104.md:
#        a div-10 loop, groups of 3, a SPACE 0x20 separator, CRT-free,
#        no ceiling - any u64)
#     4. SIGN - AS THE ORIGINAL 0x46BEFC (the 0x46BEFC prologue):
#        test value,value; jns -> unsigned; js -> neg + the '-' prefix
#        (the original: lea r8,""/"-" + entry-A prepended '-' to the string).
#        WARNING (documented): values with the sign bit set
#        (>=2^63) are treated as negative - EXACTLY like the stock
#        0x46BEFC and v99-ESR(1). Practical RO counters (< 2^63)
#        are always positive. The author's simulation "2^64-1 -> 18 446 ..."
#        applies to the isolated core (the core really has no ceiling);
#        combined with the stock sign 2^64-1 -> "-1" (as the original).
#     5. str-assign: 0x4CF2DE(r12, string); return r12 (thunk: rax=r12).
#
# SIMULATION (stock compatibility for <=3 groups - the "%s%u %3.3u %3.3u" formats):
#   0→«0»; 999→«999»; 1176→«1 176»; 999999999→«999 999 999»;
#   8589934747->"8 589 934 747" (4 groups); 1207910912244->"1 207 910 912 244";
#   -1234567890->"-1 234 567 890" (the sign via the stock mechanics).
#
# BUFFER: base rsp+0x28, the core writes downward from base+0x1B; the max =
#   1(sign)+19(int64 digits)+6(spaces)+1(NUL) = 27 <= 0x1C - inside the frame
#   (sub 0x58) with room to spare.
# ABI: entry rsp==8 (a call from the dispatcher); push r13/r12 (callee-saved);
#   sub 0x58 -> rsp==0 on the 0x4CF2DE call (alignment OK); clobbers only
#   volatile (rax/rcx/rdx/r9/r10/r11); r8 is read, never touched.
# External rel32: call 0x4CF2DE (a .set symbol - ld resolves it into bytes,
#   verified empirically by esra3/esrb).
# ============================================================================

.intel_syntax noprefix
.code64

.set STR_ASSIGN, 0x4CF2DE         # string-assign(str_obj, c_str)

    .text
    .globl esrc_conv
# --- CONVERTER @0x65B500 (the thunk 0x46BFCC replacement in slot 0x596CE0) ----------
esrc_conv:
    push r13
    push r12
    sub  rsp, 0x58                 # frame + call-site alignment
    mov  r12, rcx                  # str_obj (thunk: mov r12,rcx)
    mov  r9, qword ptr [r8]        # value (thunk: mov rdx,[r8])

    # --- sign (the 0x46BEFC prologue: test rdx,rdx; jns/neg + prefix) -----------
    xor  r10d, r10d                # r10 = the sign flag
    test r9, r9
    jns  1f
    neg  r9                        # |value| for the core
    mov  r10d, 1                   # mark as negative

    # --- the ESR core (NEW-hex; imm32 instead of imm64 - the same semantics) ----------
1:  lea  r13, [rsp+0x28]           # the buffer base
    add  r13, 0x1B                 # the end of the 27-byte digit zone
    mov  byte ptr [r13], 0         # the NUL terminator
    mov  r11d, 4                   # group counter: the first dec -> 3 digits
    mov  rax, r9                   # the value (BEFORE r9 is clobbered by the divisor!)
    mov  r9d, 10
2:  dec  r11
    jne  3f                        # not the group end -> just a digit
    mov  r11d, 3                   # reload the counter
    dec  r13
    mov  byte ptr [r13], 0x20      # the SPACE separator (as ESR)
3:  xor  edx, edx
    div  r9                        # rax=quotient, rdx=digit
    add  rdx, 0x30
    dec  r13
    mov  byte ptr [r13], dl        # a digit, right to left
    test rax, rax
    ja   2b                        # value exhausted? no -> continue

    # --- the minus prefix (entry-A: [r8]=='-' -> prepend to the string) -------
    test r10d, r10d
    jz   4f
    dec  r13
    mov  byte ptr [r13], 0x2D      # '-'

    # --- str-assign + return (the thunk contract: rax = r12) ------------------
4:  mov  rcx, r12
    mov  rdx, r13                  # r13 = the string start
    call STR_ASSIGN
    mov  rax, r12                  # return str_obj (as the thunk)
    add  rsp, 0x58
    pop  r12
    pop  r13
    ret
