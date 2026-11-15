# range_marker_gate.s - the Range pre-check cave @0x65A700 (65B), the
# jgmem2d build.
# Checks whether the "bignumberrange..." marker (0x65A750, 28B) is present
# in the jg image:
#   NOT found -> reset the FREADFN slot (Range off) -> return (skip
#   Range);
#   FOUND     -> the Range marker (0x659457) -> continue in the jgmem
#   cave (0x6590DB).
# Restored from a hex dump byte-for-byte (verified).
.intel_syntax noprefix
.global _start
_start:
    xor    r12, r12
    movabs rsi, 0x65A750          # the "bignumberrange..." marker in statics
    mov    rcx, 0x1C              # 28B marker length
    call   0x65929C               # findmarker (a shared function)
    test   rax, rax
    jne    L_found                # FOUND -> continue
    # --- NOT found: Range off ---
    mov    qword ptr [0x659520], 0   # reset the FREADFN slot (disable Range)
    jmp    0x659187               # return (skip Range)
    # --- FOUND: continue Range ---
L_found:
    xor    r12, r12
    movabs rsi, 0x659457          # the Range marker (in the jg)
    jmp    0x6590DB               # continue in the jgmem cave
