# range_marker_gate_p10.s - Range pre-check cave @0x65A700 (65B), jgmem2d build
# Checks for the "bignumberrange..." marker (0x65A750, 28B) in the jg image:
#   NOT found -> reset the FREADFN slot (Range off) -> return (skip Range);
#   FOUND     -> the Range marker (0x659457) -> continue in the unified cave (0x6590DB).
# Restored byte-exact from a hex dump (verified).
.intel_syntax noprefix
.global _start
_start:
    xor    r12, r12
    movabs rsi, 0x65A750          # the "bignumberrange..." marker in statics
    mov    rcx, 0x1C              # 28B marker length
    call   0x65929C               # findmarker (shared function)
    test   rax, rax
    jne    L_found                # FOUND -> continue
    # --- NOT found: Range off ---
    mov    qword ptr [0x659520], 0   # reset the FREADFN slot (disable Range)
    jmp    0x65915A               # 7.24 FIX: through the CloseHandle block (else a share-lock!)
    # --- FOUND: continue Range ---
L_found:
    xor    r12, r12
    movabs rsi, 0x659457          # the Range marker (in jg)
    jmp    0x6590DB               # continue in the unified cave

