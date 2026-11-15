# range_boundary.s - compute R_boundary for piecewise, do NOT touch the
# Range slots
# Trampoline @0x65915A (5B cmpq -> jmp here)
.intel_syntax noprefix
.code64
.globl postrange3
postrange3:
    push rax
    push rcx
    
    # R_boundary = [0x659520] - 365 (the Range pos in the current -> in the
    # original buffer)
    # (we assume I1+I2 both fired - for 7.25/7.26 that is always the case)
    mov  rax, [0x659520]         # the Range INSERT_POS (in the field-shifted buffer)
    sub  rax, 365                 # convert to original coordinates
    mov  [0x659900], rax          # R_boundary for piecewise
    
    # (we do NOT overwrite [0x659520]/[0x659528] - piecewise does not use them)
    
    pop  rcx
    pop  rax
    
    # Restore the replaced instruction: cmpq $0x0, [0x6594D0]
    cmp  qword ptr [0x6594D0], 0
    
    # Return to the je @0x659162
    jmp  0x659162
