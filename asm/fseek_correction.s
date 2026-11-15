# fseek_correction.s - the multi-level FSEEKFN correction for 3 insertions
# Replaces the SEEK_SET path (0x659369) through a trampoline
# Slots: 0x6598F8=I1_pos, 0x6598FC=I2_pos, 0x659900=R_pos (all in
# ORIGINAL coordinates)
.intel_syntax noprefix
.code64
.globl piecewise
piecewise:
    # rax = offset (32-bit, zero-extended) - as in the original
    mov  eax, edx
    
    # PIECEWISE: from the upper zone down
    cmp  rax, [0x659900]         # R_pos (Range in the original)
    jae  PW_402
    cmp  rax, [0x6598FC]         # I2_pos (the TR injection in the original)
    jae  PW_365
    cmp  rax, [0x6598F8]         # I1_pos (the Ping injection in the original)
    jae  PW_183
    jmp  PW_store                 # < I1 -> no correction
    
PW_402:
    add  rax, 402                 # I1(183) + I2(182) + Range(37)
    jmp  PW_store
PW_365:
    add  rax, 365                 # I1(183) + I2(182)
    jmp  PW_store
PW_183:
    add  rax, 183                 # I1 only
PW_store:
    mov  [0x6594F8], rax          # ROS_POS = the corrected position
    jmp  0x6593AA                 # -> bounds check (shared with the original)
