# ntp_display.s - the jg type-masking cave for RouterOS 7.25+.
# Position: 0x658100 (under the retarget of the type-parser hook
# 0x4A28AA - the builder does the e9 patch). Code up to 0x658160.
#
# WHAT IT DOES: RouterOS 7.25+ sends fields of new types (bigfixedpoint -
# the NTP fields Time/Offset/Delay/..., bignumberrange - Range fields);
# the stock client type parser does not know them and skips them ->
# dialogs without data. The cave substitutes the type names in the jg
# image with ones known to the client:
#   'bigfixedpoint' -> 'bignumber'   (a numeric field with scale/postfix);
#   'bignumberrange'-> 'numberrange' (a range);
# after the substitution the tails return into the parser - the fields
# are built the stock way.
#
# CANON: the tails returning into the parser are absolute symbols
# (jmp tails to three continuation points); the string masking is a
# byte-by-byte overwrite.
.intel_syntax noprefix
.code64

.set EXT_A, 0x4A1DE4     # continuation after the "bigf" branch
.set EXT_B, 0x4A182B     # continuation after the "bign" branch
.set EXT_OUT, 0x4A292F   # final tail (past the masking)

.globl ntp_display_cave
ntp_display_cave:
    cmp  DWORD PTR [r12+0x10], 1     # 41 83 7c 24 10 01
    # near jcc form (6B, as in the reference; gas itself emits a 2B short!):
    .byte 0x0F, 0x85                 # jne near L_out
    .long L_out - . - 4
    mov  rax, QWORD PTR [r12+0x18]   # 49 8b 44 24 18
    test rax, rax                    # 48 85 c0
    .byte 0x0F, 0x84                 # je near L_out (6B)
    .long L_out - . - 4
    cmp  DWORD PTR [rax], 0x66676962 # 81 38 …          "bigf"
    jne  L_second                    # 75 19
    mov  DWORD PTR [rax], 0x6E676962 # c7 00 …          "bign"
    mov  DWORD PTR [rax+4], 0x65626D75 # c7 40 04 …     "umbe"
    mov  DWORD PTR [rax+8], 0x72     # c7 40 08 …       "r\0\0\0" → "bignumber"
    jmp  EXT_A                       # e9 …
L_second:
    cmp  DWORD PTR [rax], 0x6E676962 # 81 38 …          "bign"
    jne  L_out                       # 75 19
    mov  DWORD PTR [rax], 0x626D756E # c7 00 …          "numb"
    mov  DWORD PTR [rax+4], 0x61727265 # c7 40 04 …     "erra"
    mov  DWORD PTR [rax+8], 0x0065676E # c7 40 08 …     "nge\0" → "numberrange"
    jmp  EXT_B                       # e9 …
L_out:
    jmp  EXT_OUT                     # e9 …
