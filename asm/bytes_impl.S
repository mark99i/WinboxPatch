# bytes_impl.S - 'bytes' (u32) field converter blob for patch set v4.
#
# RouterOS 7.24+ stopped sending the 'bytes' converter in the WinBox
# protocol, so WinBox 3.43 shows bytes fields (e.g. MTU, IPv4 Fragment
# Threshold) red and silently discards every edit. This blob implements the
# missing parser: it accepts the WinBox4 grammar (KiB/MiB/GiB/TiB binary
# suffixes, k/M/G/T decimal, bare 'B', empty string = 0) and returns the
# value in EDX with the success flag in AL, clamped to 0xFFFFFFFF. The tail
# at .org 0x400 is the value-commit stub that stores the parsed value back
# into the record.
#
# Source kept verbatim from ANALYSIS-FRAG.md section G.1 (codename "frag4").
# Loaded at VA 0x657400 inside .text of the patched exe; build-patched-v4.py
# redirects the converter's empty parse slot (vt+0x28, VA 0x502050) and
# commit slot (vt+0x20, VA 0x501FF0) to this blob.
# Rebuild with: python build-blobs.py  (as --64 + ld -Ttext=0x657400 +
# objcopy -O binary; verified against the reference SHA-256).
.intel_syntax noprefix
.code64
# FRAG4 (минимальная форма): НОЛЬ клеток/глобалей — ядро возвращает пару (AL=1/0, EDX=u32).
# Контракт стаба1 (0x502050): вызыватели читают ТОЛЬКО AL (проверено: 0x470d8a/0x470f9a/
# 0x473c8a после call rbx не читают rdx) — EDX свободен как канал значения.

.globl _start
.text
_start:
    push rbx
    push rsi
    push r12
    push r13
    push r14
    push r15
    xor  eax, eax
    xor  r15d, r15d            # saw-digit
    test rdx, rdx
    je   L_fail
    mov  rsi, QWORD PTR [rdx]  # inner
    mov  r13, 0x7fffffffffff   # дефенс: inner обязан выглядеть указателем
    cmp  rsi, r13
    ja   L_fail
    cmp  rsi, 0x10000
    jb   L_fail
    add  rsi, 4                # chars (asciiz)

L_sp1:                          # ведущие пробелы
    movzx ebx, BYTE PTR [rsi]
    cmp  bl, ' '
    jne  L_pl
    inc  rsi
    jmp  L_sp1
L_pl:
    cmp  bl, '+'
    jne  L_num
    inc  rsi
L_num:
    xor  r8d, r8d               # int acc (u64)
    xor  r12d, r12d             # big-flag
    xor  r9d, r9d               # frac acc (безусловный сброс — регистры не сохраняются между вызовами!)
    xor  r10d, r10d             # frac digit count
    mov  r13, 0xffffffff        # u32-максимум (переиспользуется в L_tot)
L_int:
    movzx ebx, BYTE PTR [rsi]
    sub  bl, '0'
    cmp  bl, 9
    ja   L_intd
    mov  r15d, 1
    test r12d, r12d
    jne  L_iskip
    cmp  r8, r13                # int уже больше u32-цели — дальше не копим
    ja   L_ibig
    lea  r8, [r8 + r8*4]
    add  r8, r8                 # r8*10
    movzx ebx, BYTE PTR [rsi]
    sub  bl, '0'
    movzx ebx, bl
    add  r8, rbx
L_inext:
    inc  rsi
    jmp  L_int
L_ibig:
    mov  r12d, 1
L_iskip:
    inc  rsi
    jmp  L_int
L_intd:
    movzx ebx, BYTE PTR [rsi]
    cmp  bl, '.'
    jne  L_nofrac
    inc  rsi
L_fr:
    movzx ebx, BYTE PTR [rsi]
    sub  bl, '0'
    cmp  bl, 9
    ja   L_frd
    mov  r15d, 1
    cmp  r10d, 9                # дальше 9 знаков точность не копим
    jae  L_fskip
    lea  r9, [r9 + r9*4]
    add  r9, r9
    movzx ebx, BYTE PTR [rsi]
    sub  bl, '0'
    movzx ebx, bl
    add  r9, rbx
    inc  r10d
L_fskip:
    inc  rsi
    jmp  L_fr
L_frd:
    nop
L_nofrac:                       # пробелы перед суффиксом («4096.0 MiB»)
    movzx ebx, BYTE PTR [rsi]
    cmp  bl, ' '
    jne  L_suf
    inc  rsi
    jmp  L_nofrac
L_suf:
    test r15d, r15d
    jne  L_have
    test bl, bl
    jne  L_fail                 # мусор без цифр
    jmp  L_ok0                  # пусто -> валидно 0 (семантика оригинала)
L_have:
    mov  r11d, 0                # idx суффикса
    mov  r14d, 0                # binary flag
    test bl, bl
    je   L_calc                 # голое число, mult=1
    movzx eax, bl
    and  eax, 0xdf              # uppercase
    cmp  al, 'K'
    je   L_k
    cmp  al, 'M'
    je   L_m
    cmp  al, 'G'
    je   L_g
    cmp  al, 'T'
    je   L_t
    cmp  al, 'B'
    je   L_bareB
    jmp  L_fail
L_k:    mov r11d, 1
        jmp L_s2
L_m:    mov r11d, 2
        jmp L_s2
L_g:    mov r11d, 3
        jmp L_s2
L_t:    mov r11d, 4
        jmp L_s2
L_bareB:                        # 'B' = байты, mult=1
    inc  rsi
    jmp  L_endchk
L_s2:
    inc  rsi
    movzx ebx, BYTE PTR [rsi]
    test bl, bl
    je   L_calc                 # 'K' без продолжения -> десятичный
    movzx eax, bl
    and  eax, 0xdf
    cmp  al, 'I'
    jne  L_s2b
    mov  r14d, 1                # бинарный
    inc  rsi
    movzx ebx, BYTE PTR [rsi]
    test bl, bl
    je   L_calc                 # 'Ki' -> бинарный
    movzx eax, bl
    and  eax, 0xdf
L_s2b:
    cmp  al, 'B'
    jne  L_fail                 # 'KB' (десятичный) / 'KiB' (бинарный)
    inc  rsi
    jmp  L_endchk
L_endchk:                       # хвостовые пробелы, затем строгий NUL
    movzx ebx, BYTE PTR [rsi]
    cmp  bl, ' '
    jne  L_endc
    inc  rsi
    jmp  L_endchk
L_endc:
    test bl, bl
    jne  L_fail
L_calc:                         # mult в r11 из idx/бинарности
    test r11d, r11d
    je   L_setone              # bare-число или 'B': mult = 1
    test r14d, r14d
    jne  L_bin
    mov  rcx, r11
    mov  r11d, 1
L_dl:
    imul r11, r11, 1000
    dec  rcx
    jne  L_dl
    jmp  L_m1
L_setone:
    mov  r11d, 1
    jmp  L_m1
L_bin:
    mov  rcx, r11
    shl  rcx, 3
    lea  rcx, [rcx + r11*2]     # idx*10
    mov  r11d, 1
L_sl:
    shl  r11, 1
    dec  rcx
    jne  L_sl
L_m1:                           # value = int*mult + frac*mult/10^n
    test r12d, r12d
    jne  L_clamp
    mov  rax, r8
    mul  r11
    test rdx, rdx
    jne  L_clamp                # 64-бит переполнение -> заведомо больше цели
    mov  r14, rax
    test r10d, r10d
    je   L_tot
    mov  rax, r9
    mul  r11
    test rdx, rdx
    jne  L_clamp
    mov  rcx, r10
    mov  r13, 10
L_dv:
    xor  edx, edx
    div  r13
    dec  rcx
    jne  L_dv
    add  r14, rax
    jc   L_clamp
L_tot:
    mov  r13d, 0xffffffff       # восстановить u32-максимум (r13 затёрт делителем 10 в L_dv)
    mov  rax, r14
    cmp  rax, r13
    jbe  L_okv
L_clamp:
    mov  eax, 0xffffffff
    jmp  L_okv
L_okv:
    mov  edx, eax              # EDX = u32-значение (канал для стаба3)
    mov  eax, 1
    jmp  L_out
L_ok0:
    xor  edx, edx              # пусто = валидно 0 (семантика оригинала)
    mov  eax, 1
    jmp  L_out
L_fail:
    xor  eax, eax
L_out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rsi
    pop  rbx
    ret

# STAB3 (value-commit): замена 0x501ff0 — слот vt+0x20 bytes-конвертера
# (класс 0x58f508). Штатный путь (единый для всех editor-полей, widget 0x5a63d8):
#   OK → 0x4976c3 → [widget vt+0x40]=0x470f18 → [widget vt+0xc8]=0x5207c0
#   → [конвертер vt+0x20](rcx=conv, rdx=[widget+0x18]=&store[varnum]-холдер, r8=str)
# У брата 'number' (0x58f0e8) слот = 0x46b17a (mov rcx,r8; jmp 0x46b0f0 — u32 в [rdx]);
# у interval — 0x46f518/0x468044 ([r12]=eax). У bytes — ПУСТОЙ (ret) -> правка не
# доставлялась -> поле откатывалось -> set нёс open-value.
# Стаб3: тонкая обёртка над ядром 0x657400 (стаб1): str из r8, u32 в [rdx].
# =============================================================================
.org 0x400                     # стаб3 ровно на 0x657800 (0x657400+0x400)
.globl stub3
stub3:
    push rbx                   # сохранить
    mov  rbx, rdx              # rbx = &out (холдер = &store[varnum])
    mov  rdx, r8               # rdx = str-объект (контракт ядра)
    call _start                # ядро: AL=1/0 + EDX=u32
    test al, al
    je   L3_out
    mov  DWORD PTR [rbx], edx  # холдер/store[varnum] = значение правки
    mov  eax, 1
L3_out:
    pop  rbx
    ret
