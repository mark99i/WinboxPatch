# bigbytes_impl.S - 'bigbytes' (u64) field converter blob for patch set v4.
#
# Same defect as 'bytes' in its 64-bit flavour: RouterOS 7.24+ sends no
# converter for 'bigbytes' fields (e.g. Container -> Shm Size, tmpfs/memory
# limits, disk file size/offset), so they show up red and uneditable. This
# blob implements the missing u64 parser with the WinBox4 grammar
# (KiB/MiB/GiB/TiB binary suffixes, k/M/G/T decimal, bare 'B', empty = 0)
# and returns the value in EDX with the success flag in AL. The tail at
# .org 0x400 is the value-commit stub that stores the parsed value back
# into the record.
#
# Source kept verbatim from ANALYSIS-SHM.md section G.1 (codename "shm2").
# Loaded at VA 0x638500 inside .text of the patched exe; build-patched-v4.py
# redirects the converter's empty parse slot (vt+0x28, VA 0x50BAC0) and
# commit slot (vt+0x20, VA 0x50BA60) to this blob.
# Rebuild with: python build-blobs.py  (as --64 + ld -Ttext=0x638500 +
# objcopy -O binary; verified against the reference SHA-256).
.intel_syntax noprefix
.code64
.set G_WCNT, 0x638400         # qword: счётчик вызовов стаба2 (store-writer) — диагностика round-2
.set G_ARMED, 0x638408        # qword: 1 = G_VAL от непустого распарсенного текста
.set G_CNT, 0x638410          # qword: счётчик вызовов стаба1 (диагностика)
.set G_VAL, 0x638418          # qword: последнее распарсенное значение (u32, кламп)
.set G_PTR, 0x638420          # qword: указатель chars последнего вызова (диагностика)

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
    mov  r13, 0xffffffffffffffff # u64-максимум bigbytes (переиспользуется в L_tot)
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
    add  r8, r8                 # r8*10 (CF гасится следующим add!)
    jc   L_ibig                 # u64-wrap при ×10 -> big-flag -> кламп
    movzx ebx, BYTE PTR [rsi]
    sub  bl, '0'
    movzx ebx, bl
    add  r8, rbx
    jc   L_ibig                 # u64-wrap при +цифра -> кламп
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
    mov  r13, 0xffffffffffffffff # восстановить u64-максимум (r13 затёрт делителем 10 в L_dv)
    mov  rax, r14
    cmp  rax, r13
    jbe  L_okv
L_clamp:
    mov  rax, 0xffffffffffffffff
    jmp  L_okv
L_okv:
    mov  rdx, rax                # RDX = u64-значение (канал для стаба3)
    mov  eax, 1
    jmp  L_out
L_ok0:
    xor  edx, edx                # пусто = валидно 0 (семантика оригинала)
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

# =============================================================================
# STAB3 (VALUE-COMMIT): замена 0x50ba60 — слот vt+0x20 bigbytes-конвертера
# (класс 0x5948f8). Штатный OK-путь (единый для editor-полей; ДОКАЗАНО для shm
# по v66: [widget+0x18]=0x2c75590 -> [0x2c75590]=0x4000000=64MiB = ХОЛДЕР
# &store[0x120]):
#   OK -> 0x4976c3 -> [widget vt+0x40]=0x470f18 -> [widget vt+0xc8]=0x5207c0
#   -> [конвертер vt+0x20](rcx=conv, rdx=[widget+0x18]=&store[varnum], r8=str)
# У брата number слот = 0x46b17a (u32 в [rdx]); у bigbytes — ПУСТОЙ (ret) ->
# правка не доставлялась -> откат -> set нёс open-value.
# Стаб3: тонкая обёртка над ядром: str из r8, u64 в [rdx] (холдер).
# =============================================================================
.org 0x400                     # стаб3 ровно на 0x638900 (0x638500+0x400)
.globl stub3
stub3:
    push rbx                   # сохранить
    mov  rbx, rdx              # rbx = &out (холдер = &store[varnum])
    mov  rdx, r8               # rdx = str-объект (контракт ядра)
    call _start                # ядро: AL=1/0 + RDX=u64
    test al, al
    je   L3_out
    mov  QWORD PTR [rbx], rdx  # холдер/store[varnum] = значение правки (u64)
    mov  eax, 1
L3_out:
    pop  rbx
    ret
