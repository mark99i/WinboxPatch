# v107e "shield on the free path" - cave @ 0x658000
# Hook entry 0x4cf0da (object-release):
#   stock: rdx=[rcx]; rdx==0x53d268 (sentinel) -> ret; otherwise free(rdx).
# Crash class: free() of a block with a smashed CRT/NT header (0-overlay /
#   huge size / freed-fill) -> allocator AV. Shield: sanity-check the header
#   BEFORE free; if broken -> ret (a leak is safer than a crash).
# ABI: function entry hook (call -> rsp==8); the cave makes no calls of its
#   own -> alignment is not critical; rax/rdx/rcx are volatile (the stock
#   function clobbers rax/rcx too; rdx is volatile per ABI). Tail-jmp to
#   free - ret returns to the caller (same as stock).
    .intel_syntax noprefix
    .text
    .globl _start
_start:
    mov     rdx, QWORD PTR [rcx]      # object buffer (the memory being freed)
    mov     eax, 0x53d268             # the "do not free" sentinel
    cmp     rdx, rax
    je      L_ret                     # stock sentinel path
    cmp     rdx, 0x10000              # heap lower bound (reject NULL/garbage)
    jb      L_ret
    test    rdx, 0xF                  # 16-byte alignment (x64 malloc blocks)
    jnz     L_ret
    mov     eax, DWORD PTR [rdx-8]    # size field of the block CRT/NT header
    test    eax, eax                  # 0-overlay (smashed)?
    jz      L_ret
    cmp     eax, 0xFEEEFEEE           # freed-fill ?
    je      L_ret
    cmp     eax, 0xBAADF00D           # tagged/uninit-fill ?
    je      L_ret
    cmp     eax, 0x80000              # sane size <= 8MB (0x80000 units)
    ja      L_ret                     # (the broken 0xc00290 class is rejected)
    # header valid -> stock free
    mov     rcx, rdx
    jmp     0x4d5408                  # free(buf); ret returns to the caller
L_ret:
    ret
