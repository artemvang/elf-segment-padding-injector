section .text
    global _start

time:

_start:

    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg]
    mov rdx, msg_end - msg
    syscall

    mov rax, 0x1111111111111111
    jmp rax

msg db 0x1b,'[31msuch infected, much wow!',0x1b,'[0m',0x0a,0
msg_end db 0x0