
build_all: payload infector test


payload: payload.asm
	nasm -f elf64 -o payload.o payload.asm && ld -o payload payload.o

infector: infector.c
	gcc -o infector infector.c

test: test.c
	gcc -o test test.c -g

.PHONY: payload test infector