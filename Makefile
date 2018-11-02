
build_all: payload infector example


payload: payload.asm
	nasm -f elf64 -o payload.o payload.asm && ld -o payload payload.o

infector: infector.c
	gcc -o infector infector.c

example: example.c
	gcc -o example example.c

clean:
	rm *.o; rm payload infector example

.PHONY: payload example infector clean
