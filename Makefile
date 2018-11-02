PAYLOADS = payloads/fork_ncat_server payloads/hello_world

all: $(PAYLOADS) infector example

$(PAYLOADS): %: %.asm
	nasm -f elf64 -o payloads/tmp.o $< && ld -o $@ payloads/tmp.o && rm payloads/tmp.o

infector: infector.c
	gcc -o infector infector.c

example: example.c
	gcc -o example example.c

clean:
	rm infector example; rm $(PAYLOADS)

.PHONY: $(PAYLOADS) example infector clean
