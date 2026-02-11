#ifndef _ELF_DUMP_H
#define _ELF_DUMP_H

#include "elf_parse.h"

void elf_dump_ehdr(elf_t *e);
void elf_dump_phdrs(elf_t *e);
void elf_dump_shdrs(elf_t *e);
void elf_dump_symtab(elf_t *e);
void elf_dump_dynsym(elf_t *e);
void elf_dump_rela(elf_t *e);
void elf_dump_dynamic(elf_t *e);
void elf_dump_hex(elf_t *e, const char *name);
void elf_dump_all(elf_t *e);

#endif
