#ifndef _ELF_PARSE_H
#define _ELF_PARSE_H

#include "elf_read.h"

elf_t *elf_parse(const char *path);

const elf_shdr_t *elf_find_section(elf_t *e, u32 type);
const elf_shdr_t *elf_find_section_name(elf_t *e, const char *name);

#endif
