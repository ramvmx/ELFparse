#ifndef _ELF_READ_H
#define _ELF_READ_H

#include "elf_types.h"

u8  *elf_at(elf_t *e, u64 off, u64 sz);

u16  elf_r16(elf_t *e, const void *p);
u32  elf_r32(elf_t *e, const void *p);
u64  elf_r64(elf_t *e, const void *p);

const char *elf_str(const char *tab, u64 tabsz, u32 off);

elf_t *elf_map(const char *path);
void   elf_unmap(elf_t *e);

#endif
