/*
 * Copyright (C) 2026 elfparse contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "elf_parse.h"

/** @brief Raw 32-bit ELF header as it appears on disk. */
typedef struct PACKED _raw_ehdr32_t {
  u8  ident[EI_NIDENT];
  u16 type,  machine;
  u32 version;
  u32 entry, phoff, shoff;
  u32 flags;
  u16 ehsize,
      phentsize, phnum,
      shentsize, shnum,
      shstrndx;
} raw_ehdr32_t;

/** @brief Raw 64-bit ELF header as it appears on disk. */
typedef struct PACKED _raw_ehdr64_t {
  u8  ident[EI_NIDENT];
  u16 type,  machine;
  u32 version;
  u64 entry, phoff, shoff;
  u32 flags;
  u16 ehsize,
      phentsize, phnum,
      shentsize, shnum,
      shstrndx;
} raw_ehdr64_t;

/** @brief Raw 32-bit program header as it appears on disk. */
typedef struct PACKED _raw_phdr32_t {
  u32 type, offset, vaddr, paddr,
      filesz, memsz, flags, align;
} raw_phdr32_t;

/** @brief Raw 64-bit program header as it appears on disk. */
typedef struct PACKED _raw_phdr64_t {
  u32 type, flags;
  u64 offset, vaddr, paddr,
      filesz, memsz, align;
} raw_phdr64_t;

/** @brief Raw 32-bit section header as it appears on disk. */
typedef struct PACKED _raw_shdr32_t {
  u32 name, type, flags, addr,
      offset, size, link, info,
      addralign, entsize;
} raw_shdr32_t;

/** @brief Raw 64-bit section header as it appears on disk. */
typedef struct PACKED _raw_shdr64_t {
  u32 name, type;
  u64 flags, addr, offset, size;
  u32 link, info;
  u64 addralign, entsize;
} raw_shdr64_t;

/** @brief Raw 32-bit symbol table entry as it appears on disk. */
typedef struct PACKED _raw_sym32_t {
  u32 name;
  u32 value, size;
  u8  info, other;
  u16 shndx;
} raw_sym32_t;

/** @brief Raw 64-bit symbol table entry as it appears on disk. */
typedef struct PACKED _raw_sym64_t {
  u32 name;
  u8  info, other;
  u16 shndx;
  u64 value, size;
} raw_sym64_t;

/** @brief Raw 32-bit RELA relocation entry as it appears on disk. */
typedef struct PACKED _raw_rela32_t {
  u32 offset;
  u32 info;
  i32 addend;
} raw_rela32_t;

/** @brief Raw 64-bit RELA relocation entry as it appears on disk. */
typedef struct PACKED _raw_rela64_t {
  u64 offset;
  u64 info;
  i64 addend;
} raw_rela64_t;

/** @brief Raw 32-bit dynamic section entry as it appears on disk. */
typedef struct PACKED _raw_dyn32_t {
  i32 tag;
  u32 val;
} raw_dyn32_t;

/** @brief Raw 64-bit dynamic section entry as it appears on disk. */
typedef struct PACKED _raw_dyn64_t {
  i64 tag;
  u64 val;
} raw_dyn64_t;

/**
 * @brief Finds the first section header matching a given type.
 * @param e The ELF context.
 * @param type The section type (SHT_*) to search for.
 * @return Pointer to the matching section header, or NULL if not found.
*/

const elf_shdr_t *elf_find_section(elf_t *e, u32 type) {
  for (u16 i = 0; i < e->shnum; ++i)
    if (e->shdrs[i].type == type)
      return &e->shdrs[i];
  return NULL;
}

/**
 * @brief Finds a section header by its name in the section string table.
 * @param e The ELF context.
 * @param name The section name to search for.
 * @return Pointer to the matching section header, or NULL if not found.
*/

const elf_shdr_t *elf_find_section_name(elf_t *e, const char *name) {
  for (u16 i = 0; i < e->shnum; ++i)
    if (e->shdrs[i].name && !strcmp(e->shdrs[i].name, name))
      return &e->shdrs[i];
  return NULL;
}

/**
 * @brief Decodes the ELF file header into the context struct.
 * @param e The ELF context (must already have class/data set).
*/

static void _parse_ehdr(elf_t *e) {
  if (e->class == ELF_CLASS_64) {
    raw_ehdr64_t *h = (void *)elf_at(e, 0, sizeof(*h));
    e->type      = elf_r16(e, &h->type);
    e->machine   = elf_r16(e, &h->machine);
    e->entry     = elf_r64(e, &h->entry);
    e->phoff     = elf_r64(e, &h->phoff);
    e->shoff     = elf_r64(e, &h->shoff);
    e->flags     = elf_r32(e, &h->flags);
    e->ehsize    = elf_r16(e, &h->ehsize);
    e->phentsize = elf_r16(e, &h->phentsize);
    e->phnum     = elf_r16(e, &h->phnum);
    e->shentsize = elf_r16(e, &h->shentsize);
    e->shnum     = elf_r16(e, &h->shnum);
    e->shstrndx  = elf_r16(e, &h->shstrndx);
  } else {
    raw_ehdr32_t *h = (void *)elf_at(e, 0, sizeof(*h));
    e->type      = elf_r16(e, &h->type);
    e->machine   = elf_r16(e, &h->machine);
    e->entry     = elf_r32(e, &h->entry);
    e->phoff     = elf_r32(e, &h->phoff);
    e->shoff     = elf_r32(e, &h->shoff);
    e->flags     = elf_r32(e, &h->flags);
    e->ehsize    = elf_r16(e, &h->ehsize);
    e->phentsize = elf_r16(e, &h->phentsize);
    e->phnum     = elf_r16(e, &h->phnum);
    e->shentsize = elf_r16(e, &h->shentsize);
    e->shnum     = elf_r16(e, &h->shnum);
    e->shstrndx  = elf_r16(e, &h->shstrndx);
  }
}

/**
 * @brief Parses all program headers into the context's phdr array.
 * @param e The ELF context.
*/

static void _parse_phdrs(elf_t *e) {
  if (!e->phnum) return;
  e->phdrs = calloc(e->phnum, sizeof(elf_phdr_t));
  ASSERT(e->phdrs, "alloc phdrs");

  for (u16 i = 0; i < e->phnum; ++i) {
    u64 off    = e->phoff + (u64)i * e->phentsize;
    elf_phdr_t *p = &e->phdrs[i];

    if (e->class == ELF_CLASS_64) {
      raw_phdr64_t *h = (void *)elf_at(e, off, sizeof(*h));
      p->type   = elf_r32(e, &h->type);
      p->flags  = elf_r32(e, &h->flags);
      p->offset = elf_r64(e, &h->offset);
      p->vaddr  = elf_r64(e, &h->vaddr);
      p->paddr  = elf_r64(e, &h->paddr);
      p->filesz = elf_r64(e, &h->filesz);
      p->memsz  = elf_r64(e, &h->memsz);
      p->align  = elf_r64(e, &h->align);
    } else {
      raw_phdr32_t *h = (void *)elf_at(e, off, sizeof(*h));
      p->type   = elf_r32(e, &h->type);
      p->flags  = elf_r32(e, &h->flags);
      p->offset = elf_r32(e, &h->offset);
      p->vaddr  = elf_r32(e, &h->vaddr);
      p->paddr  = elf_r32(e, &h->paddr);
      p->filesz = elf_r32(e, &h->filesz);
      p->memsz  = elf_r32(e, &h->memsz);
      p->align  = elf_r32(e, &h->align);
    }
  }
}

/**
 * @brief Parses all section headers and resolves section names from shstrtab.
 * @param e The ELF context.
*/

static void _parse_shdrs(elf_t *e) {
  if (!e->shnum) return;
  e->shdrs = calloc(e->shnum, sizeof(elf_shdr_t));
  ASSERT(e->shdrs, "alloc shdrs");

  for (u16 i = 0; i < e->shnum; ++i) {
    u64 off    = e->shoff + (u64)i * e->shentsize;
    elf_shdr_t *s = &e->shdrs[i];

    if (e->class == ELF_CLASS_64) {
      raw_shdr64_t *h = (void *)elf_at(e, off, sizeof(*h));
      s->_name_off = elf_r32(e, &h->name);
      s->type      = elf_r32(e, &h->type);
      s->flags     = elf_r64(e, &h->flags);
      s->addr      = elf_r64(e, &h->addr);
      s->offset    = elf_r64(e, &h->offset);
      s->size      = elf_r64(e, &h->size);
      s->link      = elf_r32(e, &h->link);
      s->info      = elf_r32(e, &h->info);
      s->addralign = elf_r64(e, &h->addralign);
      s->entsize   = elf_r64(e, &h->entsize);
    } else {
      raw_shdr32_t *h = (void *)elf_at(e, off, sizeof(*h));
      s->_name_off = elf_r32(e, &h->name);
      s->type      = elf_r32(e, &h->type);
      s->flags     = elf_r32(e, &h->flags);
      s->addr      = elf_r32(e, &h->addr);
      s->offset    = elf_r32(e, &h->offset);
      s->size      = elf_r32(e, &h->size);
      s->link      = elf_r32(e, &h->link);
      s->info      = elf_r32(e, &h->info);
      s->addralign = elf_r32(e, &h->addralign);
      s->entsize   = elf_r32(e, &h->entsize);
    }
  }

  if (e->shstrndx < e->shnum) {
    elf_shdr_t *ss = &e->shdrs[e->shstrndx];
    e->shstrtab    = (const char *)elf_at(e, ss->offset, ss->size);
    e->shstrtab_sz = ss->size;

    for (u16 i = 0; i < e->shnum; ++i)
      e->shdrs[i].name = elf_str(e->shstrtab, e->shstrtab_sz,
                                  e->shdrs[i]._name_off);
  }
}

/**
 * @brief Locates and caches pointers to the .strtab and .dynstr sections.
 * @param e The ELF context.
*/

static void _resolve_strtabs(elf_t *e) {
  const elf_shdr_t *s;

  if ((s = elf_find_section_name(e, ".strtab"))) {
    e->strtab    = (const char *)elf_at(e, s->offset, s->size);
    e->strtab_sz = s->size;
  }
  if ((s = elf_find_section_name(e, ".dynstr"))) {
    e->dynstr    = (const char *)elf_at(e, s->offset, s->size);
    e->dynstr_sz = s->size;
  }
}

/**
 * @brief Parses a symbol table section (SHT_SYMTAB or SHT_DYNSYM).
 * @param e The ELF context.
 * @param shtype Section type to search for (SHT_SYMTAB or SHT_DYNSYM).
 * @param out Output pointer to the allocated symbol array.
 * @param out_n Output pointer to the symbol count.
 * @param strtab Associated string table base pointer.
 * @param strsz Size of the associated string table.
*/

static void _parse_symtab_sect(elf_t *e, u32 shtype,
                                elf_sym_t **out, u32 *out_n,
                                const char *strtab, u64 strsz) {
  const elf_shdr_t *sec = elf_find_section(e, shtype);
  if (!sec || !sec->entsize) return;

  u32 n = (u32)(sec->size / sec->entsize);
  *out   = calloc(n, sizeof(elf_sym_t));
  *out_n = n;
  ASSERT(*out, "alloc symtab");

  for (u32 i = 0; i < n; ++i) {
    u64 off     = sec->offset + (u64)i * sec->entsize;
    elf_sym_t *sym = &(*out)[i];

    if (e->class == ELF_CLASS_64) {
      raw_sym64_t *s = (void *)elf_at(e, off, sizeof(*s));
      u32 noff    = elf_r32(e, &s->name);
      sym->name   = elf_str(strtab, strsz, noff);
      sym->value  = elf_r64(e, &s->value);
      sym->size   = elf_r64(e, &s->size);
      sym->bind   = s->info >> 4;
      sym->type   = s->info & 0xf;
      sym->vis    = s->other & 0x3;
      sym->shndx  = elf_r16(e, &s->shndx);
    } else {
      raw_sym32_t *s = (void *)elf_at(e, off, sizeof(*s));
      u32 noff    = elf_r32(e, &s->name);
      sym->name   = elf_str(strtab, strsz, noff);
      sym->value  = elf_r32(e, &s->value);
      sym->size   = elf_r32(e, &s->size);
      sym->bind   = s->info >> 4;
      sym->type   = s->info & 0xf;
      sym->vis    = s->other & 0x3;
      sym->shndx  = elf_r16(e, &s->shndx);
    }
  }
}

/**
 * @brief Counts the total number of relocation entries of a given type.
 * @param e The ELF context.
 * @param shtype Section type to count (SHT_RELA or SHT_REL).
 * @return Total number of relocation entries across all matching sections.
*/

static u32 _count_rela(elf_t *e, u32 shtype) {
  u32 total = 0;
  for (u16 i = 0; i < e->shnum; ++i)
    if (e->shdrs[i].type == shtype && e->shdrs[i].entsize)
      total += (u32)(e->shdrs[i].size / e->shdrs[i].entsize);
  return total;
}

/**
 * @brief Decodes relocation entries from all sections of a given type.
 * @param e The ELF context.
 * @param shtype Section type to decode (SHT_RELA or SHT_REL).
 * @param out Pre-allocated output array for decoded entries.
 * @param idx Pointer to the current write index (updated in place).
*/

static void _fill_rela(elf_t *e, u32 shtype,
                        elf_rela_t *out, u32 *idx) {
  for (u16 i = 0; i < e->shnum; ++i) {
    elf_shdr_t *sec = &e->shdrs[i];
    if (sec->type != shtype || !sec->entsize) continue;

    u32 n = (u32)(sec->size / sec->entsize);
    for (u32 j = 0; j < n; ++j) {
      u64 off     = sec->offset + (u64)j * sec->entsize;
      elf_rela_t *r = &out[(*idx)++];

      if (e->class == ELF_CLASS_64) {
        raw_rela64_t *h = (void *)elf_at(e, off, sizeof(*h));
        u64 info  = elf_r64(e, &h->info);
        r->offset = elf_r64(e, &h->offset);
        r->addend = (u64)elf_r64(e, &h->addend);
        r->sym    = (u32)(info >> 32);
        r->type   = (u32)(info & 0xffffffff);
      } else {
        raw_rela32_t *h = (void *)elf_at(e, off, sizeof(*h));
        u32 info  = elf_r32(e, &h->info);
        r->offset = elf_r32(e, &h->offset);
        r->addend = (u64)(i64)(i32)elf_r32(e, &h->addend);
        r->sym    = info >> 8;
        r->type   = info & 0xff;
      }
    }
  }
}

/**
 * @brief Parses all SHT_RELA sections into the context's rela array.
 * @param e The ELF context.
*/

static void _parse_rela(elf_t *e) {
  u32 n = _count_rela(e, SHT_RELA);
  if (n) {
    e->rela   = calloc(n, sizeof(elf_rela_t));
    e->rela_n = n;
    ASSERT(e->rela, "alloc rela");
    u32 idx = 0;
    _fill_rela(e, SHT_RELA, e->rela, &idx);
  }
}

/**
 * @brief Parses the SHT_DYNAMIC section into the context's dynamic array.
 * @param e The ELF context.
*/

static void _parse_dynamic(elf_t *e) {
  const elf_shdr_t *sec = elf_find_section(e, SHT_DYNAMIC);
  if (!sec || !sec->entsize) return;

  u32 n        = (u32)(sec->size / sec->entsize);
  e->dynamic   = calloc(n, sizeof(elf_dyn_t));
  e->dynamic_n = n;
  ASSERT(e->dynamic, "alloc dynamic");

  for (u32 i = 0; i < n; ++i) {
    u64 off     = sec->offset + (u64)i * sec->entsize;
    elf_dyn_t *d = &e->dynamic[i];

    if (e->class == ELF_CLASS_64) {
      raw_dyn64_t *h = (void *)elf_at(e, off, sizeof(*h));
      d->tag = (i64)elf_r64(e, &h->tag);
      d->val = elf_r64(e, &h->val);
    } else {
      raw_dyn32_t *h = (void *)elf_at(e, off, sizeof(*h));
      d->tag = (i64)(i32)elf_r32(e, &h->tag);
      d->val = elf_r32(e, &h->val);
    }

    if (d->tag == DT_NULL) { e->dynamic_n = i; break; }
  }
}

/**
 * @brief Fully parses an ELF binary from disk.
 * @param path Filesystem path to the ELF file.
 * @return A heap-allocated ELF context with all structures populated.
*/

elf_t *elf_parse(const char *path) {
  elf_t *e = elf_map(path);

  _parse_ehdr(e);
  _parse_phdrs(e);
  _parse_shdrs(e);
  _resolve_strtabs(e);

  _parse_symtab_sect(e, SHT_SYMTAB, &e->symtab, &e->symtab_n,
                     e->strtab, e->strtab_sz);
  _parse_symtab_sect(e, SHT_DYNSYM, &e->dynsym, &e->dynsym_n,
                     e->dynstr, e->dynstr_sz);

  _parse_rela(e);
  _parse_dynamic(e);

  return e;
}
