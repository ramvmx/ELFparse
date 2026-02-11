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

#define _GNU_SOURCE
#include "elf_read.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * @brief Returns a bounds-checked pointer into the memory-mapped ELF file.
 * @param e The ELF context.
 * @param off Byte offset from the start of the file.
 * @param sz Number of bytes to access.
 * @return Pointer to the requested region within the mapped file.
*/

u8 *elf_at(elf_t *e, u64 off, u64 sz) {
  ASSERT(off + sz <= e->len,
         "out of bounds: off=0x%lx sz=0x%lx file=0x%lx",
         (unsigned long)off, (unsigned long)sz, (unsigned long)e->len);
  return e->base + off;
}

/**
 * @brief Reads a 16-bit value with endian awareness.
 * @param e The ELF context (used to determine byte order).
 * @param p Pointer to the raw bytes.
 * @return The decoded 16-bit value.
*/

u16 elf_r16(elf_t *e, const void *p) {
  const u8 *b = p;
  return e->data == ELF_DATA_MSB
    ? (u16)b[0] << 8 | b[1]
    : (u16)b[1] << 8 | b[0];
}

/**
 * @brief Reads a 32-bit value with endian awareness.
 * @param e The ELF context (used to determine byte order).
 * @param p Pointer to the raw bytes.
 * @return The decoded 32-bit value.
*/

u32 elf_r32(elf_t *e, const void *p) {
  const u8 *b = p;
  return e->data == ELF_DATA_MSB
    ? (u32)b[0] << 24 | (u32)b[1] << 16 | (u32)b[2] << 8 | b[3]
    : (u32)b[3] << 24 | (u32)b[2] << 16 | (u32)b[1] << 8 | b[0];
}

/**
 * @brief Reads a 64-bit value with endian awareness.
 * @param e The ELF context (used to determine byte order).
 * @param p Pointer to the raw bytes.
 * @return The decoded 64-bit value.
*/

u64 elf_r64(elf_t *e, const void *p) {
  const u8 *b = p;
  return e->data == ELF_DATA_MSB
    ? (u64)b[0] << 56 | (u64)b[1] << 48 | (u64)b[2] << 40 |
      (u64)b[3] << 32 | (u64)b[4] << 24 | (u64)b[5] << 16 |
      (u64)b[6] << 8  | (u64)b[7]
    : (u64)b[7] << 56 | (u64)b[6] << 48 | (u64)b[5] << 40 |
      (u64)b[4] << 32 | (u64)b[3] << 24 | (u64)b[2] << 16 |
      (u64)b[1] << 8  | (u64)b[0];
}

/**
 * @brief Resolves a string from a string table by offset.
 * @param tab Pointer to the base of the string table.
 * @param tabsz Total size of the string table in bytes.
 * @param off Byte offset into the string table.
 * @return The resolved string, or "" if out of bounds or tab is NULL.
*/

const char *elf_str(const char *tab, u64 tabsz, u32 off) {
  if (!tab || off >= tabsz) return "";
  return tab + off;
}

/**
 * @brief Memory-maps an ELF file and validates its identification bytes.
 * @param path Filesystem path to the ELF binary.
 * @return A heap-allocated ELF context with the file mapped and ident parsed.
*/

elf_t *elf_map(const char *path) {
  int fd = open(path, O_RDONLY);
  ASSERT(fd >= 0, "cannot open '%s'", path);

  struct stat st;
  if (fstat(fd, &st) < 0) { close(fd); DIE("cannot stat '%s'", path); }
  ASSERT(st.st_size >= 16, "file too small");

  elf_t *e = calloc(1, sizeof(elf_t));
  ASSERT(e, "alloc");

  e->len  = (u64)st.st_size;
  e->base = mmap(NULL, e->len, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  ASSERT(e->base != MAP_FAILED, "mmap '%s'", path);

  u8 *id = elf_at(e, 0, EI_NIDENT);
  ASSERT(id[0] == ELFMAG0 && id[1] == ELFMAG1 &&
         id[2] == ELFMAG2 && id[3] == ELFMAG3,
         "bad magic: not an ELF file");

  e->class  = id[4];
  e->data   = id[5];
  e->osabi  = id[7];
  e->abiver = id[8];

  ASSERT(e->class == ELF_CLASS_32 || e->class == ELF_CLASS_64,
         "unsupported ELF class %u", e->class);
  ASSERT(e->data == ELF_DATA_LSB || e->data == ELF_DATA_MSB,
         "unsupported endianness %u", e->data);

  return e;
}

/**
 * @brief Unmaps the ELF file and frees all associated resources.
 * @param e The ELF context to destroy.
*/

void elf_unmap(elf_t *e) {
  if (!e) return;
  if (e->base && e->base != MAP_FAILED)
    munmap(e->base, e->len);
  free(e->phdrs);
  free(e->shdrs);
  free(e->symtab);
  free(e->dynsym);
  free(e->rela);
  free(e->pltrel);
  free(e->dynamic);
  free(e);
}
