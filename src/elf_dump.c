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

#include "elf_dump.h"

#define C_RST  "\x1b[0m"
#define C_BLD  "\x1b[1m"
#define C_DIM  "\x1b[2m"
#define C_RED  "\x1b[31m"
#define C_GRN  "\x1b[32m"
#define C_YEL  "\x1b[33m"
#define C_BLU  "\x1b[34m"
#define C_MAG  "\x1b[35m"
#define C_CYN  "\x1b[36m"
#define C_WHT  "\x1b[37m"
#define C_BGRN "\x1b[1;32m"
#define C_BYEL "\x1b[1;33m"
#define C_BCYN "\x1b[1;36m"

/** @brief ELF object type lookup table. */
static const char *_type_str[] = {
  [ET_NONE] = "NONE", [ET_REL]  = "REL",  [ET_EXEC] = "EXEC",
  [ET_DYN]  = "DYN",  [ET_CORE] = "CORE"
};

/** @brief OS/ABI identifier lookup table. */
static const char *_osabi_str[] = {
  [0]  = "UNIX System V",  [1]  = "HP-UX",     [2]  = "NetBSD",
  [3]  = "Linux",          [6]  = "Solaris",    [7]  = "AIX",
  [8]  = "IRIX",           [9]  = "FreeBSD",    [12] = "OpenBSD"
};

/** @brief Machine architecture lookup table. */
static const char *_machine_str[] = {
  [EM_NONE]    = "None",         [EM_386]     = "Intel 80386",
  [EM_MIPS]    = "MIPS",         [EM_PPC]     = "PowerPC",
  [EM_PPC64]   = "PowerPC64",    [EM_ARM]     = "ARM",
  [EM_X86_64]  = "AMD x86-64",  [EM_AARCH64] = "AArch64",
  [EM_RISCV]   = "RISC-V"
};

/**
 * @brief Resolves a program header type to its string representation.
 * @param type The segment type (PT_*).
 * @return Human-readable type string.
*/

static const char *_pt_str(u32 type) {
  switch (type) {
    case PT_NULL:         return "NULL";
    case PT_LOAD:         return "LOAD";
    case PT_DYNAMIC:      return "DYNAMIC";
    case PT_INTERP:       return "INTERP";
    case PT_NOTE:         return "NOTE";
    case PT_SHLIB:        return "SHLIB";
    case PT_PHDR:         return "PHDR";
    case PT_TLS:          return "TLS";
    case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
    case PT_GNU_STACK:    return "GNU_STACK";
    case PT_GNU_RELRO:    return "GNU_RELRO";
    case PT_GNU_PROPERTY: return "GNU_PROPERTY";
    default:              return "???";
  }
}

/**
 * @brief Resolves a section header type to its string representation.
 * @param type The section type (SHT_*).
 * @return Human-readable type string.
*/

static const char *_sht_str(u32 type) {
  switch (type) {
    case SHT_NULL:          return "NULL";
    case SHT_PROGBITS:      return "PROGBITS";
    case SHT_SYMTAB:        return "SYMTAB";
    case SHT_STRTAB:        return "STRTAB";
    case SHT_RELA:          return "RELA";
    case SHT_HASH:          return "HASH";
    case SHT_DYNAMIC:       return "DYNAMIC";
    case SHT_NOTE:          return "NOTE";
    case SHT_NOBITS:        return "NOBITS";
    case SHT_REL:           return "REL";
    case SHT_DYNSYM:        return "DYNSYM";
    case SHT_INIT_ARRAY:    return "INIT_ARRAY";
    case SHT_FINI_ARRAY:    return "FINI_ARRAY";
    case SHT_PREINIT_ARRAY: return "PREINIT_ARRAY";
    case SHT_GNU_HASH:      return "GNU_HASH";
    case SHT_GNU_VERSYM:    return "VERSYM";
    case SHT_GNU_VERNEED:   return "VERNEED";
    case SHT_GNU_VERDEF:    return "VERDEF";
    default:                return "???";
  }
}

/** @brief Symbol binding lookup table. */
static const char *_stb_str[] = {
  [STB_LOCAL]  = "LOCAL",
  [STB_GLOBAL] = "GLOBAL",
  [STB_WEAK]   = "WEAK"
};

/** @brief Symbol type lookup table. */
static const char *_stt_str[] = {
  [STT_NOTYPE]  = "NOTYPE",  [STT_OBJECT]  = "OBJECT",
  [STT_FUNC]    = "FUNC",    [STT_SECTION] = "SECTION",
  [STT_FILE]    = "FILE",    [STT_COMMON]  = "COMMON",
  [STT_TLS]     = "TLS"
};

/**
 * @brief Resolves a dynamic section tag to its string representation.
 * @param tag The dynamic tag value (DT_*).
 * @return Human-readable tag string.
*/

static const char *_dt_str(i64 tag) {
  switch (tag) {
    case DT_NULL:         return "NULL";
    case DT_NEEDED:       return "NEEDED";
    case DT_PLTRELSZ:     return "PLTRELSZ";
    case DT_PLTGOT:       return "PLTGOT";
    case DT_HASH:         return "HASH";
    case DT_STRTAB:       return "STRTAB";
    case DT_SYMTAB:       return "SYMTAB";
    case DT_RELA:         return "RELA";
    case DT_RELASZ:       return "RELASZ";
    case DT_RELAENT:      return "RELAENT";
    case DT_STRSZ:        return "STRSZ";
    case DT_SYMENT:       return "SYMENT";
    case DT_INIT:         return "INIT";
    case DT_FINI:         return "FINI";
    case DT_SONAME:       return "SONAME";
    case DT_RPATH:        return "RPATH";
    case DT_SYMBOLIC:     return "SYMBOLIC";
    case DT_REL:          return "REL";
    case DT_RELSZ:        return "RELSZ";
    case DT_RELENT:       return "RELENT";
    case DT_PLTREL:       return "PLTREL";
    case DT_DEBUG:        return "DEBUG";
    case DT_JMPREL:       return "JMPREL";
    case DT_INIT_ARRAY:   return "INIT_ARRAY";
    case DT_FINI_ARRAY:   return "FINI_ARRAY";
    case DT_INIT_ARRAYSZ: return "INIT_ARRAYSZ";
    case DT_FINI_ARRAYSZ: return "FINI_ARRAYSZ";
    case DT_RUNPATH:      return "RUNPATH";
    case DT_FLAGS:        return "FLAGS";
    case DT_FLAGS_1:      return "FLAGS_1";
    case DT_VERNEED:      return "VERNEED";
    case DT_VERNEEDNUM:   return "VERNEEDNUM";
    case DT_VERSYM:       return "VERSYM";
    case DT_RELACOUNT:    return "RELACOUNT";
    default:              return "???";
  }
}

/**
 * @brief Formats program header permission flags into a 3-char string.
 * @param buf Output buffer (minimum 4 bytes).
 * @param f The permission flags (PF_R, PF_W, PF_X).
*/

static void _pflags(char *buf, u32 f) {
  buf[0] = (f & PF_R) ? 'R' : '-';
  buf[1] = (f & PF_W) ? 'W' : '-';
  buf[2] = (f & PF_X) ? 'X' : '-';
  buf[3] = '\0';
}

/**
 * @brief Formats section header flags into a 6-char string.
 * @param buf Output buffer (minimum 7 bytes).
 * @param f The section flags (SHF_WRITE, SHF_ALLOC, etc.).
*/

static void _shflags(char *buf, u64 f) {
  buf[0] = (f & SHF_WRITE)     ? 'W' : '-';
  buf[1] = (f & SHF_ALLOC)     ? 'A' : '-';
  buf[2] = (f & SHF_EXECINSTR) ? 'X' : '-';
  buf[3] = (f & SHF_MERGE)     ? 'M' : '-';
  buf[4] = (f & SHF_STRINGS)   ? 'S' : '-';
  buf[5] = (f & SHF_TLS)       ? 'T' : '-';
  buf[6] = '\0';
}

/** @brief Prints a colorized section title. */
#define TITLE(s) printf(C_BLD C_CYN "━━━ " s " ━━━" C_RST "\n")

/**
 * @brief Dumps the ELF file header (class, type, machine, entry, etc.).
 * @param e The ELF context.
*/

void elf_dump_ehdr(elf_t *e) {
  u8 *id = elf_at(e, 0, EI_NIDENT);
  TITLE("ELF Header");
  printf("  Magic:       %s%02x %02x %02x %02x%s\n",
         C_DIM, id[0], id[1], id[2], id[3], C_RST);
  printf("  Class:       ELF%s%s%s\n",
         C_BGRN, e->class == ELF_CLASS_64 ? "64" : "32", C_RST);
  printf("  Encoding:    %s\n",
         e->data == ELF_DATA_LSB ? "Little Endian" : "Big Endian");
  printf("  OS/ABI:      %s\n", SAFE_STR(_osabi_str, id[7]));
  printf("  Type:        %s%s%s\n",
         C_BYEL, SAFE_STR(_type_str, e->type), C_RST);
  printf("  Machine:     %s\n", SAFE_STR(_machine_str, e->machine));
  printf("  Entry:       %s0x%lx%s\n",
         C_BCYN, (unsigned long)e->entry, C_RST);
  printf("  PH:          off=0x%lx  ent=%u  num=%u\n",
         (unsigned long)e->phoff, e->phentsize, e->phnum);
  printf("  SH:          off=0x%lx  ent=%u  num=%u  stridx=%u\n",
         (unsigned long)e->shoff, e->shentsize, e->shnum, e->shstrndx);
  printf("  Flags:       0x%x\n\n", e->flags);
}

/**
 * @brief Dumps all program headers (segments).
 * @param e The ELF context.
*/

void elf_dump_phdrs(elf_t *e) {
  if (!e->phnum) return;
  TITLE("Program Headers");
  printf("  %s%-14s %-3s %-18s %-18s %-10s %-10s %-6s%s\n",
         C_DIM, "Type", "Flg", "VAddr", "PAddr",
         "FileSz", "MemSz", "Align", C_RST);

  char fl[4];
  for (u16 i = 0; i < e->phnum; ++i) {
    elf_phdr_t *p = &e->phdrs[i];
    _pflags(fl, p->flags);

    const char *c = (p->type == PT_LOAD)    ? C_GRN :
                    (p->type == PT_DYNAMIC)  ? C_YEL :
                    (p->type == PT_INTERP)   ? C_MAG : "";

    printf("  %s%-14s%s %-3s 0x%016lx 0x%016lx 0x%08lx 0x%08lx 0x%lx\n",
           c, _pt_str(p->type), C_RST, fl,
           (unsigned long)p->vaddr,  (unsigned long)p->paddr,
           (unsigned long)p->filesz, (unsigned long)p->memsz,
           (unsigned long)p->align);

    if (p->type == PT_INTERP && p->filesz > 0 && p->filesz < 4096) {
      const char *interp = (const char *)elf_at(e, p->offset, p->filesz);
      printf("  %s  └─ %.*s%s\n", C_DIM, (int)p->filesz, interp, C_RST);
    }
  }
  putchar('\n');
}

/**
 * @brief Dumps all section headers.
 * @param e The ELF context.
*/

void elf_dump_shdrs(elf_t *e) {
  if (!e->shnum) return;
  TITLE("Section Headers");
  printf("  %s[%2s] %-20s %-14s %-6s %-18s %-10s %-4s %-4s%s\n",
         C_DIM, "Nr", "Name", "Type", "Flags",
         "Addr", "Size", "Lnk", "Inf", C_RST);

  char fl[7];
  for (u16 i = 0; i < e->shnum; ++i) {
    elf_shdr_t *s = &e->shdrs[i];
    _shflags(fl, s->flags);

    const char *c = (s->type == SHT_PROGBITS && (s->flags & SHF_EXECINSTR))
                    ? C_GRN
                    : (s->type == SHT_SYMTAB || s->type == SHT_DYNSYM)
                    ? C_YEL
                    : (s->type == SHT_DYNAMIC) ? C_MAG : "";

    printf("  [%2u] %s%-20.20s%s %-14s %-6s 0x%016lx 0x%08lx %-4u %-4u\n",
           i, c, s->name ? s->name : "", C_RST,
           _sht_str(s->type), fl,
           (unsigned long)s->addr, (unsigned long)s->size,
           s->link, s->info);
  }
  putchar('\n');
}

/**
 * @brief Dumps a symbol table with colorized output.
 * @param title Display title for the table.
 * @param syms Pointer to the symbol array.
 * @param n Number of symbols.
*/

static void _dump_syms(const char *title, elf_sym_t *syms, u32 n) {
  if (!n) return;
  printf(C_BLD C_CYN "━━━ %s (%u entries) ━━━" C_RST "\n", title, n);
  printf("  %s%-5s %-18s %-7s %-8s %-8s %s%s\n",
         C_DIM, "Num", "Value", "Size", "Bind", "Type", "Name", C_RST);

  for (u32 i = 0; i < n; ++i) {
    elf_sym_t *s = &syms[i];

    const char *c = (s->type == STT_FUNC)   ? C_GRN :
                    (s->type == STT_OBJECT)  ? C_YEL :
                    (s->bind == STB_WEAK)    ? C_RED : "";

    printf("  %-5u %s0x%016lx%s %-7lu %-8s %-8s %s%s%s\n",
           i, C_DIM, (unsigned long)s->value, C_RST,
           (unsigned long)s->size,
           SAFE_STR(_stb_str, s->bind),
           SAFE_STR(_stt_str, s->type),
           c, s->name ? s->name : "", C_RST);
  }
  putchar('\n');
}

/**
 * @brief Dumps the static symbol table (.symtab).
 * @param e The ELF context.
*/

void elf_dump_symtab(elf_t *e) {
  _dump_syms("Symbol Table", e->symtab, e->symtab_n);
}

/**
 * @brief Dumps the dynamic symbol table (.dynsym).
 * @param e The ELF context.
*/

void elf_dump_dynsym(elf_t *e) {
  _dump_syms("Dynamic Symbols", e->dynsym, e->dynsym_n);
}

/**
 * @brief Dumps all RELA relocation entries.
 * @param e The ELF context.
*/

void elf_dump_rela(elf_t *e) {
  if (!e->rela_n) return;
  printf(C_BLD C_CYN "━━━ Relocations (%u entries) ━━━" C_RST "\n", e->rela_n);
  printf("  %s%-18s %-8s %-8s %-18s %s%s\n",
         C_DIM, "Offset", "Type", "Sym", "Addend", "Symbol", C_RST);

  for (u32 i = 0; i < e->rela_n; ++i) {
    elf_rela_t *r = &e->rela[i];
    const char *sym = "";
    if (e->dynsym && r->sym < e->dynsym_n && e->dynsym[r->sym].name)
      sym = e->dynsym[r->sym].name;

    printf("  0x%016lx %-8u %-8u 0x%016lx %s%s%s\n",
           (unsigned long)r->offset, r->type, r->sym,
           (unsigned long)r->addend,
           C_GRN, sym, C_RST);
  }
  putchar('\n');
}

/**
 * @brief Dumps the dynamic section (.dynamic) entries.
 * @param e The ELF context.
*/

void elf_dump_dynamic(elf_t *e) {
  if (!e->dynamic_n) return;
  printf(C_BLD C_CYN "━━━ Dynamic Section (%u entries) ━━━" C_RST "\n",
         e->dynamic_n);
  printf("  %s%-18s %-18s %s%s\n",
         C_DIM, "Tag", "Value", "Info", C_RST);

  for (u32 i = 0; i < e->dynamic_n; ++i) {
    elf_dyn_t *d = &e->dynamic[i];
    printf("  %-18s 0x%016lx", _dt_str(d->tag), (unsigned long)d->val);

    if ((d->tag == DT_NEEDED  || d->tag == DT_SONAME ||
         d->tag == DT_RPATH   || d->tag == DT_RUNPATH) && e->dynstr)
      printf(" %s[%s]%s",
             C_MAG, elf_str(e->dynstr, e->dynstr_sz, (u32)d->val), C_RST);

    putchar('\n');
  }
  putchar('\n');
}

/**
 * @brief Dumps a hex view of a named section's raw bytes.
 * @param e The ELF context.
 * @param name The section name to dump (e.g. ".text", ".rodata").
*/

void elf_dump_hex(elf_t *e, const char *name) {
  const elf_shdr_t *sec = elf_find_section_name(e, name);
  if (!sec || !sec->size) return;

  printf(C_BLD C_CYN "━━━ Hex: %s (0x%lx bytes) ━━━" C_RST "\n",
         name, (unsigned long)sec->size);

  const u8 *data = elf_at(e, sec->offset, sec->size);
  u64 limit      = MIN(sec->size, 0x200);

  for (u64 off = 0; off < limit; off += 16) {
    printf("  %s0x%08lx%s  ", C_DIM, (unsigned long)(sec->addr + off), C_RST);
    u64 row = MIN(16, limit - off);

    for (u64 j = 0; j < 16; ++j) {
      if (j < row)  printf("%02x ", data[off + j]);
      else          printf("   ");
      if (j == 7)   putchar(' ');
    }

    printf(" %s|", C_DIM);
    for (u64 j = 0; j < row; ++j) {
      u8 c = data[off + j];
      putchar(c >= 0x20 && c < 0x7f ? c : '.');
    }
    printf("|%s\n", C_RST);
  }

  if (sec->size > 0x200)
    printf("  %s... %lu more bytes%s\n",
           C_DIM, (unsigned long)(sec->size - 0x200), C_RST);
  putchar('\n');
}

/**
 * @brief Dumps all parsed structures (header, segments, sections, symbols,
 *        relocations, and the dynamic section).
 * @param e The ELF context.
*/

void elf_dump_all(elf_t *e) {
  elf_dump_ehdr(e);
  elf_dump_phdrs(e);
  elf_dump_shdrs(e);
  elf_dump_symtab(e);
  elf_dump_dynsym(e);
  elf_dump_rela(e);
  elf_dump_dynamic(e);
}
