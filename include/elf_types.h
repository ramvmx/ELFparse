#ifndef _ELF_TYPES_H
#define _ELF_TYPES_H

#include "types.h"

#define EI_NIDENT 16

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'

typedef enum _elf_class_t {
  ELF_CLASS_NONE = 0,
  ELF_CLASS_32   = 1,
  ELF_CLASS_64   = 2
} elf_class_t;

typedef enum _elf_data_t {
  ELF_DATA_NONE = 0,
  ELF_DATA_LSB  = 1,
  ELF_DATA_MSB  = 2
} elf_data_t;

typedef enum _elf_type_t {
  ET_NONE = 0,
  ET_REL  = 1,
  ET_EXEC = 2,
  ET_DYN  = 3,
  ET_CORE = 4
} elf_type_t;

typedef enum _elf_pt_t {
  PT_NULL    = 0,
  PT_LOAD    = 1,
  PT_DYNAMIC = 2,
  PT_INTERP  = 3,
  PT_NOTE    = 4,
  PT_SHLIB   = 5,
  PT_PHDR    = 6,
  PT_TLS     = 7,
  PT_GNU_EH_FRAME = 0x6474e550,
  PT_GNU_STACK    = 0x6474e551,
  PT_GNU_RELRO    = 0x6474e552,
  PT_GNU_PROPERTY = 0x6474e553
} elf_pt_t;

typedef enum _elf_sht_t {
  SHT_NULL          = 0,
  SHT_PROGBITS      = 1,
  SHT_SYMTAB        = 2,
  SHT_STRTAB        = 3,
  SHT_RELA          = 4,
  SHT_HASH          = 5,
  SHT_DYNAMIC       = 6,
  SHT_NOTE          = 7,
  SHT_NOBITS        = 8,
  SHT_REL           = 9,
  SHT_SHLIB         = 10,
  SHT_DYNSYM        = 11,
  SHT_INIT_ARRAY    = 14,
  SHT_FINI_ARRAY    = 15,
  SHT_PREINIT_ARRAY = 16,
  SHT_GROUP         = 17,
  SHT_SYMTAB_SHNDX  = 18,
  SHT_GNU_HASH      = 0x6ffffff6,
  SHT_GNU_VERSYM    = 0x6fffffff,
  SHT_GNU_VERNEED   = 0x6ffffffe,
  SHT_GNU_VERDEF    = 0x6ffffffd
} elf_sht_t;

typedef enum _elf_stb_t {
  STB_LOCAL  = 0,
  STB_GLOBAL = 1,
  STB_WEAK   = 2
} elf_stb_t;

typedef enum _elf_stt_t {
  STT_NOTYPE  = 0,
  STT_OBJECT  = 1,
  STT_FUNC    = 2,
  STT_SECTION = 3,
  STT_FILE    = 4,
  STT_COMMON  = 5,
  STT_TLS     = 6
} elf_stt_t;

typedef enum _elf_dt_t {
  DT_NULL         = 0,
  DT_NEEDED       = 1,
  DT_PLTRELSZ     = 2,
  DT_PLTGOT       = 3,
  DT_HASH         = 4,
  DT_STRTAB       = 5,
  DT_SYMTAB       = 6,
  DT_RELA         = 7,
  DT_RELASZ       = 8,
  DT_RELAENT      = 9,
  DT_STRSZ        = 10,
  DT_SYMENT       = 11,
  DT_INIT         = 12,
  DT_FINI         = 13,
  DT_SONAME       = 14,
  DT_RPATH        = 15,
  DT_SYMBOLIC     = 16,
  DT_REL          = 17,
  DT_RELSZ        = 18,
  DT_RELENT       = 19,
  DT_PLTREL       = 20,
  DT_DEBUG        = 21,
  DT_JMPREL       = 23,
  DT_INIT_ARRAY   = 25,
  DT_FINI_ARRAY   = 26,
  DT_INIT_ARRAYSZ = 27,
  DT_FINI_ARRAYSZ = 28,
  DT_RUNPATH      = 29,
  DT_FLAGS        = 30,
  DT_FLAGS_1      = 0x6ffffffb,
  DT_VERNEED      = 0x6ffffffe,
  DT_VERNEEDNUM   = 0x6fffffff,
  DT_VERSYM       = 0x6ffffff0,
  DT_RELACOUNT    = 0x6ffffff9
} elf_dt_t;

#define SHF_WRITE     0x1
#define SHF_ALLOC     0x2
#define SHF_EXECINSTR 0x4
#define SHF_MERGE     0x10
#define SHF_STRINGS   0x20
#define SHF_INFO_LINK 0x40
#define SHF_TLS       0x400

#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

#define EM_NONE    0
#define EM_386     3
#define EM_MIPS    8
#define EM_PPC     20
#define EM_PPC64   21
#define EM_ARM     40
#define EM_X86_64  62
#define EM_AARCH64 183
#define EM_RISCV   243

typedef struct _elf_phdr_t {
  u32 type,
      flags;
  u64 offset,
      vaddr,
      paddr,
      filesz,
      memsz,
      align;
} elf_phdr_t;

typedef struct _elf_shdr_t {
  const char *name;
  u32         type,
              link,
              info;
  u64         flags,
              addr,
              offset,
              size,
              addralign,
              entsize;
  u32         _name_off;
} elf_shdr_t;

typedef struct _elf_sym_t {
  const char *name;
  u64         value,
              size;
  u8          bind,
              type,
              vis;
  u16         shndx;
} elf_sym_t;

typedef struct _elf_rela_t {
  u64 offset,
      addend;
  u32 sym,
      type;
} elf_rela_t;

typedef struct _elf_dyn_t {
  i64 tag;
  u64 val;
} elf_dyn_t;

typedef struct _elf_note_t {
  const char *name,
             *desc;
  u32         namesz,
              descsz,
              type;
} elf_note_t;

typedef struct _elf_t {
  u8          *base;
  u64          len;

  elf_class_t  class;
  elf_data_t   data;
  u8           osabi,
               abiver;

  u16          type,
               machine;
  u64          entry,
               phoff,
               shoff;
  u32          flags;
  u16          ehsize,
               phentsize,
               phnum,
               shentsize,
               shnum,
               shstrndx;

  elf_phdr_t  *phdrs;
  elf_shdr_t  *shdrs;

  elf_sym_t   *symtab;
  u32          symtab_n;
  elf_sym_t   *dynsym;
  u32          dynsym_n;

  elf_rela_t  *rela;
  u32          rela_n;
  elf_rela_t  *pltrel;
  u32          pltrel_n;

  elf_dyn_t   *dynamic;
  u32          dynamic_n;

  const char  *shstrtab;
  u64          shstrtab_sz;
  const char  *strtab;
  u64          strtab_sz;
  const char  *dynstr;
  u64          dynstr_sz;
} elf_t;

#endif
