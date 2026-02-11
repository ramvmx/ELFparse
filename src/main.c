/*
 * Copyright (C) 2026 ramvma
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

/** @brief Command-line option flags. */
typedef struct _opt_t {
  unsigned all      : 1,
           header   : 1,
           programs : 1,
           sections : 1,
           symbols  : 1,
           dynsyms  : 1,
           relocs   : 1,
           dynamic  : 1;
  const char *hexdump;
} opt_t;

/**
 * @brief Prints the usage message and exits.
 * @param prog The program name (argv[0]).
*/

static void _usage(const char *prog) {
  fprintf(stderr,
    "usage: %s [options] <elf-file>\n"
    "  -a          all\n"
    "  -h          ELF header\n"
    "  -l          program headers\n"
    "  -S          section headers\n"
    "  -s          symbol table\n"
    "  -d          dynamic symbols\n"
    "  -r          relocations\n"
    "  -D          dynamic section\n"
    "  -x <n>   hex dump section\n",
    prog);
  exit(1);
}

/**
 * @brief Dispatches a single command-line flag character.
 * @param i Pointer to the current argv index (may be incremented for -x).
 * @param argc Total argument count.
 * @param argv Argument vector.
 * @param opt The options struct to populate.
 * @param flag The flag character to process.
*/

static void _parse_flag(int *i, int argc, char **argv,
                         opt_t *opt, char flag) {
  switch (flag) {
    case 'a': opt->all      = 1; break;
    case 'h': opt->header   = 1; break;
    case 'l': opt->programs = 1; break;
    case 'S': opt->sections = 1; break;
    case 's': opt->symbols  = 1; break;
    case 'd': opt->dynsyms  = 1; break;
    case 'r': opt->relocs   = 1; break;
    case 'D': opt->dynamic  = 1; break;
    case 'x':
      ASSERT(*i + 1 < argc, "-x requires a section name");
      opt->hexdump = argv[++(*i)];
      break;
    default:
      _usage(argv[0]);
  }
}

/**
 * @brief Entry point: parses arguments, loads the ELF file, and dumps output.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success.
*/

int main(int argc, char **argv) {
  opt_t opt        = {0};
  const char *path = NULL;

  if (argc < 2) _usage(argv[0]);

  for (int i = 1; i < argc; ++i) {
    if (argv[i][0] != '-' || !argv[i][1]) {
      path = argv[i];
      continue;
    }
    for (const char *c = argv[i] + 1; *c; ++c)
      _parse_flag(&i, argc, argv, &opt, *c);
  }

  if (!path) _usage(argv[0]);

  int any = opt.header   | opt.programs | opt.sections |
            opt.symbols  | opt.dynsyms  | opt.relocs   |
            opt.dynamic  | (opt.hexdump != NULL);
  if (!any) opt.all = 1;

  elf_t *e = elf_parse(path);

  if (opt.all)                        elf_dump_all(e);
  else {
    if (opt.header)                   elf_dump_ehdr(e);
    if (opt.programs)                 elf_dump_phdrs(e);
    if (opt.sections)                 elf_dump_shdrs(e);
    if (opt.symbols)                  elf_dump_symtab(e);
    if (opt.dynsyms)                  elf_dump_dynsym(e);
    if (opt.relocs)                   elf_dump_rela(e);
    if (opt.dynamic)                  elf_dump_dynamic(e);
  }
  if (opt.hexdump)                    elf_dump_hex(e, opt.hexdump);

  elf_unmap(e);
  return 0;
}
