```
                     

    ┌─────────────────────────────────────┐
    │  7f 45 4c 46 02 01 01 00           │
    │  .ELF........................       │
    │  >> parsing the bones of binaries  │
    └─────────────────────────────────────┘
```

## Features

- **ELF32 & ELF64** support with automatic detection
- **Big & Little Endian** decoding via endian-aware readers
- **Zero-copy** parsing through memory-mapped I/O (`mmap`)
- **Self-contained** ELF type definitions — no reliance on system `<elf.h>`
- **Colorized** terminal output with semantic highlighting
- **Packed raw structs** for direct, safe casting from the mapped file
- **Bounds-checked** access on every read — no silent overflows

## Building

Requires `gcc` and `make` on a Linux system (native or WSL).

```
make
```

To rebuild from scratch:

```
make clean && make
```

The default build uses `-O3 -march=native -flto` for maximum optimization.

## Usage

```
./elfparse [options] <elf-file>
```

| Flag | Description |
|------|-------------|
| `-a` | Dump everything (default if no flags given) |
| `-h` | ELF header |
| `-l` | Program headers (segments) |
| `-S` | Section headers |
| `-s` | Symbol table (`.symtab`) |
| `-d` | Dynamic symbols (`.dynsym`) |
| `-r` | Relocations (`.rela.*`) |
| `-D` | Dynamic section (`.dynamic`) |
| `-x <name>` | Hex dump of a section (e.g. `-x .text`) |

Flags can be combined:

```
./elfparse -h -l -D /usr/bin/ls
./elfparse -s -x .rodata ./my_binary
```

## Examples

Parse the ELF header:

```
$ ./elfparse -h /usr/bin/ls
━━━ ELF Header ━━━
  Magic:       7f 45 4c 46
  Class:       ELF64
  Encoding:    Little Endian
  OS/ABI:      UNIX System V
  Type:        DYN
  Machine:     AMD x86-64
  Entry:       0x6d30
  ...
```

Parse itself:

```
$ ./elfparse ./elfparse
```

## Project Structure

```
elfparse/
├── include/
│   ├── types.h          Base typedefs (u8–u64), macros (DIE, ASSERT)
│   ├── elf_types.h      Self-contained ELF structures and enums
│   ├── elf_read.h       Memory-mapped file access, endian-aware readers
│   ├── elf_parse.h      Parsing interface
│   └── elf_dump.h       Display/output interface
├── src/
│   ├── elf_read.c       mmap, bounds checking, r16/r32/r64, string table
│   ├── elf_parse.c      Packed raw structs → parsed structs (32/64)
│   ├── elf_dump.c       Colorized output, lookup tables, hex dump
│   └── main.c           CLI argument handling and entry point
└── Makefile
```

## How It Works

```
  ┌──────────────┐     mmap      ┌──────────────────┐
  │              │  ──────────>  │   Virtual Memory   │
  │   ELF File   │   read-only  │                    │
  │   on disk    │              │  ┌──────────────┐  │
  │              │              │  │  ELF Header   │──┼──> elf_t
  └──────────────┘              │  ├──────────────┤  │
                                │  │  Program Hdrs │──┼──> elf_phdr_t[]
                                │  ├──────────────┤  │
         elf_r16/32/64          │  │  Sections     │──┼──> elf_shdr_t[]
       ┌─────────────┐         │  ├──────────────┤  │
       │ endian-aware │         │  │  .symtab     │──┼──> elf_sym_t[]
       │   decoding   │         │  ├──────────────┤  │
       └─────────────┘         │  │  .dynamic    │──┼──> elf_dyn_t[]
                                │  ├──────────────┤  │
       every access is          │  │  .rela.*     │──┼──> elf_rela_t[]
       bounds-checked           │  └──────────────┘  │
                                └──────────────────┘
```

1. The ELF file is memory-mapped read-only via `mmap` — no heap copies of file data
2. A set of packed raw structs (`raw_ehdr64_t`, `raw_phdr64_t`, etc.) mirror the on-disk layout exactly and are cast directly from the mapped region
3. Endian-aware reader functions (`elf_r16`, `elf_r32`, `elf_r64`) decode fields based on the ELF's declared byte order
4. Every access is bounds-checked against the file size before dereferencing
5. Parsed data is stored in clean, normalized structs that abstract away the 32/64-bit differences

## Color Coding

Output is color-coded by semantic meaning:

| Color | Meaning |
|-------|---------|
| Green | Executable sections, `LOAD` segments, `FUNC` symbols |
| Yellow | Symbol tables, `OBJECT` symbols, `DYNAMIC` segments |
| Magenta | Dynamic section, `INTERP` segment, shared library names |
| Red | Weak symbols |
| Cyan | Section titles, entry point address |

---


## License

This project is licensed under the [GNU General Public License v2.0](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html).
