#ifndef _TYPES_H
#define _TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t  i32;
typedef int64_t  i64;

#define PACKED __attribute__((packed))

#define DIE(fmt, ...)                                                          \
  do {                                                                         \
    fprintf(stderr, "\x1b[1;31melfparse:\x1b[0m " fmt "\n",                   \
            ##__VA_ARGS__);                                                    \
    exit(1);                                                                   \
  } while (0)

#define ASSERT(cond, fmt, ...)                                                 \
  do { if (!(cond)) DIE(fmt, ##__VA_ARGS__); } while (0)

#define ARRLEN(a) (sizeof(a) / sizeof(*(a)))

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define SAFE_STR(tbl, idx)                                                     \
  ((u64)(idx) < ARRLEN(tbl) && (tbl)[(idx)] ? (tbl)[(idx)] : "???")

#endif
