
#ifndef CPU_H
#define CPU_H

#include <stdint.h>
#include <stdbool.h>

#include "opcodes.h"

#define MAX_PROG_SIZE 4096
#define STACK_SIZE 4096
#define MAX_INSTR 4096

#define MAX_FILESIZE 4096ul
#define MAX_FNAME_LENGTH 256
#define MAX_STR_INPUT 4096

struct cpu {
  uint64_t ip;
  uint64_t sp;
  uint64_t stack[STACK_SIZE];
  unsigned char program[MAX_PROG_SIZE];
  bool halt : 1;
  bool cmp : 1;
  unsigned int prog_length;
};

extern struct cpu *cpu;

void cpu_init();
void cpu_run();


#endif
