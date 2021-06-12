#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

#include "cpu.h"
#include "util.h"

#define assert(cond) { \
  if (!(cond)) { \
    fprintf(stderr, "assert failed\n"); \
    cpu->halt = true; \
    return; \
  } \
}

#define PTR_MASK (1ul<<63)

#define IS_PTR(ptr) (((uint64_t)ptr & PTR_MASK) == PTR_MASK)
#define MASK_PTR(ptr) ((uint64_t)ptr ^ PTR_MASK)
#define UNMASK_PTR(ptr) ({uint64_t _ptr = ptr; assert(IS_PTR(_ptr)); (void *)(_ptr ^ PTR_MASK);})


#define ASSERT_N(n) { \
  assert(!(cpu->sp < n)); \
}

#define ASSERT_ONE_FREE() { \
  assert(cpu->sp != STACK_SIZE); \
}

#define ASSERT_N_INTS(n) { \
  ASSERT_N(n); \
  for (int i = 0; i<n; i++) { \
    assert(!IS_PTR(cpu->stack[cpu->sp-i-1])); \
  } \
}


#ifdef DEBUG

#define PRINT_CPU { \
  if (getenv("DEBUG")) { \
    printf("Executing instruction %d (0x%x)\n", instruction, instruction);  \
    printf("{ip: %d, sp: %d, halt: %d, cmp: %d}\n", cpu->ip, cpu->sp, cpu->halt, cpu->cmp); \
  } \
}

#define LOG_INS(i) { printf(i "\n"); }

#else

#define PRINT_CPU {}
#define LOG_INS(i) {}

#endif

struct cpu *cpu;


void exec_nop(void) {
  LOG_INS("NOP");
}

void exec_push(void) {
  LOG_INS("PUSH");
  ASSERT_ONE_FREE();
  uint64_t value = *((uint64_t *)&cpu->program[cpu->ip]);

  value = value & ~PTR_MASK;

  cpu->stack[cpu->sp++] = value;
  cpu->ip += 8;
}

void exec_pop(void) {
  LOG_INS("POP");
  ASSERT_N_INTS(1);
  uint64_t value = cpu->stack[--cpu->sp];
  printf("0x%lx\n", value);
}

void exec_read(void) {
  LOG_INS("READ");
  ASSERT_ONE_FREE();

  uint64_t value;

  assert(read(STDIN_FILENO, &value, sizeof(value)) == sizeof(value));

  value = value & ~PTR_MASK;

  cpu->stack[cpu->sp++] = value;
}

void exec_add(void) {
  LOG_INS("ADD");
  ASSERT_N_INTS(2);
  cpu->sp--;
  cpu->stack[cpu->sp-1] = cpu->stack[cpu->sp] + cpu->stack[cpu->sp-1];
  ASSERT_N_INTS(1);
}

void exec_sub(void) {
  LOG_INS("SUB");
  ASSERT_N_INTS(2);
  cpu->sp--;
  cpu->stack[cpu->sp-1] = cpu->stack[cpu->sp] - cpu->stack[cpu->sp-1];
  ASSERT_N_INTS(1);
}

void exec_mul(void) {
  LOG_INS("MUL");
  ASSERT_N_INTS(2);
  cpu->sp--;
  cpu->stack[cpu->sp-1] = cpu->stack[cpu->sp] * cpu->stack[cpu->sp-1];
  ASSERT_N_INTS(1);
}

void exec_div(void) {
  LOG_INS("DIV");
  ASSERT_N_INTS(2);
  cpu->sp--;
  assert(cpu->stack[cpu->sp-1] != 0);
  cpu->stack[cpu->sp-1] = cpu->stack[cpu->sp] / cpu->stack[cpu->sp-1];
  ASSERT_N_INTS(1);
}

void exec_mod(void) {
  LOG_INS("MOD");
  ASSERT_N_INTS(2);
  cpu->sp--;
  assert(cpu->stack[cpu->sp-1] != 0);
  cpu->stack[cpu->sp-1] = cpu->stack[cpu->sp] % cpu->stack[cpu->sp-1];
  ASSERT_N_INTS(1);
}

void exec_itostr(void) {
  LOG_INS("MOD");
  ASSERT_N_INTS(1);

  uint64_t value = cpu->stack[--cpu->sp];
  uint64_t len = snprintf(NULL, 0, "%ld", value);
  assert(len < 64);

  char *buf = malloc(len+1);
  assert(buf);

  snprintf(buf, len+1, "%ld", value);

  cpu->stack[cpu->sp++] = MASK_PTR(buf);
}

// OPT: jmp_rel
void exec_jmp(void) {
  LOG_INS("JMP");
  cpu->ip = *((uint16_t *)&cpu->program[cpu->ip]);
}

void exec_lt(void) {
  LOG_INS("LT");
  ASSERT_N_INTS(2);
  cpu->sp -= 2;
  cpu->cmp = !(cpu->stack[cpu->sp+1] < cpu->stack[cpu->sp]);
}

void exec_gt(void) {
  LOG_INS("GT");
  ASSERT_N_INTS(2);
  cpu->sp -= 2;
  cpu->cmp = !(cpu->stack[cpu->sp+1] > cpu->stack[cpu->sp]);
}

void exec_eq(void) {
  LOG_INS("EQ");
  ASSERT_N_INTS(2);
  cpu->sp -= 2;
  cpu->cmp = !(cpu->stack[cpu->sp+1] == cpu->stack[cpu->sp]);
}

void exec_jnz(void) {
  LOG_INS("JNZ");
  if (cpu->cmp) {
    cpu->ip = *((uint16_t *)&cpu->program[cpu->ip]);
  } else {
    cpu->ip += 2;
  }
}

void exec_jz(void) {
  LOG_INS("JZ");
  if (!cpu->cmp) {
    cpu->ip = *((uint16_t *)&cpu->program[cpu->ip]);
  } else {
    cpu->ip += 2;
  }
}

void exec_inc(void) {
  LOG_INS("INC");
  ASSERT_N_INTS(1);
  cpu->stack[cpu->sp-1]++;
  ASSERT_N_INTS(1);
}

void exec_dec(void) {
  LOG_INS("DEC");
  ASSERT_N_INTS(1);
  cpu->stack[cpu->sp-1]--;
  ASSERT_N_INTS(1);
}

void exec_shl(void) {
  LOG_INS("SHL");
  ASSERT_N_INTS(1);
  cpu->stack[cpu->sp-1] = cpu->stack[cpu->sp-1] << 1;
  ASSERT_N_INTS(1);
}

void exec_shr(void) {
  LOG_INS("SHR");
  ASSERT_N_INTS(1);
  cpu->stack[cpu->sp-1] = cpu->stack[cpu->sp-1] >> 1;
  ASSERT_N_INTS(1);
}

void exec_cpy(void) {
  LOG_INS("CPY");
  ASSERT_N(1);
  ASSERT_ONE_FREE();
  uint64_t value = cpu->stack[cpu->sp-1];
  if (IS_PTR(value)) {
    void *buf = strdup(UNMASK_PTR(value));
    assert(buf);
    cpu->stack[cpu->sp] = MASK_PTR(buf);
  } else {
    cpu->stack[cpu->sp] = cpu->stack[cpu->sp-1];
  }
  cpu->sp++;
}

void exec_swap(void) {
  LOG_INS("SWAP");
  // This is THE vulnerability (should be 2 instead of 1)
  //ASSERT_N(2);
  ASSERT_N(1);

  uint64_t tmp = cpu->stack[cpu->sp-1];
  cpu->stack[cpu->sp-1] = cpu->stack[cpu->sp-2];
  cpu->stack[cpu->sp-2] = tmp;
}

void exec_pushs(void) {
  LOG_INS("PUSHS");
  ASSERT_ONE_FREE();

  uint8_t len = cpu->program[cpu->ip++];
  assert(cpu->ip + len <= cpu->prog_length);

  char *buf = malloc(len+1);
  assert(buf);

  cpu->stack[cpu->sp++] = MASK_PTR(buf);
  strncpy(buf, (char *) &cpu->program[cpu->ip], len);
  buf[len] = '\0';
  cpu->ip += len;
}

void exec_pops(void) {
  LOG_INS("POPS");
  ASSERT_N(1);

  char *buf = UNMASK_PTR(cpu->stack[--cpu->sp]);
  printf("%s\n", buf);
  free(buf);
}

void exec_reads(void) {
  LOG_INS("READS");
  ASSERT_ONE_FREE();

  char tmp_buf[MAX_STR_INPUT];
  assert(fgets(tmp_buf, MAX_STR_INPUT, stdin) && strlen(tmp_buf)>1);

  char *buf = malloc(strlen(tmp_buf)+1);
  assert(buf);

  strcpy(buf, tmp_buf);

  if (buf[strlen(buf)-1] == '\n') {
    buf[strlen(buf)-1] = '\0';
  }

  cpu->stack[cpu->sp++] = MASK_PTR(buf);
}

void exec_strcat(void) {
  LOG_INS("STRCAT");
  ASSERT_N(2);

  char *buf1 = UNMASK_PTR(cpu->stack[--cpu->sp]);
  char *buf2 = UNMASK_PTR(cpu->stack[--cpu->sp]);

  char *buf = malloc(strlen(buf1) + strlen(buf2) + 1);
  assert(buf);

  cpu->stack[cpu->sp++] = MASK_PTR(buf);

  buf[0] = '\0';
  strcat(buf, buf1);
  strcat(buf, buf2);

  free(buf1);
  free(buf2);
}

void exec_strlen(void) {
  LOG_INS("STRLEN");
  ASSERT_N(1);

  char *buf = UNMASK_PTR(cpu->stack[--cpu->sp]);
  cpu->stack[cpu->sp++] = strlen(buf);
  free(buf);
}

void exec_strtoi(void) {
  LOG_INS("STRTOI");
  ASSERT_N(1);

  char *buf = UNMASK_PTR(cpu->stack[--cpu->sp]);
  cpu->stack[cpu->sp++] = atol(buf);
  free(buf);
  ASSERT_N_INTS(1);
}

void exec_strcmp(void) {
  LOG_INS("STRCMP");
  ASSERT_N(2);

  char *buf1 = UNMASK_PTR(cpu->stack[--cpu->sp]);
  char *buf2 = UNMASK_PTR(cpu->stack[--cpu->sp]);

  cpu->cmp = strcmp(buf1, buf2) != 0;

  free(buf1);
  free(buf2);
}

void exec_instr(void) {
  LOG_INS("INSTR");
  ASSERT_N(2);

  char *buf1 = UNMASK_PTR(cpu->stack[--cpu->sp]);
  char *buf2 = UNMASK_PTR(cpu->stack[--cpu->sp]);

  cpu->cmp = strstr(buf1, buf2) == 0;

  free(buf1);
  free(buf2);
}

void exec_writefile(void) {
  LOG_INS("WRITEFILE");
  ASSERT_N(2);

  char *fname = UNMASK_PTR(cpu->stack[--cpu->sp]);
  char *content = UNMASK_PTR(cpu->stack[--cpu->sp]);

  // assert there is no bad character in fname
  assert(strlen(fname) <= MAX_FNAME_LENGTH);
  for (unsigned int i = 0; i<strlen(fname); i++) {
    assert(isascii(fname[i]) && isalnum(fname[i]));
  }

  char fpath[strlen(fname) + strlen(DATA_DIR) + 1];
  fpath[0] = '\0';
  strcat(fpath, DATA_DIR);
  strcat(fpath, fname);

  FILE *fptr = fopen(fpath, "w");
  assert(fptr);

  assert(fwrite(content, sizeof(char), min(strlen(content), MAX_FILESIZE), fptr));

  sleep(1);
  printf("file written\n");

  fclose(fptr);
  free(fname);
  free(content);
}

void exec_readfile(void) {
  LOG_INS("READFILE");
  ASSERT_N(1);

  char *fname = UNMASK_PTR(cpu->stack[--cpu->sp]);

  // assert there is no bad character in fname
  assert(strlen(fname) <= MAX_FNAME_LENGTH);
  for (unsigned int i = 0; i<strlen(fname); i++) {
    assert(isascii(fname[i]) && isalnum(fname[i]));
  }

  char fpath[strlen(fname) + strlen(DATA_DIR) + 1];
  fpath[0] = '\0';
  strcat(fpath, DATA_DIR);
  strcat(fpath, fname);

  FILE *fptr = fopen(fpath, "r");
  assert(fptr);

  // obtain file size
  fseek(fptr, 0, SEEK_END);
  size_t fsize = min((unsigned long) ftell(fptr), MAX_FILESIZE);
  rewind(fptr);

  // create new buffer
  char *buf = malloc(fsize+1);
  assert(buf);

  // read content
  size_t size = fread(buf, sizeof(char), fsize, fptr);
  assert(size == fsize);
  buf[size] = '\0';

  cpu->stack[cpu->sp++] = MASK_PTR(buf);

  fclose(fptr);
  free(fname);
}

void exec_halt(void) {
  LOG_INS("HALT");
  cpu->halt = true;
}


// TODO: Check if the array actually is read only or replace with switch-case
static void (*const dispatch[]) (void) = { FOREACH_INSTRUCTION(GENERATE_SYMBOL_LIST) };

static void execute(unsigned char instruction) {
  PRINT_CPU;

  if (instruction < NUM_INSTRUCTIONS) {
    dispatch[(unsigned int) instruction]();
  } else {
    exec_halt();
  }
}

void cpu_init() {
  cpu = malloc(sizeof(struct cpu));
  if (!cpu) {
    die("malloc failed");
  }

  memset(cpu, 0, sizeof(struct cpu));
}

void cpu_run() {
  for (int i = 0; i < MAX_INSTR; i++) {
    if (cpu->halt || cpu->ip >= cpu->prog_length) {
      break;
    }

    unsigned char instruction = cpu->program[cpu->ip];
    cpu->ip++;
    execute(instruction);
  }
}
