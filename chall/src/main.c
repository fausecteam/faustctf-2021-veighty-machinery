#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "util.h"
#include "cpu.h"

void print_header() {
  char *header = "Go program your\n"
"                  __\n"
"                 /  \\\n"
"           .-.  |    |\n"
"   *    _.-'  \\  \\__/\n"
"    \\.-'       \\\n"
"   /          _/\n"
"  |      _  /\"\n"
"  |     /_\\'\n"
"   \\    \\_/\n"
"    \"\"\"\"";
  printf("%s\n", header);
  sleep(1);
}

int main(void) {
  char cmd_buf[100];

  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);

#ifndef DEBUG
  alarm(45);
#endif

  print_header();
  printf("Give me your bytecode!\n");
  sleep(1);
  printf("I will load the cannon and execute it.\n");
  sleep(1);

  printf("Length:\n");
  if (!fgets(cmd_buf, sizeof(cmd_buf), stdin)) {
    die("fgets");
  }

  cpu_init();

  cpu->prog_length = atoi(cmd_buf);
  if (cpu->prog_length >= MAX_PROG_SIZE) {
    die("invalid prog_length");
  }

  printf("Bytecode:\n");
  for (unsigned int i = 0; i < cpu->prog_length; i++) {
    int c = getchar();
    if (c == EOF) {
      die("Failed to read input");
    }
    cpu->program[i] = c;
  }

  cpu_run();

  exit(EXIT_SUCCESS);
}
