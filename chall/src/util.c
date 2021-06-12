#include <stdio.h>
#include <stdlib.h>

#include "util.h"

void die(const char *msg) {
  fprintf(stderr, "%s\n", msg);
  exit(EXIT_FAILURE);
}
