
#ifndef UTIL_H
#define UTIL_H

void die(const char *msg);

#define min(a,b) \
  ({ __typeof__ (a) _a = (a); \
      __typeof__ (b) _b = (b); \
      _a < _b ? _a : _b; })

#define DATA_DIR "data/"

#endif
