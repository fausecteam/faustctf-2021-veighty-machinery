FAUST CTF 2021 Challenge: veighty-machinery
===========================================

### General
A simple stack-based virtual machine in C.

### Build
Build:
```bash
$ make -C chall
```

### Vulnerability
The `swap` instruction fails to check if there are at least two values on the stack.
This allows the modification of the stack pointer, which is stored in front of the stack.
Subsequently, out-of-bound access on the heap is possible.
