#!/usr/bin/env python
"""Parses the instruction set for veighty-machinery."""
import os
import pathlib

import pwn
import pycparser


def s(string): # pylint: disable=invalid-name
    """Packs a string for string instructions."""
    return pwn.p8(len(string)) + string

def p_i(value):
    """Packs an integer for integer instructions."""
    return pwn.p64(value)

def p_j(value):
    """Packs an integer for jmp instructions."""
    return pwn.p16(value)

_header = pycparser.parse_file(pathlib.Path(os.path.abspath(__file__)).parent /
        "../chall/src/include/opcodes.h", use_cpp=True)
_instructions = [x.name[4:].upper() for x in _header.ext[0].type.type.values.enumerators]

for _i, _instruction in enumerate(_instructions):
    exec(f'{_instruction} = ({_i}).to_bytes(1, byteorder="big")') # pylint: disable=exec-used
