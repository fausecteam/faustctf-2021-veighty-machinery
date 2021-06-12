#!/usr/bin/env python
import sys

from pwn import p64, p16, p8
from pycparser import parse_file

def s(string):
    return p8(len(string)) + string

header = parse_file("src/include/opcodes.h", use_cpp=True)
instructions = [x.name[4:].upper() for x in header.ext[0].type.type.values.enumerators]

for i, instruction in enumerate(instructions):
    exec(f'{instruction} = ({i}).to_bytes(1, byteorder="big")')


payload = PUSH + p64(4333333333333333335)
payload += PUSH + p64(4777777777777777775)
payload += PUSH + p64(0x61)
payload += PUSH + p64(0x62)

payload += NOP

payload += CPY
payload += INC
payload += ADD

#payload += GT
#payload += JZ + p16(38)

#payload += JMP + p16(39)

payload += PUSHS + p8(8) + b'A'*8
payload += PUSHS + p8(8) + b'B'*8
payload += PUSHS + p8(8) + b'B'*8
payload += POPS
payload += STRCAT
payload += POPS

payload += PUSHS + p8(1) + b'2'
payload += PUSHS + p8(1) + b'4'
payload += STRCAT
payload += STRTOI
payload += POP


payload += PUSHS + p8(8) + b'A'*8
payload += PUSHS + p8(8) + b'B'*8
payload += STRCMP

payload += PUSHS + p8(8) + b'C'*8
payload += PUSHS + p8(8) + b'C'*8
payload += STRCMP

payload += PUSHS + p8(2) + b'DD'
payload += PUSHS + p8(8) + b'D'*8
payload += INSTR

payload += PUSHS + p8(2) + b'Ee'
payload += PUSHS + p8(10) + b'E'*10
payload += INSTR


payload += PUSHS + s(b'This is the file content.\n')
payload += PUSHS + s(b'filename')
payload += WRITEFILE

payload += PUSHS + s(b'filename2')
payload += READFILE
payload += POPS


payload += PUSH + p64(0x62)
payload += ITOSTR
payload += POPS


payload += READS
payload += POPS

payload += READ
payload += POP








payload += NOP*10
payload += POP*10

sys.stdout.buffer.write(str(len(payload)).encode('ascii') + b'\n')
sys.stdout.buffer.write(payload)
