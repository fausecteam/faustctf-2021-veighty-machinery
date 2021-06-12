#!/usr/bin/env python
"""Assembles random instruction sequences for veighty-machinery."""
import inspect
import random
import string
import sys
from typing import Callable, Union

import pwn

from instructions import * # pylint: disable=unused-wildcard-import,wildcard-import
from utils import get_random_string


# pylint: disable=undefined-variable


class Ins():
    """Represents one instruction of the machine."""
    def __init__(self, ins: bytes, param: bytes = None, output: Union[bytes, str] = None) -> None:
        """Sets the instructions data."""
        self.ins = ins
        self.param = param
        self.output = output.encode() if isinstance(output, str) else output

    def __str__(self) -> str:
        return 'Ins(' + str(self.ins) + ', ' + str(self.param) + ', ' + str(self.output) + ')'


def log_funcname(method: Callable) -> Callable:
    """Logs the function name for a method."""
    def log_f(*args, **kw):
        pwn.log.info(f'Generating instructions: {method.__name__}')
        return method(*args, **kw)
    return log_f


def _get_padding(length: int) -> bytes:
    """Returns some random padding bytes."""
    pad = (''.join(random.choice(string.ascii_lowercase) for i in range(length))).encode()
    if random.randint(0, 2):
        # Generate some random stuff
        new_pad = b''
        for _ in range(10):
            if len(new_pad) >= length:
                break
            new_pad += b''.join([ins.ins for ins in random.choice(_samples)()])
        else:
            new_pad += pad

    pad = pad[:length]

    assert len(pad) == length
    return pad


def _push_value(value: int) -> list:
    """Pushes a given integer value to the stack."""
    return [random.choice([
        Ins(PUSH + p_i(value)),
        Ins(READ, param=p_i(value)),
    ])]

def _pushs_value(value: bytes) -> list:
    """Pushes a given string value to the stack."""
    return [random.choice([
        Ins(PUSHS + s(value)),
        Ins(READS, param=value+b'\n'),
    ])]


@log_funcname
def _sample_nop() -> list:
    return [
        Ins(NOP),
    ]

@log_funcname
def _sample_push_pop() -> list:
    value = random.getrandbits(random.randint(5, 63))
    return [
        Ins(PUSH + p_i(value)),
        Ins(POP, output=hex(value)),
    ]

@log_funcname
def _sample_read() -> list:
    value = random.getrandbits(random.randint(5, 63))
    return [
        Ins(READ, param=p_i(value)),
        Ins(POP, output=hex(value)),
    ]

@log_funcname
def _sample_add() -> list:
    value1 = random.getrandbits(random.randint(5, 60))
    value2 = random.getrandbits(random.randint(5, 60))
    return _push_value(value2) + _push_value(value1) + [
        Ins(ADD),
        Ins(POP, output=hex(value1+value2)),
    ]

@log_funcname
def _sample_sub() -> list:
    value1 = random.getrandbits(random.randint(5, 60))
    value2 = random.getrandbits(random.randint(5, 60))
    if value1 < value2:
        value1, value2 = value2, value1
    return _push_value(value2) + _push_value(value1) + [
        Ins(SUB),
        Ins(POP, output=hex(value1-value2)),
    ]

@log_funcname
def _sample_mul() -> list:
    value1 = random.getrandbits(random.randint(5, 30))
    value2 = random.getrandbits(random.randint(5, 30))
    return _push_value(value2) + _push_value(value1) + [
        Ins(MUL),
        Ins(POP, output=hex(value1*value2)),
    ]

@log_funcname
def _sample_div() -> list:
    value1 = random.getrandbits(random.randint(5, 30))
    value2 = random.getrandbits(random.randint(5, 30))
    if value1 < value2:
        value1, value2 = value2, value1
    if not value2:
        value2 = 1
    return _push_value(value2) + _push_value(value1) + [
        Ins(DIV),
        Ins(POP, output=hex(value1//value2)),
    ]

@log_funcname
def _sample_mod() -> list:
    value1 = random.getrandbits(random.randint(5, 30))
    value2 = random.getrandbits(random.randint(5, 30))
    if value1 < value2:
        value1, value2 = value2, value1
    if not value2:
        value2 = 1
    return _push_value(value2) + _push_value(value1) + [
        Ins(MOD),
        Ins(POP, output=hex(value1%value2)),
    ]

@log_funcname
def _sample_itostr() -> list:
    value = random.getrandbits(random.randint(5, 60))
    return _push_value(value) + [
        Ins(ITOSTR),
        Ins(POPS, output=str(value)),
    ]

@log_funcname
def _sample_inc() -> list:
    value = random.getrandbits(random.randint(5, 62))
    i = random.randint(1, 15)
    incs = [Ins(INC)] * i
    return _push_value(value) + incs + [
        Ins(POP, output=hex(value+i)),
    ]

@log_funcname
def _sample_dec() -> list:
    value = random.getrandbits(random.randint(5, 62))
    if value < 100:
        value += 100
    i = random.randint(1, 15)
    decs = [Ins(DEC)] * i
    return _push_value(value) + decs + [
        Ins(POP, output=hex(value-i)),
    ]

@log_funcname
def _sample_shl() -> list:
    i = random.randint(1, 10)
    value = random.getrandbits(random.randint(5, 62-i))
    shls = [Ins(SHL)] * i
    return _push_value(value) + shls + [
        Ins(POP, output=hex(value<<i)),
    ]

@log_funcname
def _sample_shr() -> list:
    i = random.randint(1, 10)
    value = random.getrandbits(random.randint(5, 62))
    shrs = [Ins(SHR)] * i
    return _push_value(value) + shrs + [
        Ins(POP, output=hex(value>>i)),
    ]

@log_funcname
def _sample_cpy() -> list:
    if random.randint(0, 1):
        # Test with integer values
        value = random.getrandbits(random.randint(5, 62))
        return _push_value(value) + [
            Ins(CPY),
            Ins(POP, output=hex(value)),
            Ins(POP, output=hex(value)),
        ]
    else:
        # Test with string values
        s_value = get_random_string().encode()
        return _pushs_value(s_value) + [
            Ins(CPY),
            Ins(POPS, output=s_value),
            Ins(POPS, output=s_value),
        ]

@log_funcname
def _sample_swap() -> list:
    if random.randint(0, 1):
        # Test with integer values
        value1 = random.getrandbits(random.randint(5, 62))
        value2 = random.getrandbits(random.randint(5, 62))
        return _push_value(value2) + _push_value(value1) + [
            Ins(SWAP),
            Ins(POP, output=hex(value2)),
            Ins(POP, output=hex(value1)),
        ]
    else:
        # Test with string values
        s_value1 = get_random_string().encode()
        s_value2 = get_random_string().encode()
        return _pushs_value(s_value2) + _pushs_value(s_value1) + [
            Ins(SWAP),
            Ins(POPS, output=s_value2),
            Ins(POPS, output=s_value1),
        ]

@log_funcname
def _sample_pushs_pops() -> list:
    value = get_random_string().encode()
    return [
        Ins(PUSHS + s(value)),
        Ins(POPS, output=value),
    ]

@log_funcname
def _sample_reads() -> list:
    value = get_random_string().encode()
    return [
        Ins(READS, param=value+b'\n'),
        Ins(POPS, output=value),
    ]

@log_funcname
def _sample_strcat() -> list:
    value1 = get_random_string().encode()
    value2 = get_random_string().encode()
    return _pushs_value(value2) + _pushs_value(value1) + [
        Ins(STRCAT),
        Ins(POPS, output=value1+value2),
    ]

@log_funcname
def _sample_strlen() -> list:
    value = get_random_string().encode()
    return _pushs_value(value) + [
        Ins(STRLEN),
        Ins(POP, output=hex(len(value))),
    ]

@log_funcname
def _sample_strtoi() -> list:
    value = random.getrandbits(random.randint(5, 62))
    return _pushs_value(str(value).encode()) + [
        Ins(STRTOI),
        Ins(POP, output=hex(value)),
    ]


_samples = [obj for name,obj in inspect.getmembers(sys.modules[__name__])
    if (inspect.isfunction(obj) and name.startswith('_sample_'))]


def get_ins_sequence() -> list:
    """Returns a random list of instructions and expected behavior."""
    pwn.log.info('Generating list of instructions WITHOUT jmps.')
    instructions = []

    for _ in range(3):
        instructions += random.choice(_samples)()

    for _ in range(random.randint(1, 20)):
        offset = random.randint(1, len(instructions)-2)
        instructions = instructions[:offset] + random.choice(_samples)() + instructions[offset:]

    assert len(instructions) < 4096

    # OPT: test halt
    return instructions


@log_funcname
def _j_sample_jmp(ins_count: int) -> list:
    offset = random.randint(1, 30)

    return [
        Ins(JMP + p_j(ins_count + 3 + offset)),
        Ins(_get_padding(offset)),
    ]

@log_funcname
def _j_sample_lt(ins_count: int) -> list:
    offset = random.randint(1, 30)

    value1 = random.getrandbits(random.randint(5, 60))
    value2 = random.getrandbits(random.randint(5, 60))

    instructions = _push_value(value2) + _push_value(value1) + [
        Ins(LT),
    ]

    ins_count += sum([len(ins.ins) for ins in instructions])

    ins = JZ if random.randint(0, 1) else JNZ

    instructions += [
        Ins(ins + p_j(ins_count + 3 + offset)),
    ]

    if (ins == JZ and value1 < value2) or (ins == JNZ and not value1 < value2):
        instructions.append(Ins(_get_padding(offset)))
    else:
        instructions += random.choice(_samples)()

    return instructions

@log_funcname
def _j_sample_gt(ins_count: int) -> list:
    offset = random.randint(1, 30)

    value1 = random.getrandbits(random.randint(5, 60))
    value2 = random.getrandbits(random.randint(5, 60))

    instructions = _push_value(value2) + _push_value(value1) + [
        Ins(GT),
    ]

    ins_count += sum([len(ins.ins) for ins in instructions])

    ins = JZ if random.randint(0, 1) else JNZ

    instructions += [
        Ins(ins + p_j(ins_count + 3 + offset)),
    ]

    if (ins == JZ and value1 > value2) or (ins == JNZ and not value1 > value2):
        instructions.append(Ins(_get_padding(offset)))
    else:
        instructions += random.choice(_samples)()

    return instructions

@log_funcname
def _j_sample_eq(ins_count: int) -> list:
    offset = random.randint(1, 30)

    value1 = random.getrandbits(random.randint(5, 60))
    if random.randint(0, 1):
        value2 = random.getrandbits(random.randint(5, 60))
    else:
        value2 = value1

    instructions = _push_value(value2) + _push_value(value1) + [
        Ins(EQ),
    ]

    ins_count += sum([len(ins.ins) for ins in instructions])

    ins = JZ if random.randint(0, 1) else JNZ

    instructions += [
        Ins(ins + p_j(ins_count + 3 + offset)),
    ]

    if (ins == JZ and value1 == value2) or (ins == JNZ and not value1 == value2):
        instructions.append(Ins(_get_padding(offset)))
    else:
        instructions += random.choice(_samples)()

    return instructions

@log_funcname
def _j_sample_strcmp(ins_count: int) -> list:
    offset = random.randint(1, 30)

    value1 = get_random_string().encode()
    if random.randint(0, 1):
        value2 = get_random_string().encode()
    else:
        value2 = value1

    instructions = _pushs_value(value2) + _pushs_value(value1) + [
        Ins(STRCMP),
    ]

    ins_count += sum([len(ins.ins) for ins in instructions])

    ins = JZ if random.randint(0, 1) else JNZ

    instructions += [
        Ins(ins + p_j(ins_count + 3 + offset)),
    ]

    if (ins == JZ and value1 == value2) or (ins == JNZ and not value1 == value2):
        instructions.append(Ins(_get_padding(offset)))
    else:
        instructions += random.choice(_samples)()

    return instructions

@log_funcname
def _j_sample_instr(ins_count: int) -> list:
    offset = random.randint(1, 30)

    value1 = get_random_string().encode()
    value2 = get_random_string().encode()
    if random.randint(0, 1):
        value1 = value1[:len(value1)//2] + value2 + value1[len(value1)//2:]

    instructions = _pushs_value(value2) + _pushs_value(value1) + [
        Ins(INSTR),
    ]

    ins_count += sum([len(ins.ins) for ins in instructions])

    ins = JZ if random.randint(0, 1) else JNZ

    instructions += [
        Ins(ins + p_j(ins_count + 3 + offset)),
    ]

    if (ins == JZ and value2 in value1) or (ins == JNZ and not value2 in value1):
        instructions.append(Ins(_get_padding(offset)))
    else:
        instructions += random.choice(_samples)()

    return instructions


_j_samples = [obj for name,obj in inspect.getmembers(sys.modules[__name__])
    if (inspect.isfunction(obj) and name.startswith('_j_sample_'))]


def get_jmp_ins_sequence() -> list:
    """Returns a random list of instructions and expected behavior (with compares and jumps)."""
    pwn.log.info('Generating list of instructions WITH jmps.')
    instructions = []

    for _ in range(3):
        instructions += random.choice(_samples)()

    ins_count = sum([len(ins.ins) for ins in instructions])

    instructions += random.choice(_j_samples)(ins_count)

    for _ in range(2):
        instructions += random.choice(_samples)()

    assert len(instructions) < 4096
    return instructions
