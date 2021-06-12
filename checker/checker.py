#!/usr/bin/env python3
"""Checker script for veighty-machinery."""
import os
import random
import time
from typing import Callable, Tuple

# Pwntools requires this, otherwise it would complain about the missing terminal
os.environ['PWNLIB_NOTERM'] = '5'

import pwn
from ctf_gameserver import checkerlib

import utils
from ins_test import Ins, get_ins_sequence, get_jmp_ins_sequence
from instructions import * # pylint: disable=unused-wildcard-import,wildcard-import


pwn.context.log_level = 'warn'
pwn.context.timeout = 5


def log_time(method: Callable) -> Callable:
    """Logs the execution time for a method."""
    def timed(*args, **kw):
        start_time = time.time()

        result = method(*args, **kw)

        pwn.log.info(f'Overall duration for {method.__name__}: {int(time.time() - start_time)}s')

        return result
    return timed


class Interaction():
    """This class encapsulates the interaction with the binary."""

    PORT = 7777

    HEADER = [
        'Go program your\n' \
        '                  __\n' \
        '                 /  \\\n' \
        '           .-.  |    |\n' \
        '   *    _.-\'  \\  \\__/\n' \
        '    \\.-\'       \\\n' \
        '   /          _/\n' \
        '  |      _  /"\n' \
        '  |     /_\\\'\n' \
        '   \\    \\_/\n' \
        '    """"\n' \
        '',
        'Give me your bytecode!\n',
        'I will load the cannon and execute it.\n'
    ]

    def __init__(self, ip: str, init: bool = False) -> None:
        """Sets the ip for the new interaction."""
        self.ip = ip # pylint: disable=invalid-name
        self.proc = None

        if init:
            self.__enter__()

    def __enter__(self) -> 'Interaction':
        """Opens a connection and intializes variables."""
        try:
            self.proc = pwn.remote(self.ip, self.PORT)
        except pwn.pwnlib.exception.PwnlibException:
            # Raising a ConnectionRefusedError here is not necessarily correct.
            # Anyway, this error is handled by the checkerlib.
            raise ConnectionRefusedError('Cannot connect to target')
        return self

    def __exit__(self, exc_type: None, exc_value: object, traceback: object) -> None:
        """Closes the connection."""
        self.proc.close()

    def _execute_instructions(self, instructions: list) -> bool:
        """Sends the payload."""

        pwn.log.info(f'Executing instructions: [{", ".join([str(i) for i in instructions])}]')

        payload = b''.join([i.ins for i in instructions])

        for header in self.HEADER:
            if self.proc.recvuntil(header, drop=True):
                return False

        pwn.log.info(f'Sending payload: {payload}')
        if self.proc.recvuntil('Length:\n', drop=True):
            return False
        self.proc.sendline(str(len(payload)).encode('ascii'))
        if self.proc.recvuntil('Bytecode:\n', drop=True):
            return False
        self.proc.send(payload)

        for ins in instructions:
            # OPT: We can split this into two loops for better performance
            if ins.param:
                pwn.log.info(f'Sending param for read: {ins.param}')
                self.proc.send(ins.param)
            if ins.output:
                pwn.log.info(f'Waiting for output: {ins.output}')
                try:
                    expected = ins.output + b'\n'
                    output = self.proc.recvuntil(expected)
                    if not output:
                        pwn.log.info('Didn\'t receive output within timeout')
                        return False
                    if output != expected:
                        pwn.log.info('Didn\'t receive expected output. '
                            f'Expected: {expected} Received: {output}')
                        return False
                except EOFError:
                    pwn.log.info('Received EOF')
                    return False
        return True

    def place_key(self, key: str, value: str) -> bool:
        """Places a key. Returns True, if nothing unexpected happened."""
        # pylint: disable=undefined-variable
        pwn.log.info(f'Placing new pair: {key} = {value}')

        if len(value) > 10:
            value_first = value[:len(value)//2]
            value_second = value[len(value)//2:]

            instructions = [
                Ins(PUSHS + s(value_second.encode('ascii'))),
                Ins(PUSHS + s(value_first.encode('ascii'))),
                Ins(STRCAT),
                Ins(PUSHS + s(key.encode('ascii'))),
                Ins(WRITEFILE, output='file written'),
            ]
        else:
            instructions = [
                Ins(PUSHS + s(value.encode('ascii'))),
                Ins(PUSHS + s(key.encode('ascii'))),
                Ins(WRITEFILE, output='file written'),
            ]

        return self._execute_instructions(instructions)

    def get_key(self, key: str) -> str:
        """Returns the extracted value, None on error."""
        # pylint: disable=undefined-variable
        pwn.log.info(f'Getting key: {key}')

        if len(key) > 8:
            key_first = key[:len(key)//2]
            key_second = key[len(key)//2:]

            instructions = [
                Ins(PUSHS + s(key_second.encode('ascii'))),
                Ins(PUSHS + s(key_first.encode('ascii'))),
                Ins(STRCAT),
                Ins(READFILE),
                Ins(POPS),
            ]
        else:
            instructions = [
                Ins(PUSHS + s(key.encode('ascii'))),
                Ins(READFILE),
                Ins(POPS),
            ]

        self._execute_instructions(instructions)

        try:
            return self.proc.recvall().decode('ascii')
        except EOFError:
            return ""

    def random_test(self) -> bool:
        """Runs a random interaction and returns True, if successful."""
        pwn.log.info('Executing some random interaction')

        if random.randint(0, 1):
            instructions = get_ins_sequence()
        else:
            instructions = get_jmp_ins_sequence()

        return self._execute_instructions(instructions)


class ChallChecker(checkerlib.BaseChecker):
    """This is for checking the veighty-machinery."""

    @staticmethod
    def _get_key_for_flag(flag: str) -> str:
        """Returns a key for the given flag. Generates a fresh key, if flag is new."""
        flag_keys = checkerlib.load_state("flag_keys")
        if not flag_keys:
            flag_keys = {}

        if flag in flag_keys.keys():
            return flag_keys[flag]

        def _new_flag_key() -> str:
            """Returns a new random key for a flag."""
            return str(random.randrange(10**10, 10**11))

        new_key = _new_flag_key()
        while new_key in flag_keys.values():
            new_key = _new_flag_key()

        flag_keys[flag] = new_key
        checkerlib.store_state("flag_keys", flag_keys)

        return new_key

    @staticmethod
    def _get_new_key() -> str:
        """Returns a new key for general purpose."""
        used_keys = checkerlib.load_state("used_keys")
        if not used_keys:
            used_keys = []

        def _init_new_key() -> str:
            """Returns a new random key."""
            separator = random.choice([" ", "_", "-", ""])
            separator = ""
            return utils.get_random_string() + separator + str(random.randrange(10**3, 10**6))

        def _valid_key(key: str) -> bool:
            """Returns true, if key is a valid key."""
            return key not in used_keys and len(key) <= 24

        new_key = _init_new_key()
        while not _valid_key(new_key):
            new_key = _init_new_key()

        used_keys.append(new_key)
        checkerlib.store_state("used_keys", used_keys)

        return new_key

    @staticmethod
    def _get_new_value(flag: str = None) -> str:
        """Returns a new value to submit."""
        if flag:
            return flag
        else:
            if random.randrange(4) < 1:
                return utils.generate_suspicious_message()
            return utils.get_random_string()

    @staticmethod
    def _save_pair(key: str, item: str) -> None:
        """Saves the item in the state."""
        saved_items = checkerlib.load_state("saved_pairs")
        if not saved_items:
            saved_items = []

        saved_items.insert(0, (key, item))
        saved_items = saved_items[:10]

        pwn.log.info(f'Saving new state: {saved_items}')

        checkerlib.store_state("saved_pairs", saved_items)

    @staticmethod
    def _get_random_pair() -> Tuple[str, str]:
        """Returns a random key-value pair from the state."""
        saved_items = checkerlib.load_state("saved_pairs")
        return random.choice(saved_items) if saved_items else (None, None)


    @log_time
    def place_flag(self, tick: int) -> checkerlib.CheckResult:
        """Places a flag at the target team."""
        flag = checkerlib.get_flag(tick)

        key = self._get_key_for_flag(flag)
        value = self._get_new_value(flag=flag)

        with Interaction(self.ip) as interaction:
            if not interaction.place_key(key, value):
                return checkerlib.CheckResult.FAULTY

        return checkerlib.CheckResult.OK

    @log_time
    def check_service(self) -> checkerlib.CheckResult:
        """Checks if the service is working as expected."""
        # 1. Some random interaction
        with Interaction(self.ip) as interaction:
            if not interaction.random_test():
                return checkerlib.CheckResult.FAULTY

        # 2. Generate new key-value pair
        key = self._get_new_key()
        value = self._get_new_value()

        # Place new value
        with Interaction(self.ip) as interaction:
            if not interaction.place_key(key, value):
                pwn.log.info('Failed to place new random key-value pair')
                return checkerlib.CheckResult.FAULTY

        # Save the pair
        self._save_pair(key, value)

        # 3. Some random interaction
        with Interaction(self.ip) as interaction:
            if not interaction.random_test():
                return checkerlib.CheckResult.FAULTY

        # 4. Choose some other pair
        (other_key, other_value) = self._get_random_pair()
        if other_key:
            # Retrieve that other value
            pwn.log.info(f'Trying to retrieve value for "{other_key}": "{other_value}"')
            with Interaction(self.ip) as interaction:
                interaction.get_key(other_key)
            # We cannot check, if this is what we expect. This would yield unnecessary faulty
            # results, when it should be recovering instead.

        # 5. Some random interaction
        with Interaction(self.ip) as interaction:
            if not interaction.random_test():
                return checkerlib.CheckResult.FAULTY

        # 6. Retrieve the previous value
        pwn.log.info(f'Trying to retrieve value for previous "{key}": "{value}"')
        with Interaction(self.ip) as interaction:
            observed_value = interaction.get_key(key)
        if not observed_value or value not in observed_value:
            return checkerlib.CheckResult.FAULTY

        # All checks passed
        return checkerlib.CheckResult.OK

    @log_time
    def check_flag(self, tick: int) -> checkerlib.CheckResult:
        """Tries to retrieve a flag."""

        flag = checkerlib.get_flag(tick)

        key = self._get_key_for_flag(flag)

        with Interaction(self.ip) as interaction:
            result = interaction.get_key(key)

        if not result or flag not in result:
            return checkerlib.CheckResult.FLAG_NOT_FOUND
        return checkerlib.CheckResult.OK

if __name__ == "__main__":
    checkerlib.run_check(ChallChecker)
