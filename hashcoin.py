from collections import namedtuple
from hashlib import sha1
from itertools import count, combinations_with_replacement


def iter_bytes():
    """Iterate through all possible bytes objects, starting with b''.

    >>> from itertools import islice
    >>> list(islice(iter_bytes(), 7))
    [b'', b'\\x00', b'\\x01', b'\\x02', b'\\x03', b'\\x04', b'\\x05']
    >>> list(islice(iter_bytes(), 255, 259))
    [b'\\xfe', b'\\xff', b'\\x00\\x00', b'\\x00\\x01']
    >>> list(islice(iter_bytes(), 0))
    []
    """
    for num_bytes in count():
        value_combos = combinations_with_replacement(range(256), num_bytes)
        for values in value_combos:
            yield bytes(values)


def leading_zeros(b):
    """
    >>> leading_zeros(b'')
    0
    >>> leading_zeros(b'\\x00')
    1
    >>> leading_zeros(b'\\x01')
    0
    >>> leading_zeros(b'\\x02')
    0
    >>> leading_zeros(b'\\x00\\x01')
    1
    >>> leading_zeros(b'\\x00\\x10')
    1
    >>> leading_zeros(b'\\x00\\x00\\x10')
    2
    >>> leading_zeros(b'\\x00\\x01\\x00')
    1
    """
    zeros = 0
    for byte in b:
        if not byte:
            zeros += 1
        else:
            break
    return zeros


class Hashcoin(namedtuple('Hashcoin', ['data', 'salt'])):
    """Hashcash-inspired proof-of-work token."""

    @classmethod
    def new(cls, min_value, data):
        return next(cls.mine(min_value, data))

    @classmethod
    def mine(cls, min_value, data):
        for salt in iter_bytes():
            c = Hashcoin(data, salt)
            if c.value >= min_value:
                yield c

    @property
    def digest(self):
        return sha1(self.data + self.salt).digest()

    @property
    def value(self):
        return leading_zeros(self.digest)
