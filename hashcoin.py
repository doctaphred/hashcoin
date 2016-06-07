import hashlib
from collections import namedtuple
from itertools import count, combinations_with_replacement, islice


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


def intify(b, byteorder='big'):
    return int.from_bytes(b, byteorder=byteorder)


class Hashcoin(namedtuple('Hashcoin', ['data', 'salt'])):
    """Hashcash-inspired proof-of-work token.

    >>> c = Hashcoin.new(0.00001, b'test')
    >>> c
    Hashcoin(data=b'test', salt=b'F\\xef')
    >>> c.digest().hex()
    '000048714ba75a1a1d03d8968dece7caf560c62e'
    >>> c.percentile()
    4.317913093217246e-06
    """

    hash = hashlib.sha1

    @classmethod
    def new(cls, max_percentile, data):
        return next(cls.mine(max_percentile, data))

    @classmethod
    def mine(cls, max_percentile, data):
        data_hash = cls.hash(data)
        max_digest_value = intify(cls.max_digest())
        for salt in iter_bytes():
            full_hash = data_hash.copy()
            full_hash.update(salt)
            digest_value = intify(full_hash.digest())
            if digest_value / max_digest_value <= max_percentile:
                yield cls(data, salt)

    @classmethod
    def refine(cls, data):
        data_hash = cls.hash(data)
        min_digest_value = intify(cls.max_digest())
        for salt in iter_bytes():
            full_hash = data_hash.copy()
            full_hash.update(salt)
            digest_value = intify(full_hash.digest())
            if digest_value < min_digest_value:
                min_digest_value = digest_value
                yield cls(data, salt)

    @classmethod
    def best(cls, n, data):
        data_hash = cls.hash(data)
        min_digest_value = intify(cls.max_digest())
        min_salt = b''
        for salt in islice(iter_bytes(), n):
            full_hash = data_hash.copy()
            full_hash.update(salt)
            digest_value = intify(full_hash.digest())
            if digest_value < min_digest_value:
                min_digest_value = digest_value
                min_salt = salt
        return cls(data, min_salt)

    @classmethod
    def max_digest(cls):
        return bytes([0xff] * cls.hash().digest_size)

    def digest(self):
        h = self.hash(self.data)
        h.update(self.salt)
        return h.digest()

    def percentile(self):
        return intify(self.digest()) / intify(self.max_digest())
