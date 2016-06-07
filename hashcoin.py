import hashlib
from collections import namedtuple
from itertools import count, combinations_with_replacement, islice


def iter_bytes():
    """Iterate through all possible bytes objects, starting with b''.

    >>> [b.hex() for b in islice(iter_bytes(), 11)]
    ['', '00', '01', '02', '03', '04', '05', '06', '07', '08', '09']
    >>> [b.hex() for b in islice(iter_bytes(), 255, 259)]
    ['fe', 'ff', '0000', '0001']
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

    >>> c = Hashcoin.new(1e-4, b'ayy')
    >>> c.salt.hex()
    '0891'
    >>> c.digest().hex()
    '0006057b44e5e9e7382819dd37610810260e89e6'
    >>> c.percentile()
    9.187945843050359e-05
    """

    hash = hashlib.sha1

    @classmethod
    def salts(cls):
        yield from iter_bytes()

    @classmethod
    def max_digest(cls):
        return bytes([0xff] * cls.hash().digest_size)

    @classmethod
    def percentile_digest(cls, percentile):
        max_digest_value = int.from_bytes(cls.max_digest(), 'big')
        percentile_digest_value = int(percentile * (max_digest_value + 1))
        return percentile_digest_value.to_bytes(cls.hash().digest_size, 'big')

    @classmethod
    def new(cls, percentile, data):
        return next(cls.in_percentile(percentile, data))

    @classmethod
    def in_percentile(cls, percentile, data):
        """
        >>> for c in islice(Hashcoin.in_percentile(1e-3, b'ayy'), 3):
        ...     print(c.salt.hex(), c.digest().hex())
        0005 002402f87f6348e1f379d1226469c8b09cc97286
        00ac 002571d5ea51f79cb0e9ee7a76ae40436ab2bcb1
        05d3 001a5c55ae5b7abcb2e5b93022121b97352ddafb
        """
        data_hash = cls.hash(data)
        max_digest = cls.percentile_digest(percentile)
        for salt in cls.salts():
            full_hash = data_hash.copy()
            full_hash.update(salt)
            if full_hash.digest() <= max_digest:
                yield cls(data, salt)

    @classmethod
    def refine(cls, data):
        """Iterate through Hashcoins, each with lower digest than the last."""
        data_hash = cls.hash(data)
        min_digest = cls.max_digest()
        for salt in cls.salts():
            full_hash = data_hash.copy()
            full_hash.update(salt)
            digest = full_hash.digest()
            if digest < min_digest:
                min_digest = digest
                yield cls(data, salt)

    @classmethod
    def best(cls, n, data):
        """Return the lowest-digest Hashcoin from n different guesses."""
        data_hash = cls.hash(data)
        min_digest = cls.max_digest()
        min_salt = b''
        for salt in islice(cls.salts(), n):
            full_hash = data_hash.copy()
            full_hash.update(salt)
            digest = full_hash.digest()
            if digest < min_digest:
                min_digest = digest
                min_salt = salt
        return cls(data, min_salt)

    def digest(self):
        h = self.hash(self.data)
        h.update(self.salt)
        return h.digest()

    def percentile(self):
        """The portion of possible digests strictly lower in numeric value."""
        return intify(self.digest()) / (intify(self.max_digest()) + 1)
