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

    >>> c = Hashcoin.new(1e-4, b'ayyy')
    >>> c.salt.hex()
    '1b85'
    >>> c.digest().hex()
    '000177eb8d8c88921c86310f7a14ab82fbd42e91'
    >>> c.percentile()
    2.240658573005831e-05
    """

    hash = hashlib.sha1

    @classmethod
    def salts(cls):
        yield from iter_bytes()

    @classmethod
    def new(cls, percentile, data):
        return next(cls.in_percentile(percentile, data))

    @classmethod
    def in_percentile(cls, percentile, data):
        """
        >>> for c in islice(Hashcoin.in_percentile(1e-3, b'ayyy'), 3):
        ...     print(c.salt.hex(), c.digest().hex())
        02d3 0035e34d536474e7056e5c06220f77283b9dd1a5
        0413 003fb3118e0b7d1a1e19eca886a88217a05ec3ec
        04e6 001af85850623cb2423a86af680dbb8509ac32aa
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

    @classmethod
    def max_digest(cls):
        return bytes([0xff] * cls.hash().digest_size)

    @classmethod
    def percentile_digest(cls, percentile):
        max_digest_value = int.from_bytes(cls.max_digest(), 'big')
        percentile_digest_value = int(percentile * (max_digest_value + 1))
        return percentile_digest_value.to_bytes(cls.hash().digest_size, 'big')

    def digest(self):
        h = self.hash(self.data)
        h.update(self.salt)
        return h.digest()

    def percentile(self):
        return intify(self.digest()) / (intify(self.max_digest()) + 1)
