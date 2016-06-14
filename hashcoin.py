import hashlib
from collections import namedtuple
from functools import lru_cache, partial, wraps
from itertools import count, combinations_with_replacement, islice


def reuse(func=None, *, cache=lru_cache()):
    """Cache and reuse a generator function across multiple calls."""
    # Allow this decorator to work with or without being called
    if func is None:
        return partial(reuse, cache=cache)

    # Either initialize an empty history and start a new generator, or
    # retrieve an existing history and the already-started generator
    # that produced it
    @cache
    def resume(*args, **kwargs):
        return [], func(*args, **kwargs)

    @wraps(func)
    def reuser(*args, **kwargs):
        history, gen = resume(*args, **kwargs)
        yield from history
        record = history.append  # Avoid inner-loop name lookup
        for x in gen:
            record(x)
            yield x

    return reuser


def byte_sequences(num_bytes):
    """
    >>> [b.hex() for b in byte_sequences(0)]
    ['']
    >>> [b.hex() for b in byte_sequences(2)[:4]]
    ['0000', '0001', '0002', '0003']
    >>> [b.hex() for b in byte_sequences(2)[-4:]]
    ['fffc', 'fffd', 'fffe', 'ffff']
    """
    return [i.to_bytes(num_bytes, 'big') for i in range(256 ** num_bytes)]


@reuse
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
        for i in range(256 ** num_bytes):
            yield i.to_bytes(num_bytes, 'big')
        # value_combos = combinations_with_replacement(range(256), num_bytes)
        # for values in value_combos:
        #     yield bytes(values)


def byte_sequences_up_to(num_bytes):
    seqs = [b'']
    for num_bytes in count():
        value_combos = combinations_with_replacement(range(256), num_bytes)
        seqs.extend([bytes(values) for values in value_combos])
    return seqs


# small_byte_seqs = [b'']
# for num_bytes in count(1):
#     small_byte_seqs.extend(byte_sequences(num_bytes))


def intify(b, byteorder='big'):
    return int.from_bytes(b, byteorder=byteorder)


def percentile(value, max_value):
    """What portion of all possible values are strictly lower in value?

    >>> percentile(0, 1)
    0.0
    >>> percentile(1, 1)
    0.5
    >>> percentile(0, 3)
    0.0
    >>> percentile(1, 3)
    0.25
    >>> percentile(2, 3)
    0.5
    >>> percentile(3, 3)
    0.75
    """
    return value / (max_value + 1)


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


if __name__ == '__main__':
    import os

    for _ in range(100):
        for c in islice(Hashcoin.in_percentile(1e-4, os.urandom(4)), 10):
            print(c.digest().hex(), c.data.hex(), c.salt.hex())
