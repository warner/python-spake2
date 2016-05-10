from spake2 import six
from hashlib import sha256
from itertools import count

class PRG:
    # this returns a callable which, when invoked with an integer N, will
    # return N pseudorandom bytes derived from the seed
    def __init__(self, seed):
        self.generator = self.block_generator(seed)

    def __call__(self, numbytes):
        return b"".join([six.next(self.generator) for i in range(numbytes)])

    def block_generator(self, seed):
        assert isinstance(seed, type(b""))
        for counter in count():
            cseed = b"".join([b"prng-",
                              str(counter).encode("ascii"),
                              b"-",
                              seed])
            block = sha256(cseed).digest()
            for i in range(len(block)):
                yield block[i:i+1]
