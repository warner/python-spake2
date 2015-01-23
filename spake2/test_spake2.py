
import unittest
from spake2 import SPAKE2, SPAKE2_P, SPAKE2_Q, PAKEError, \
     params_80, params_112, params_128
from binascii import hexlify
from hashlib import sha256
import json

class Basic(unittest.TestCase):
    def test_success(self):
        pw = "password"
        pA,pB = SPAKE2_P(pw), SPAKE2_Q(pw)
        m1A,m1B = pA.one(), pB.one()
        kA,kB = pA.two(m1B), pB.two(m1A)
        self.failUnlessEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))

    def test_failure(self):
        pw = "password"
        pA,pB = SPAKE2_P(pw), SPAKE2_Q("passwerd")
        m1A,m1B = pA.one(), pB.one()
        kA,kB = pA.two(m1B), pB.two(m1A)
        self.failIfEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))
        self.failUnlessEqual(len(kB), len(sha256().digest()))

class Parameters(unittest.TestCase):
    def do_tests(self, params):
        pw = "password"
        pA,pB = SPAKE2_P(pw, params=params), SPAKE2_Q(pw, params=params)
        m1A,m1B = pA.one(), pB.one()
        #print len(json.dumps(m1A))
        kA,kB = pA.two(m1B), pB.two(m1A)
        self.failUnlessEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))

        pA,pB = SPAKE2_P(pw, params=params), SPAKE2_Q("passwerd", params=params)
        m1A,m1B = pA.one(), pB.one()
        kA,kB = pA.two(m1B), pB.two(m1A)
        self.failIfEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))
        self.failUnlessEqual(len(kB), len(sha256().digest()))

    def test_params(self):
        for params in [params_80, params_112, params_128]:
            self.do_tests(params)

    def test_default_is_80(self):
        pw = "password"
        pA,pB = SPAKE2_P(pw, params=params_80), SPAKE2_Q(pw)
        m1A,m1B = pA.one(), pB.one()
        kA,kB = pA.two(m1B), pB.two(m1A)
        self.failUnlessEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))


class PRNG:
    # this returns a callable which, when invoked with an integer N, will
    # return N pseudorandom bytes.
    def __init__(self, seed):
        self.generator = self.block_generator(seed)

    def __call__(self, numbytes):
        return "".join([self.generator.next() for i in range(numbytes)])

    def block_generator(self, seed):
        counter = 0
        while True:
            for byte in sha256("prng-%d-%s" % (counter, seed)).digest():
                yield byte
            counter += 1

class OtherEntropy(unittest.TestCase):
    def test_entropy(self):
        entropy = PRNG("seed")
        pw = "password"
        pA,pB = SPAKE2_P(pw, entropy=entropy), SPAKE2_Q(pw, entropy=entropy)
        m1A1,m1B1 = pA.one(), pB.one()
        kA1,kB1 = pA.two(m1B1), pB.two(m1A1)
        self.failUnlessEqual(hexlify(kA1), hexlify(kB1))

        # run it again with the same entropy stream: all messages should be
        # identical
        entropy = PRNG("seed")
        pA,pB = SPAKE2_P(pw, entropy=entropy), SPAKE2_Q(pw, entropy=entropy)
        m1A2,m1B2 = pA.one(), pB.one()
        kA2,kB2 = pA.two(m1B2), pB.two(m1A2)
        self.failUnlessEqual(hexlify(kA2), hexlify(kB2))

        self.failUnlessEqual(m1A1, m1A2)
        self.failUnlessEqual(m1B1, m1B2)
        self.failUnlessEqual(kA1, kA2)
        self.failUnlessEqual(kB1, kB2)

class Serialize(unittest.TestCase):
    def replace(self, orig):
        data = json.dumps(orig.to_json())
        #print len(data)
        return SPAKE2.from_json(json.loads(data))

    def test_serialize(self):
        pw = "password"
        pA,pB = SPAKE2_P(pw), SPAKE2_Q(pw)
        pA = self.replace(pA)
        m1A,m1B = pA.one(), pB.one()
        pA = self.replace(pA)
        kA,kB = pA.two(m1B), pB.two(m1A)
        self.failUnlessEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))

class Packed(unittest.TestCase):
    def test_pack(self):
        pw = "password"
        pA,pB = SPAKE2_P(pw), SPAKE2_Q(pw)
        m1A,m1B = pA.one(), pB.one()
        m1Ap = pA.pack_msg(m1A)
        #print "m1:", len(json.dumps(m1A)), len(m1Ap)
        kA,kB = pA.two(m1B), pB.two(pB.unpack_msg(m1Ap))
        self.failUnlessEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))

class Errors(unittest.TestCase):
    def test_bad_side(self):
        self.failUnlessRaises(PAKEError,
                              SPAKE2, "password", "R", params_80)

if __name__ == '__main__':
    unittest.main()

