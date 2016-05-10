import unittest
from binascii import hexlify
from hashlib import sha256
from spake2.spake2 import SPAKE2_A, SPAKE2_B, SPAKE2_Symmetric
from .common import PRG

class TestPRG(unittest.TestCase):
    def test_basic(self):
        PRGA = PRG(b"A")
        dataA = PRGA(16)
        self.assertEqual(hexlify(dataA), b"c1d59d78903e9d7874d9064e12d36c58")
        PRGB = PRG(b"B")
        dataB = PRGB(16)
        self.assertEqual(hexlify(dataB), b"2af6d4b843a9e6cd1d185eb5de870f77")

class SPAKE2(unittest.TestCase):
    """Make sure we know when an incompatible change has landed"""
    def test_asymmetric(self):
        PRGA = PRG(b"A")
        PRGB = PRG(b"B")
        pw = b"password"
        sA,sB = SPAKE2_A(pw, entropy_f=PRGA), SPAKE2_B(pw, entropy_f=PRGB)
        m1A,m1B = sA.start(), sB.start()
        self.assertEqual(hexlify(m1A), b"41b64e03c9ecf77308abcfbe937bf359d9975e04a01b0da78bca4636c4b6a5a490")
        self.assertEqual(hexlify(m1B), b"42312acae984b85cad53d33896eb6ae52dc75824a7d3dceced207a2c420424fc21")

        kA,kB = sA.finish(m1B), sB.finish(m1A)
        self.assertEqual(hexlify(kA),
                         b"a25f511e6a17cc3855194b5a4b4ed93be511c1da2b2b9d76281f360a7e1da981")
        self.assertEqual(hexlify(kA), hexlify(kB))
        self.assertEqual(len(kA), len(sha256().digest()))

    def test_symmetric(self):
        PRG1 = PRG(b"1")
        PRG2 = PRG(b"2")
        pw = b"password"
        s1 = SPAKE2_Symmetric(pw, entropy_f=PRG1)
        s2 = SPAKE2_Symmetric(pw, entropy_f=PRG2)
        m11,m12 = s1.start(), s2.start()
        self.assertEqual(hexlify(m11), b"5399bfc2cab3f574ea6201668d4b1d90f5dd300068c006b9832c8ea2f605c09ce0")
        self.assertEqual(hexlify(m12), b"53ce58ebbb3a221ce825b43689379557a9a4b7db4b77138060eb25588108e40a38")

        k1,k2 = s1.finish(m12), s2.finish(m11)
        self.assertEqual(hexlify(k1),
                         b"bc89d46f5d111aa80aee0a2b65d0e2fd36caba3bc4832804e6f6eb6045dd8483")
        self.assertEqual(hexlify(k1), hexlify(k2))
        self.assertEqual(len(k1), len(sha256().digest()))
