import unittest
from binascii import hexlify
from hashlib import sha256
from spake2.spake2 import SPAKE2_A, SPAKE2_B
from .common import PRG

class TestPRG(unittest.TestCase):
    def test_basic(self):
        PRGA = PRG(b"A")
        dataA = PRGA(16)
        self.assertEqual(hexlify(dataA), b"c1d59d78903e9d7874d9064e12d36c58")
        PRGB = PRG(b"B")
        dataB = PRGB(16)
        self.assertEqual(hexlify(dataB), b"2af6d4b843a9e6cd1d185eb5de870f77")

class Basic(unittest.TestCase):
    def test_success(self):
        """Make sure we know when an incompatible change has landed"""
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
