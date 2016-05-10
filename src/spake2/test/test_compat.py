import unittest
from binascii import hexlify, unhexlify
from hashlib import sha256
from spake2 import groups, ed25519_group
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

# These vectors exercise the password-to-scalar conversion step. The vectors
# should be all JSON, so in the future we can cut-and-paste them into other
# implementations for compatibility testing.
# hexlify(b"pw") == "7077"
# "0001feff" is meant to test non-ASCII passwords
P2S_TEST_VECTORS = [
    {"group": "I1024", "pw_hex": "7077",
     "bytes_hex": "8e0305a470dd82cfd0d3565b26a8cc038a760db1"},
    {"group": "I1024", "pw_hex": "0001feff",
     "bytes_hex": "d232b4453ef12bcb5bd1379f8cf5386f8f72c37a"},
    {"group": "I2048", "pw_hex": "7077",
     "bytes_hex": "31bfa1a2f261b3d25cb1374659295dc4911970ef2f36b11c298e87b9"},
    {"group": "I2048", "pw_hex": "0001feff",
     "bytes_hex": "2e9240620965970def29f7cf8b36553a29459e6136497094a6089bed"},
    {"group": "I3072", "pw_hex": "7077",
     "bytes_hex": "03e8e502ef6cd6eeea8d602d55f15b3a843db65a1fb5c6e8875ddc4607d68c8c"},
    {"group": "I3072", "pw_hex": "0001feff",
     "bytes_hex": "0689b1f4af52d5baff2d126b7e91d086edc0aceff6721df8bbd29f66dce6ba7d"},
    {"group": "Ed25519", "pw_hex": "7077",
     "bytes_hex": "93fefb531c25f73215ed4a6c6c70fedcb2fc653971f1341d4cf1a651c6c6a103"},
    {"group": "Ed25519", "pw_hex": "0001feff",
     "bytes_hex": "5a0c70010fb3df10c6ded9b9d57d8088d1676eda41555bb2598bb926a8f67c08"},
    ]
P2S_GROUPS = {
    "I1024": groups.I1024,
    "I2048": groups.I2048,
    "I3072": groups.I3072,
    "Ed25519": ed25519_group.Ed25519Group,
    }

class PasswordToScalar(unittest.TestCase):
    def test_vectors(self):
        for vector in P2S_TEST_VECTORS:
            group = P2S_GROUPS[vector["group"]]
            scalar = group.password_to_scalar(unhexlify(vector["pw_hex"]))
            scalar_bytes = group.scalar_to_bytes(scalar)
            self.assertEqual(len(scalar_bytes), group.scalar_size_bytes)
            expected = vector["bytes_hex"].encode("ascii")
            self.assertEqual(hexlify(scalar_bytes), expected, vector)
