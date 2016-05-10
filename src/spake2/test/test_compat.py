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

GROUPS = {
    "I1024": groups.I1024,
    "I2048": groups.I2048,
    "I3072": groups.I3072,
    "Ed25519": ed25519_group.Ed25519Group,
    }

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

class PasswordToScalar(unittest.TestCase):
    def test_vectors(self):
        for vector in P2S_TEST_VECTORS:
            group = GROUPS[vector["group"]]
            pw = unhexlify(vector["pw_hex"].encode("ascii"))
            scalar = group.password_to_scalar(pw)
            scalar_bytes = group.scalar_to_bytes(scalar)
            self.assertEqual(len(scalar_bytes), group.scalar_size_bytes)
            expected = vector["bytes_hex"].encode("ascii")
            self.assertEqual(hexlify(scalar_bytes), expected, vector)

# check for endian issues, number-of-leading-zeros
S2B_TEST_VECTORS = [
    {"group": "I1024", "scalar": 1,
     "bytes_hex": "0000000000000000000000000000000000000001"},
    {"group": "I1024", "scalar": 2,
     "bytes_hex": "0000000000000000000000000000000000000002"},
    {"group": "I2048", "scalar": 1,
     "bytes_hex": "00000000000000000000000000000000000000000000000000000001"},
    {"group": "I2048", "scalar": 2,
     "bytes_hex": "00000000000000000000000000000000000000000000000000000002"},
    {"group": "I3072", "scalar": 1,
     "bytes_hex": "0000000000000000000000000000000000000000000000000000000000000001"},
    {"group": "I3072", "scalar": 2,
     "bytes_hex": "0000000000000000000000000000000000000000000000000000000000000002"},
    {"group": "Ed25519", "scalar": 1,
     "bytes_hex": "0100000000000000000000000000000000000000000000000000000000000000"},
    {"group": "Ed25519", "scalar": 2,
     "bytes_hex": "0200000000000000000000000000000000000000000000000000000000000000"},
    ]

class ScalarToBytes(unittest.TestCase):
    def test_vectors(self):
        for vector in S2B_TEST_VECTORS:
            group = GROUPS[vector["group"]]
            scalar = vector["scalar"]
            scalar_bytes = group.scalar_to_bytes(scalar)
            #print(hexlify(scalar_bytes))
            expected = vector["bytes_hex"].encode("ascii")
            self.assertEqual(hexlify(scalar_bytes), expected, vector)

AE_TEST_VECTORS = [
    {"group": "I1024", "seed_hex": "41",
     "element_hex": "102db0f3f0ba6c2274dff5fa7502a796673fb77d18907a3ea466dfabd5f13b7dbd4b593ff7d72592d54ee13819a8034f471a2f1f2fd329dcf32ca703e9540ce8cbc839ce06b92abed7728a0ec5f62d9a7effb0356ffc66108777b2092fc91c6a7532045252e33642c6819b64349ffef8e88c2a628c4d8a3aa75b2c73eb50b2e4"},
    {"group": "I1024", "seed_hex": "42",
     "element_hex": "906e52364ef5a3dcf07cfe7ff5b208dfca1062ed06bf1c17b1669b89293b9859daea4fea9b93aabe9a6914b58c9e964fc4b02f09d6e21f26c8e0c33a8e7d79f63aba24f42aa27cd08133817a7ccc7ef9f93c9b651df014418d2c814ccbb9644c66cc0a0b9f9f4385869d504638b40f0945b5e76d9d61e6887d86a4f1de80873f"},
    {"group": "I2048", "seed_hex": "41",
     "element_hex": "026a61a581f38ec6c735aaf53b7e6c736647cc1401c670938a588ac60bf1ed4db53c9b8ffd83a7ac55ae4f97331f126f920b26c6a85da238dfd6b37717f0201d4c851ec6b585a0d6d2cdd56c7245fbdefe98c3ab6c5c491851b6359b4e075d203097305efd3fdbd9db7fd08d7dd7f82d85502fdcedf8c826b0026a80c166ffb7948c558a5e426659a46c569351ff15ff1142ac0a7c4ea41bb7861c692eb71c6e34731da74bf5b7dfd3b30810398e6d4e6dfde99263c2e452897ae9726e96060caa06d62c3181590de51c88d3100ef6dfec376ff1e2c3929ff4c384d5efe4b50e29707153467db3cb69bb6d94ae67fdeaaff69dee06b0f1f8777b5aff22c0b15a"},
    {"group": "I2048", "seed_hex": "42",
     "element_hex": "3b3fde7d4a6efe3110d12ea5b3e9f0fa998cd554eb56ec815c3bae510965859eb9e89570f97d4fce11a74084170cb8c8941061f344c57ab65dbe7feef2da7ade16b3dc818ecbd1c7359757779970e37b16a12bbd621035d2383d8cbe449f940cd1bd2887697901776e62f69f8296bb84f6513a352075a9b2c6777b8e34f1b4f529d3da0102221bc24084100b76cfb73923b5454accdd89e1511bf832889dd47b51d814866f23bd913fcd6e48bc4c29714b02176bfc742480fc53acb7d936dc2a1a72e5ee0386103987ff18de6537166ab1c06197029bf0ba7c748338b4f2f18b4644a67d45fcb7cf63ae2597448b6a25c0aef225335f55e5c05c1fa0beea3d92"},
    {"group": "I3072", "seed_hex": "41",
     "element_hex": "38133756001ac1bcc87cd4f55fb66e1aa7be2a9cad127d4cab213b5cbfc37f5300a321aa02cc46907e81206e085389d952c7833b30ea2c72d7eef771a4e106e22c2cf7e9717233e75c10a8001f271bd1c91bc386fefb9731d87ccc241412938efc915270e46fcfb12a31a84d76fad56e3ac2da9bc179300408ebb7ea1442a0424ebc953ba567505fc1e6e9901dcfed8bb084a75b007404459561361f7009bb0737a3493d38c23f91234da37315d8ff6c0283854d7573976a8a50e78ae90c7553ecedb94ce7df4f007749ae75b860436501ddcba3bf45cc792b5b15c54bb6592928305d85031e9f81cedf6a588083c64e390d8676de296c4cca8ee32c20da296f9779060e7e3e4464dc71bccc1558d11846d7c7fc12618290a68379e1d3fffe67370db77e99d20309a58c37528f705f3fd4772834439580a0e8cee996e8b9ebf7343364c1fceb234801fa6642f8dcdf3a9255732952156dabfe964b5a3217f51484e850e4f47c76cdfdb44bede7b9b7b93cd6c75185e84e8082f88cadc33220f9"},
    {"group": "I3072", "seed_hex": "42",
     "element_hex": "72c68bb63e5005045ce1b59c7f2f307ce2be2cc65f73f477a2331b6467559f34cf013a4bb7977df1d78ea739716c9253d468c44cdd4c710e727c6d95eeb64e0b7eabc0176ed4d6a97ac90f859cf28967d9335d7b5399859c4f4c885b3e29a8bd070cafd2e747277ddc8b8c47e01c97cdca67934f80f730393a7936c140d581fc52f8b67e9f42c5d1ea60d30d1bf3813029b4045004aacc0945fb1aec3ef50e8ae8f7f53856d146841b834708bda5c6dece66f150d6a0737461a9de956c66e303d75449ee6f33570bbd9ae31429da36546b09b0e08a84d43fbbfcb019de613b70bc7ac78be6e187d722afda3723c6307f7138a6ba1cd127a0b523925c3c5ebd80f4656572d14d7ae305167b46225dbc5af618eb04d294e7051146d771a992ac4e53017d268c98e5e35ffee0b1036eefa9ffd996c2003e8278cad071c23689354a1707cfaf1eff63cc844e1ccbf5efef4947a32f4aa4d576b7b263843ae65587313ad45dc8702989cbd9eec978a20096a7d31eff12c5b7fe2e5714e19bd6a4c7ec"},
    {"group": "Ed25519", "seed_hex": "41",
     "element_hex": "a88505e0ffd606e487a59e12ea0cd5b24e1aab862b532621615cb421224af427"},
    {"group": "Ed25519", "seed_hex": "42",
     "element_hex": "de74000be83460f570feba692c5ffddb39348c32f47fc67171a70a7e057f9646"},
    ]

class ArbitraryElement(unittest.TestCase):
    def test_vectors(self):
        for vector in AE_TEST_VECTORS:
            group = GROUPS[vector["group"]]
            seed = unhexlify(vector["seed_hex"].encode("ascii"))
            elem = group.arbitrary_element(seed)
            elem_bytes = elem.to_bytes()
            self.assertEqual(len(elem_bytes), group.element_size_bytes)
            #print(hexlify(elem_bytes))
            expected = vector["element_hex"].encode("ascii")
            self.assertEqual(hexlify(elem_bytes), expected, vector)

