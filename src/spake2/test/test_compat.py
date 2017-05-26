import unittest
from binascii import hexlify, unhexlify
from hashlib import sha256
from hkdf import Hkdf
from .myhkdf import HKDF as myHKDF
from spake2 import groups, ed25519_group
from spake2.spake2 import (SPAKE2_A, SPAKE2_B, SPAKE2_Symmetric,
                           finalize_SPAKE2, finalize_SPAKE2_symmetric)
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
        self.assertEqual(hexlify(m1A), b"416fc960df73c9cf8ed7198b0c9534e2e96a5984bfc5edc023fd24dacf371f2af9")
        self.assertEqual(hexlify(m1B), b"42354e97b88406922b1df4bea1d7870f17aed3dba7c720b313edae315b00959309")
        # peek at the scalars, since it ought to be stable, and other
        # implementations that want to use this as a test vector might start
        # with the scalar, rather than duplicating our deterministic RNG
        self.assertEqual(sA.pw_scalar,
                         3515301705789368674385125653994241092664323519848410154015274772661223168839)
        self.assertEqual(sB.pw_scalar,
                         3515301705789368674385125653994241092664323519848410154015274772661223168839)
        self.assertEqual(sA.xy_scalar,
                         2611694063369306139794446498317402240796898290761098242657700742213257926693)
        self.assertEqual(sB.xy_scalar,
                         7002393159576182977806091886122272758628412261510164356026361256515836884383)

        kA,kB = sA.finish(m1B), sB.finish(m1A)
        self.assertEqual(hexlify(kA),
                         b"a480bca13fa04464bb644f10e340125e96c9494f7399fef7c2bda67eb0fdf06d")
        self.assertEqual(hexlify(kA), hexlify(kB))
        self.assertEqual(len(kA), len(sha256().digest()))

    def test_symmetric(self):
        PRG1 = PRG(b"1")
        PRG2 = PRG(b"2")
        pw = b"password"
        s1 = SPAKE2_Symmetric(pw, entropy_f=PRG1)
        s2 = SPAKE2_Symmetric(pw, entropy_f=PRG2)
        m11,m12 = s1.start(), s2.start()
        self.assertEqual(hexlify(m11), b"5308f692d38c4034ad6e2e1054c469ca1dbe990bcaec4bbd3ad78c7d968eadd0b3")
        self.assertEqual(hexlify(m12), b"5329e2d5f9b7a53e609204115c6458921b0bb27419ce82a27679fc5961002897df")

        k1,k2 = s1.finish(m12), s2.finish(m11)
        self.assertEqual(hexlify(k1),
                         b"9c4fccaa3f0740615cee6fd10ed5d3a311b91b5bdc65f53e4ea7cb2fe8aa96eb")
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
     "bytes_hex": "28f73d0d793a38cb21694b751cd0affb181474be"},
    {"group": "I1024", "pw_hex": "0001feff",
     "bytes_hex": "37044fd99e0499af9b263a21e13dd737b7b022bf"},
    {"group": "I2048", "pw_hex": "7077",
     "bytes_hex": "56db566c2740f46557d8c3695a5eb6fb736797b63f98c58931267ae6"},
    {"group": "I2048", "pw_hex": "0001feff",
     "bytes_hex": "058062c322379afd9eba83c084b8cf5b23aa9f69aeb659bac912222a"},
    {"group": "I3072", "pw_hex": "7077",
     "bytes_hex": "49454ea9faa9e70213573c8f271163d6d430b994fdba8af482478c3a3ae43f04"},
    {"group": "I3072", "pw_hex": "0001feff",
     "bytes_hex": "a1b0ffda72070f4d1bc565933904fb92307b40bc2d32ad1394eea3598128ba9a"},
    {"group": "Ed25519", "pw_hex": "7077",
     "bytes_hex": "cf090b60384cb818b12c8d972dfbaf910c0c7295c5cfe560e508f5f062f3960f"},
    {"group": "Ed25519", "pw_hex": "0001feff",
     "bytes_hex": "e86622bb57ea0f6f9f963354f2973a43a9e981901a478e6478682374441b0c04"},
    ]

class PasswordToScalar(unittest.TestCase):
    def test_vectors(self):
        for vector in P2S_TEST_VECTORS:
            group = GROUPS[vector["group"]]
            pw = unhexlify(vector["pw_hex"].encode("ascii"))
            scalar = group.password_to_scalar(pw)
            scalar_bytes = group.scalar_to_bytes(scalar)
            self.assertEqual(len(scalar_bytes), group.scalar_size_bytes)
            #print(hexlify(scalar_bytes))
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
     "element_hex": "933084f15747174af82ece8ba242f83e38db4a64b8887f9ef275c318ae0b0f4338e9fafc6ff601d1b0f8b3dfe63bbaf774117c820abb16f5d054833e897647813083d2bed14c88d54717e2b5e9d161bc87fd0265c2d10002a6ac14fadf8da81fd3710c1d179c7247ffecc148f764d0a19c9319c698aa553dd825ae4112e6128d"},
    {"group": "I1024", "seed_hex": "42",
     "element_hex": "4ac273e831a27542a1a9017d896dc32128e8e19aa726d261ae0214d7860a69958d82ad1525a8fa16c78a7b66cf52a977aefd6f4d99fb5aa26b99b0d1d9e8a8079ebd272ac78ea574df52dccb454fa253a9fad9621f8edf824b2235e02b129d357b8d3c10026357734dd4c98f018fc9ff15978679347e9b6e0a3bbd1f5402a679"},
    {"group": "I2048", "seed_hex": "41",
     "element_hex": "bb192daef4e0ab05f5e908a3f3ddefedfc8388b4a4daae894a23125322fd24c95606b85fb7d4a041c9f312d890a057c8d3587bedfe7843d997e78140fdd530d0cb2bb2738f9ec0befbb09a863f48a5ea3b503300db65a8666e55ba875640f6db8c3cfd2d55ef3b4c67bb51d28d4dd4ba3fd443e655870fa54dfa1ce7b4b493d48c692c1c46977eeac82ea5e87afe72db3d778112a689ad0275135cd0fc8378139d700e03cfd2f7bfc0f142b6f4a5f5ecd12e09ea960e91fe3c10db637770f188fb9cb3004fda24ef7957bb7f8890fd12b77b8ade48a95620dc3442aa717b9d04dcec7ffec8a33cbf51735ab4acb1520f82e03d0b465c9c9a23f75e32f6b58208"},
    {"group": "I2048", "seed_hex": "42",
     "element_hex": "a4964933a4dd3e8b5e172e5a48e01dc346d046b4d960004e0802f2da0636d081f21a9975f470480874c36dcd2e83f41cdeeb192659b8f03c4c7339eca7861672cab1f0ed765de48d8ac68cdeb2cd873b1415a73bb03eef497b221ff1a5635e6bcb96de1a444d09f986e964e2e842fb010712c261678d2ac8adb35f30986f90bda797528e32cefcfbb0733a15d59758e1021a3f13ff117e2519ba06ceeff3956212ddf07c1516ae68499c89d7c373c586119948e2b05c518d0a736baee46ffabd6756d354d38cb642b53ca7778eb3786b035163e76a868828dc71b28a63b6a24c11e9e280e5bf147f4dc20cb2cbd7fb7a961a2b0983119285d6dd6988554cb45b"},
    {"group": "I3072", "seed_hex": "41",
     "element_hex": "5459e7c980132e3002b49d6756b06139ae80b4ec7183607d9534f9f0fcb7a80cdd8db3707feddca4132ef0ea2733cd09b715092dfd330da941454cc3230188b24453878223ab6498c99a64384cf6d14f9f57213aac2fb95d7a77ccb3304e9345eb09d59dea807ff9644ffb83c5b33eff26876b5261261295e1b732b77ea26b745934499d4120d7d345edee9d1d004eda574d71884436ffe953ab7d857cebad2b5b062814c649256a20fcf1b6957c0513fd7fc3ac21edd335a368812a31daa654eec5c320d235357e642eba0c3964e1d3e40cdd913da23a88ceb8272ab920e939026348580999aceef6dbbd0babec1846be0b35b5134f8420fabbddec2ad0188dbff920e9f839208b0140f240dd24890f50b89a09899f50f26422b28fa99cefb16b9b2d6d08342be802f2d84861475ee6a47d940e681cd735c42fd124403c3ce78c5c90be8203f8497c15f07f16553f31a155ae7b5eb4b5cc93f52ff8d095f56d5930c5ff9944589d89f0e153d61b6ecb00649e716f0cb95fe8280ebb282c9f3a"},
    {"group": "I3072", "seed_hex": "42",
     "element_hex": "69e247a5284cb5683fa48c3f60ce7b83857b0f67db156d9b120a7338a52514f223d319c3a39dc81169c4a0efdcc03742a0dd08d7c1e177f8c83c19d4a1fb7955b6572051d73b0ca241a48477194fb84020e917081dc2e04ab474f6b018f68ef797cd2d2403049c6af7f6583faf19651f6e263f6a8ddf3a23165cf1703ead9dfaf3d59f6520906fd13479aa72f12777a9ea469518d4159cc832b1f39ce2b84153e3a2bc3940cdd07ee6353e7f7867bf0cb8634b54a33967958f709e5429e992eb76dfb49341530916d237cb1d2f42412443f62beeb6042c270af3633ea9561dd0cde544e21cb8b11f550f44020d3c744faa3cfc153657512000d2c13cdf53fd950c79e39cd74a0efd39c5a6f7f835e9287fbaf031c120e657ae1eeb29800e049d97517772c8dd504e0b1a124abb7b3592d1434caa0e786f01b673d19548b9e6498782b83962a5fffc389d6c4c6afe618ce5c1e9fe479e7dfef9777c62de43a657bff65218a050826bdc3ae3ba978a3fc018cc5413008b9fd7903a62a0758d51f1"},
    {"group": "Ed25519", "seed_hex": "41",
     "element_hex": "4637592ae2914247de5804be805867266ccac99c635df8077dcdc1d72becf354"},
    {"group": "Ed25519", "seed_hex": "42",
     "element_hex": "88228ee4046ba5d5fa2f23a0480a99efb1a9554ce50153d69330928215d50775"},
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

# test vectors from RFC5869

HKDF_TEST_VECTORS = [
    {
        "IKM": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "salt": "000102030405060708090a0b0c",
        "info": "f0f1f2f3f4f5f6f7f8f9",
        "L": 42,
        "PRK": "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        "OKM": "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        },
    {
        "IKM": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
        "salt": "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "info": "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "L": 82,
        "PRK": "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        "OKM": "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
        },
    {
        "IKM": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "salt": "",
        "info": "",
        "L": 42,
        "PRK": "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        "OKM": "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        },
    ]

# some additional short vectors. Note that "salt" is zero-padded to length of
# the hash (and hashed down if longer), so e.g. salt="", salt="00", and
# salt="0000" all give the same results.
HKDF_TEST_VECTORS += [
    {"salt": "",   "IKM": "01", "info": "02", "L": 4, "OKM": "f4a855e4"},
    {"salt": "00", "IKM": "01", "info": "02", "L": 4, "OKM": "f4a855e4"},
    {"salt": "",   "IKM": "01", "info": "", "L": 4, "OKM": "be7e83fb"},
    {"salt": "00", "IKM": "01", "info": "", "L": 4, "OKM": "be7e83fb"},
    {"salt": "01", "IKM": "01", "info": "", "L": 4, "OKM": "f0f7dcf9"},
    {"salt": "01", "IKM": "01", "info": "", "L": 8, "OKM": "f0f7dcf9fe847ae5"},
    {"salt": "01", "IKM": "01", "info": "", "L": 16, "OKM": "f0f7dcf9fe847ae58a24e82b13737c52"},
    {"salt": "01", "IKM": "01", "info": "", "L": 31, "OKM": "f0f7dcf9fe847ae58a24e82b13737c52bf6a4a45810f5d819ec3932eaa6012"},
    {"salt": "01", "IKM": "01", "info": "", "L": 32, "OKM": "f0f7dcf9fe847ae58a24e82b13737c52bf6a4a45810f5d819ec3932eaa601290"},
    {"salt": "01", "IKM": "01", "info": "", "L": 33, "OKM": "f0f7dcf9fe847ae58a24e82b13737c52bf6a4a45810f5d819ec3932eaa60129072"},
    {"salt": "01", "IKM": "01", "info": "", "L": 64, "OKM": "f0f7dcf9fe847ae58a24e82b13737c52bf6a4a45810f5d819ec3932eaa60129072a91afe92cffe2f2327b65ba4e2b2b6b51ed34363c9c4cca58ae7409209b97d"},
    {"salt": "01", "IKM": "01", "info": "", "L": 65, "OKM": "f0f7dcf9fe847ae58a24e82b13737c52bf6a4a45810f5d819ec3932eaa60129072a91afe92cffe2f2327b65ba4e2b2b6b51ed34363c9c4cca58ae7409209b97d76"},
    {"salt": "00", "IKM": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "info": "", "L": 4, "OKM": "37ad2910"},
    ]

class HKDF(unittest.TestCase):
    def test_vectors(self):
        for vector in HKDF_TEST_VECTORS:
            salt = unhexlify(vector["salt"].encode("ascii"))
            IKM = unhexlify(vector["IKM"].encode("ascii"))
            info = unhexlify(vector["info"].encode("ascii"))
            h = Hkdf(salt=salt, input_key_material=IKM, hash=sha256)
            digest = h.expand(info, vector["L"])
            self.assertEqual(digest, myHKDF(IKM, vector["L"], salt, info))
            #print(hexlify(digest))
            expected = vector["OKM"].encode("ascii")
            self.assertEqual(hexlify(digest), expected, vector)

class Finalize(unittest.TestCase):
    def test_asymmetric(self):
        key = finalize_SPAKE2(b"idA", b"idB", b"X_msg", b"Y_msg",
                              b"K_bytes", b"pw")
        self.assertEqual(hexlify(key), b"aa02a627537543399bb1b4b430646480b6d36ab5c44842e738c8f78694d8afac")

    def test_symmetric(self):
        key1 = finalize_SPAKE2_symmetric(b"idSymmetric",
                                         b"X_msg", b"Y_msg",
                                         b"K_bytes", b"pw")
        self.assertEqual(hexlify(key1), b"330a7ce7bb010fea7dae7e15b2261315403ab5dc269e461f6eb1cc6566620790")
        key2 = finalize_SPAKE2_symmetric(b"idSymmetric",
                                         b"Y_msg", b"X_msg",
                                         b"K_bytes", b"pw")
        self.assertEqual(hexlify(key1), hexlify(key2))
