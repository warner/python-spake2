import unittest
from binascii import hexlify
from spake2 import finalize

class SPAKE2(unittest.TestCase):
    def test_asymmetric(self):
        key = finalize.finalize_SPAKE2(b"idA", b"idB", b"X_msg", b"Y_msg",
                                       b"K_bytes", b"pw")
        self.assertEqual(hexlify(key), b"b90002522d29f405fbd5de17741c45c96dec0a4d48c44b05ad53c374c5a48a30")

    def test_symmetric(self):
        key1 = finalize.finalize_SPAKE2_symmetric(b"idSymmetric",
                                                  b"X_msg", b"Y_msg",
                                                  b"K_bytes", b"pw")
        self.assertEqual(hexlify(key1), b"8a3738cdf3d99390d8b4d2e581b88184d7ab59125767f5b5a84d5643dbab1cb7")
        key2 = finalize.finalize_SPAKE2_symmetric(b"idSymmetric",
                                                  b"Y_msg", b"X_msg",
                                                  b"K_bytes", b"pw")
        self.assertEqual(hexlify(key1), hexlify(key2))
