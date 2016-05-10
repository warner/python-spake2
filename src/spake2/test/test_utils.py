import unittest
from spake2 import util
from .common import PRG

class Utils(unittest.TestCase):
    def test_binsize(self):
        def sizebb(maxval):
            num_bits = util.size_bits(maxval)
            num_bytes = util.size_bytes(maxval)
            return (num_bytes, num_bits)
        self.assertEqual(sizebb(0x0f), (1, 4))
        self.assertEqual(sizebb(0x1f), (1, 5))
        self.assertEqual(sizebb(0x10), (1, 5))
        self.assertEqual(sizebb(0xff), (1, 8))
        self.assertEqual(sizebb(0x100), (2, 9))
        self.assertEqual(sizebb(0x101), (2, 9))
        self.assertEqual(sizebb(0x1fe), (2, 9))
        self.assertEqual(sizebb(0x1ff), (2, 9))
        self.assertEqual(sizebb(2**255-19), (32, 255))

    def test_number_to_bytes(self):
        n2b = util.number_to_bytes
        self.assertEqual(n2b(0x00, 0xff), b"\x00")
        self.assertEqual(n2b(0x01, 0xff), b"\x01")
        self.assertEqual(n2b(0xff, 0xff), b"\xff")
        self.assertEqual(n2b(0x100, 0xffff), b"\x01\x00")
        self.assertEqual(n2b(0x101, 0xffff), b"\x01\x01")
        self.assertEqual(n2b(0x102, 0xffff), b"\x01\x02")
        self.assertEqual(n2b(0x1fe, 0xffff), b"\x01\xfe")
        self.assertEqual(n2b(0x1ff, 0xffff), b"\x01\xff")
        self.assertEqual(n2b(0x200, 0xffff), b"\x02\x00")
        self.assertEqual(n2b(0xffff, 0xffff), b"\xff\xff")
        self.assertEqual(n2b(0x10000, 0xffffff), b"\x01\x00\x00")
        self.assertEqual(n2b(0x1, 0xffffffff), b"\x00\x00\x00\x01")
        self.assertRaises(ValueError, n2b, 0x10000, 0xff)

    def test_bytes_to_number(self):
        b2n = util.bytes_to_number
        self.assertEqual(b2n(b"\x00"), 0x00)
        self.assertEqual(b2n(b"\x01"), 0x01)
        self.assertEqual(b2n(b"\xff"), 0xff)
        self.assertEqual(b2n(b"\x01\x00"), 0x0100)
        self.assertEqual(b2n(b"\x01\x01"), 0x0101)
        self.assertEqual(b2n(b"\x01\x02"), 0x0102)
        self.assertEqual(b2n(b"\x01\xfe"), 0x01fe)
        self.assertEqual(b2n(b"\x01\xff"), 0x01ff)
        self.assertEqual(b2n(b"\x02\x00"), 0x0200)
        self.assertEqual(b2n(b"\xff\xff"), 0xffff)
        self.assertEqual(b2n(b"\x01\x00\x00"), 0x010000)
        self.assertEqual(b2n(b"\x00\x00\x00\x01"), 0x01)
        self.assertRaises(TypeError, b2n, 42)
        if type("") != type(b""):
            self.assertRaises(TypeError, b2n, "not bytes")

    def test_mask(self):
        gen = util.generate_mask
        self.assertEqual(gen(0x01), (0x01, 1))
        self.assertEqual(gen(0x02), (0x03, 1))
        self.assertEqual(gen(0x03), (0x03, 1))
        self.assertEqual(gen(0x04), (0x07, 1))
        self.assertEqual(gen(0x07), (0x07, 1))
        self.assertEqual(gen(0x08), (0x0f, 1))
        self.assertEqual(gen(0x09), (0x0f, 1))
        self.assertEqual(gen(0x0f), (0x0f, 1))
        self.assertEqual(gen(0x10), (0x1f, 1))
        self.assertEqual(gen(0x7f), (0x7f, 1))
        self.assertEqual(gen(0x80), (0xff, 1))
        self.assertEqual(gen(0xff), (0xff, 1))
        self.assertEqual(gen(0x0100), (0x01, 2))
        self.assertEqual(gen(2**255-19), (0x7f, 32))
        mask = util.mask_list_of_ints
        self.assertEqual(mask(0x03, [0xff, 0x55, 0xaa]), [0x03, 0x55, 0xaa])
        self.assertEqual(mask(0xff, [0xff]), [0xff])
    def test_l2n(self):
        l2n = util.list_of_ints_to_number
        self.assertEqual(l2n([0x00]), 0x00)
        self.assertEqual(l2n([0x01]), 0x01)
        self.assertEqual(l2n([0x7f]), 0x7f)
        self.assertEqual(l2n([0x80]), 0x80)
        self.assertEqual(l2n([0xff]), 0xff)
        self.assertEqual(l2n([0x01, 0x00]), 0x0100)

    def test_unbiased_randrange(self):
        for seed in range(1000):
            self.do_test_unbiased_randrange(0, 254, seed)
            self.do_test_unbiased_randrange(0, 255, seed)
            self.do_test_unbiased_randrange(0, 256, seed)
            self.do_test_unbiased_randrange(0, 257, seed)
            self.do_test_unbiased_randrange(1, 257, seed)

    def do_test_unbiased_randrange(self, start, stop, seed):
        seed_b = str(seed).encode("ascii")
        num = util.unbiased_randrange(start, stop, entropy_f=PRG(seed_b))
        self.assertTrue(start <= num < stop, (num, seed))
