
import unittest
from . import spake2, util, groups, params, six
from .spake2 import SPAKE2_A, SPAKE2_B, SPAKE2_Symmetric
from binascii import hexlify
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
        for counter in count():
            cseed = ("prng-%d-%s" % (counter, seed)).encode("ascii")
            block = sha256(cseed).digest()
            for i in range(len(block)):
                yield block[i:i+1]

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
        num = util.unbiased_randrange(start, stop, entropy_f=PRG(seed))
        self.assertTrue(start <= num < stop, (num, seed))

    def test_xor_keys(self):
        self.assertEqual(util.xor_keys(b"\x00\x00",
                                       b"\xff\xff"), b"\xff\xff")
        self.assertEqual(util.xor_keys(b"\x1c\x02",
                                       b"\x69\x3f"), b"\x75\x3d")

class Group(unittest.TestCase):
    def assertElementsEqual(self, e1, e2, msg=None):
        self.assertEqual(hexlify(e1.to_bytes()), hexlify(e2.to_bytes()), msg)
    def assertElementsNotEqual(self, e1, e2, msg=None):
        self.assertNotEqual(hexlify(e1.to_bytes()), hexlify(e2.to_bytes()), msg)

    def test_basic(self):
        g = groups.I1024
        fr = PRG(0)
        i = g.random_scalar(entropy_f=fr)
        self.assertTrue(0 <= i < g.q)
        b = g.scalar_to_bytes(i)
        self.assertEqual(len(b), g.scalar_size_bytes)
        self.assertEqual(i, g.scalar_from_bytes(b, False))
        i,e = g.random_element(entropy_f=fr)
        self.assertEqual(len(e.to_bytes()), g.element_size_bytes)
        self.assertEqual(g.scalarmult_base(i).to_bytes(), e.to_bytes())
        e = g.arbitrary_element(b"")
        self.assertEqual(len(e.to_bytes()), g.element_size_bytes)
        self.assertElementsEqual(e, g.element_from_bytes(e.to_bytes()))

    def test_math(self):
        g = groups.I1024
        sb = g.scalarmult_base
        e_zero = sb(0)
        e1 = sb(1)
        e2 = sb(2)
        self.assertElementsEqual(e1 + e_zero, e1)
        self.assertElementsEqual(e1 + e1, e1 * 2)
        self.assertElementsEqual(e1 * 2, e2)
        self.assertElementsEqual(e1 + e2, e2 + e1)
        e_m1 = sb(g.q-1)
        self.assertElementsEqual(e_m1, sb(-1))
        self.assertElementsEqual(e_m1 + e1, e_zero)
        e3 = sb(3)
        e4 = sb(4)
        e5 = sb(5)
        self.assertElementsEqual(e2+e3, e1+e4)
        self.assertElementsEqual(e5 - e3, e2)
        self.assertElementsEqual(e1 * g.q, e_zero)
        self.assertElementsEqual(e2 * g.q, e_zero)
        self.assertElementsEqual(e3 * g.q, e_zero)
        self.assertElementsEqual(e4 * g.q, e_zero)
        self.assertElementsEqual(e5 * g.q, e_zero)

    def test_bad_math(self):
        g = groups.I1024
        zero = g.identity
        self.assertRaises(TypeError, lambda: zero * zero)
        self.assertRaises(TypeError, lambda: zero + 1)
        self.assertRaises(TypeError, lambda: zero - 1)

    def test_is_member(self):
        g = groups.I1024
        fr = PRG(0)
        self.assertTrue(g.is_member(g.identity))
        self.assertTrue(g.is_member(g.scalarmult_base(2)))
        self.assertTrue(g.is_member(g.scalarmult_base(3)))
        self.assertTrue(g.is_member(g.random_element(fr)[1]))
        g2 = groups.I2048
        self.assertFalse(g.is_member(g2.identity))
        # we must bypass the normal API to create an element that's marked as
        # being of the right group, but the actual number is not in the
        # subgroup
        self.assertFalse(g.is_member(groups._GroupElement(g, 0)))
        self.assertFalse(g.is_member(groups._GroupElement(g, 2)))

    def test_arbitrary_element(self):
        g = groups.I1024
        gx = g.arbitrary_element(b"")
        # arbitrary_element once had a bug, it returned elements that were
        # not in the subgroup. Test against that.
        self.assertTrue(g.is_member(gx))
        self.assertElementsEqual(gx*-2, (gx*2)*-1)
        gy = g.arbitrary_element(b"2")
        self.assertElementsNotEqual(gx, gy)

    def test_blinding(self):
        g = groups.I1024
        fr = PRG(0)
        _, pubkey = g.random_element(fr)
        _, U = g.random_element(fr)
        pw = g.random_scalar(fr)
        # X+U*pw -U*pw == X
        blinding_factor = U * pw
        blinded_pubkey = pubkey + blinding_factor
        inverse_pw = g.invert_scalar(pw)
        inverse_blinding_factor = U * inverse_pw
        self.assertElementsEqual(inverse_blinding_factor, U * -pw)
        self.assertElementsEqual(U * -pw, (U * pw) * -1)
        self.assertElementsEqual(inverse_blinding_factor, blinding_factor * -1)
        unblinded_pubkey = blinded_pubkey + inverse_blinding_factor
        self.assertElementsEqual(pubkey, unblinded_pubkey)

    def test_password(self):
        g = groups.I1024
        i = g.password_to_scalar(b"")
        self.assertTrue(0 <= i < g.q)

    def test_math_trivial(self):
        g = I23
        e1 = g.scalarmult_base(1)
        e2 = g.scalarmult_base(2)
        e3 = g.scalarmult_base(3)
        e4 = g.scalarmult_base(4)
        e5 = g.scalarmult_base(5)
        e6 = g.scalarmult_base(6)
        self.assertEqual([e1._x, e2._x, e3._x, e4._x, e5._x, e6._x],
                         [2, 4, 8, 16, 9, 18])
        self.assertElementsEqual(e1 + e1, e1 * 2)
        self.assertElementsEqual(e1 * 2, e2)
        self.assertElementsEqual(e1 + e2, e2 + e1)
        self.assertElementsEqual(e2+e3, e1+e4)
        self.assertElementsEqual(e5 - e3, e2)

I23 = groups.IntegerGroup(p=23, q=11, g=2,
                          element_hasher=groups.sha256,
                          scalar_hasher=groups.sha256)


class Basic(unittest.TestCase):
    def test_success(self):
        pw = b"password"
        p = params.Params1024
        sA,sB = SPAKE2_A(pw, params=p), SPAKE2_B(pw, params=p)
        m1A,m1B = sA.start(), sB.start()
        kA,kB = sA.finish(m1B), sB.finish(m1A)
        self.assertEqual(hexlify(kA), hexlify(kB))
        self.assertEqual(len(kA), len(sha256().digest()))

    def test_failure(self):
        pw = b"password"
        sA,sB = SPAKE2_A(pw), SPAKE2_B(b"passwerd")
        m1A,m1B = sA.start(), sB.start()
        kA,kB = sA.finish(m1B), sB.finish(m1A)
        self.assertNotEqual(hexlify(kA), hexlify(kB))
        self.assertEqual(len(kA), len(sha256().digest()))
        self.assertEqual(len(kB), len(sha256().digest()))

    def test_reflect(self):
        pw = b"password"
        s1 = SPAKE2_A(pw)
        m1 = s1.start()
        reflected = b"B" + m1[1:]
        self.assertRaises(spake2.ReflectionThwarted, s1.finish, reflected)

class Parameters(unittest.TestCase):
    def do_tests(self, p):
        pw = b"password"
        sA,sB = SPAKE2_A(pw, params=p), SPAKE2_B(pw, params=p)
        m1A,m1B = sA.start(), sB.start()
        #print len(json.dumps(m1A))
        kA,kB = sA.finish(m1B), sB.finish(m1A)
        self.assertEqual(hexlify(kA), hexlify(kB))
        self.assertEqual(len(kA), len(sha256().digest()))

        sA,sB = SPAKE2_A(pw, params=p), SPAKE2_B(b"passwerd", params=p)
        m1A,m1B = sA.start(), sB.start()
        kA,kB = sA.finish(m1B), sB.finish(m1A)
        self.assertNotEqual(hexlify(kA), hexlify(kB))
        self.assertEqual(len(kA), len(sha256().digest()))
        self.assertEqual(len(kB), len(sha256().digest()))

    def test_params(self):
        for p in [params.Params1024, params.Params2048, params.Params3072]:
            self.do_tests(p)

    def test_default_is_2048(self):
        pw = b"password"
        sA,sB = SPAKE2_A(pw, params=params.Params2048), SPAKE2_B(pw)
        m1A,m1B = sA.start(), sB.start()
        kA,kB = sA.finish(m1B), sB.finish(m1A)
        self.assertEqual(hexlify(kA), hexlify(kB))
        self.assertEqual(len(kA), len(sha256().digest()))


class OtherEntropy(unittest.TestCase):
    def test_entropy(self):
        fr = PRG("seed")
        pw = b"password"
        sA,sB = SPAKE2_A(pw, entropy_f=fr), SPAKE2_B(pw, entropy_f=fr)
        m1A1,m1B1 = sA.start(), sB.start()
        kA1,kB1 = sA.finish(m1B1), sB.finish(m1A1)
        self.assertEqual(hexlify(kA1), hexlify(kB1))

        # run it again with the same entropy stream: all messages should be
        # identical
        fr = PRG("seed")
        sA,sB = SPAKE2_A(pw, entropy_f=fr), SPAKE2_B(pw, entropy_f=fr)
        m1A2,m1B2 = sA.start(), sB.start()
        kA2,kB2 = sA.finish(m1B2), sB.finish(m1A2)
        self.assertEqual(hexlify(kA2), hexlify(kB2))

        self.assertEqual(m1A1, m1A2)
        self.assertEqual(m1B1, m1B2)
        self.assertEqual(kA1, kA2)
        self.assertEqual(kB1, kB2)

class Serialize(unittest.TestCase):
    def test_serialize(self):
        pw = b"password"
        sA,sB = SPAKE2_A(pw), SPAKE2_B(pw)
        self.assertRaises(spake2.SerializedTooEarly, sA.serialize)
        m1A,m1B = sA.start(), sB.start()
        sA = SPAKE2_A.from_serialized(sA.serialize())
        kA,kB = sA.finish(m1B), sB.finish(m1A)
        self.assertEqual(hexlify(kA), hexlify(kB))
        self.assertEqual(len(kA), len(sha256().digest()))

class Symmetric(unittest.TestCase):
    def test_success(self):
        pw = b"password"
        s1,s2 = SPAKE2_Symmetric(pw), SPAKE2_Symmetric(pw)
        m1,m2 = s1.start(), s2.start()
        k1,k2 = s1.finish(m2), s2.finish(m1)
        self.assertEqual(hexlify(k1), hexlify(k2))

    def test_failure(self):
        s1,s2 = SPAKE2_Symmetric(b"password"), SPAKE2_Symmetric(b"wrong")
        m1,m2 = s1.start(), s2.start()
        k1,k2 = s1.finish(m2), s2.finish(m1)
        self.assertNotEqual(hexlify(k1), hexlify(k2))

    def test_serialize(self):
        pw = b"password"
        s1,s2 = SPAKE2_Symmetric(pw), SPAKE2_Symmetric(pw)
        m1,m2 = s1.start(), s2.start()
        s1 = SPAKE2_Symmetric.from_serialized(s1.serialize())
        k1,k2 = s1.finish(m2), s2.finish(m1)
        self.assertEqual(hexlify(k1), hexlify(k2))

    def test_reflect(self):
        pw = b"password"
        s1 = SPAKE2_Symmetric(pw)
        m1 = s1.start()
        # reflect Alice's message back to her
        self.assertRaises(spake2.ReflectionThwarted, s1.finish, m1)

class Errors(unittest.TestCase):
    def test_start_twice(self):
        s = SPAKE2_A(b"password")
        s.start()
        self.assertRaises(spake2.OnlyCallStartOnce, s.start)

    def test_finish_twice(self):
        pw = b"password"
        sA,sB = SPAKE2_A(pw), SPAKE2_B(pw)
        sA.start()
        msg = sB.start()
        sA.finish(msg)
        self.assertRaises(spake2.OnlyCallFinishOnce, sA.finish, msg)

    def test_wrong_side(self):
        pw = b"password"
        sA1,sA2 = SPAKE2_A(pw), SPAKE2_A(pw)
        sA1.start()
        msgA = sA2.start()
        self.assertRaises(spake2.OffSides, sA1.finish, msgA)

        sB1,sB2 = SPAKE2_B(pw), SPAKE2_B(pw)
        sB1.start()
        msgB = sB2.start()
        self.assertRaises(spake2.OffSides, sB1.finish, msgB)

        self.assertRaises(spake2.OffSides, sA2.finish, b"C"+msgB)


    def test_unserialize_wrong(self):
        s = SPAKE2_A(b"password", params=params.Params1024)
        s.start()
        data = s.serialize()
        SPAKE2_A.from_serialized(data, params=params.Params1024) # this is ok
        self.assertRaises(spake2.WrongGroupError,
                          SPAKE2_A.from_serialized, data) # default is P2048
        self.assertRaises(spake2.WrongGroupError,
                          SPAKE2_A.from_serialized, data,
                          params=params.Params3072)
        self.assertRaises(spake2.WrongSideSerialized,
                          SPAKE2_B.from_serialized, data,
                          params=params.Params1024)

if __name__ == '__main__':
    unittest.main()

