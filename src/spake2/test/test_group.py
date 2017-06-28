import unittest
from binascii import hexlify
from hashlib import sha256
from spake2 import groups, ed25519_group
from spake2.parameters.i1024 import Params1024
from spake2.parameters.i2048 import Params2048
from spake2.parameters.i3072 import Params3072
from spake2.parameters.ed25519 import ParamsEd25519
from spake2.spake2 import SPAKE2_A, SPAKE2_B
from .common import PRG

ALL_INTEGER_GROUPS = [groups.I1024, groups.I2048, groups.I3072]
ALL_GROUPS = ALL_INTEGER_GROUPS + [ed25519_group.Ed25519Group]
ALL_INTEGER_PARAMS = [Params1024, Params2048, Params3072]
ALL_PARAMS = ALL_INTEGER_PARAMS + [ParamsEd25519]

def random_element(g, entropy_f):
    s = g.random_scalar(entropy_f)
    return s, g.Base.scalarmult(s)

class Group(unittest.TestCase):
    def assertElementsEqual(self, e1, e2, msg=None):
        self.assertEqual(hexlify(e1.to_bytes()), hexlify(e2.to_bytes()), msg)
    def assertElementsNotEqual(self, e1, e2, msg=None):
        self.assertNotEqual(hexlify(e1.to_bytes()), hexlify(e2.to_bytes()), msg)

    def test_basic(self):
        for g in ALL_GROUPS:
            fr = PRG(b"0")
            i = g.random_scalar(entropy_f=fr)
            self.assertTrue(0 <= i < g.order())
            b = g.scalar_to_bytes(i)
            self.assertEqual(len(b), g.scalar_size_bytes)
            self.assertEqual(i, g.bytes_to_scalar(b))
            e = g.Base.scalarmult(i)
            self.assertEqual(len(e.to_bytes()), g.element_size_bytes)
            e = g.arbitrary_element(b"")
            self.assertEqual(len(e.to_bytes()), g.element_size_bytes)
            self.assertElementsEqual(e, g.bytes_to_element(e.to_bytes()))

    def test_math(self):
        for g in ALL_GROUPS:
            sb = g.Base.scalarmult
            e0 = sb(0)
            self.assertElementsEqual(e0, g.Zero)
            e1 = sb(1)
            e2 = sb(2)
            self.assertElementsEqual(e1.add(e0), e1)
            self.assertElementsEqual(e1.add(e1), e1.scalarmult(2))
            self.assertElementsEqual(e1.scalarmult(2), e2)
            self.assertElementsEqual(e1.add(e2), e2.add(e1))
            e_m1 = sb(g.order()-1)
            self.assertElementsEqual(e_m1, sb(-1))
            self.assertElementsEqual(e_m1.add(e1), e0)
            e3 = sb(3)
            e4 = sb(4)
            e5 = sb(5)
            self.assertElementsEqual(e2.add(e3), e1.add(e4))
            #self.assertElementsEqual(e5 - e3, e2)
            self.assertElementsEqual(e1.scalarmult(g.order()), e0)
            self.assertElementsEqual(e2.scalarmult(g.order()), e0)
            self.assertElementsEqual(e3.scalarmult(g.order()), e0)
            self.assertElementsEqual(e4.scalarmult(g.order()), e0)
            self.assertElementsEqual(e5.scalarmult(g.order()), e0)

    def test_bad_math(self):
        for g in ALL_GROUPS:
            base = g.Base
            # you cannot multiply two group elements together, only add them
            self.assertRaises(TypeError, lambda: base.scalarmult(base))
            # you cannot add group elements to scalars, you can only multiply
            # group elements *by* scalars
            self.assertRaises(TypeError, lambda: base.add(1))
            self.assertRaises(TypeError, lambda: base.add(-1))

    def test_from_bytes(self):
        for g in ALL_GROUPS:
            fr = PRG(b"0")
            e = g.Base
            self.assertElementsEqual(g.bytes_to_element(e.to_bytes()), e)
            e = g.Base.scalarmult(2)
            self.assertElementsEqual(g.bytes_to_element(e.to_bytes()), e)
            e = g.Base.scalarmult(g.random_scalar(fr))
            self.assertElementsEqual(g.bytes_to_element(e.to_bytes()), e)

        self.assertFalse(groups.I1024._is_member(groups.I2048.Zero))
        for g in ALL_INTEGER_GROUPS:
            # we must bypass the normal API to create an element that's
            # marked as being of the right group, but the actual number is
            # not in the subgroup
            s = groups.number_to_bytes(0, g.p)
            self.assertRaises(ValueError, g.bytes_to_element, s)
            s = groups.number_to_bytes(2, g.p)
            self.assertRaises(ValueError, g.bytes_to_element, s)

    def test_arbitrary_element(self):
        for g in ALL_GROUPS:
            gx = g.arbitrary_element(b"")
            self.assertElementsEqual(gx.scalarmult(-2),
                                     gx.scalarmult(2).scalarmult(-1))
            gy = g.arbitrary_element(b"2")
            self.assertElementsNotEqual(gx, gy)

    def test_blinding(self):
        for g in ALL_GROUPS:
            fr = PRG(b"0")
            _, pubkey = random_element(g, fr)
            _, U = random_element(g, fr)
            pw = g.random_scalar(fr)
            # X+U*pw -U*pw == X
            blinding_factor = U.scalarmult(pw)
            blinded_pubkey = pubkey.add(blinding_factor)
            inverse_pw = (-pw) % g.order()
            inverse_blinding_factor = U.scalarmult(inverse_pw)
            self.assertElementsEqual(inverse_blinding_factor, U.scalarmult(-pw))
            self.assertElementsEqual(U.scalarmult(-pw),
                                     U.scalarmult(pw).scalarmult(-1))
            self.assertElementsEqual(inverse_blinding_factor,
                                     blinding_factor.scalarmult(-1))
            unblinded_pubkey = blinded_pubkey.add(inverse_blinding_factor)
            self.assertElementsEqual(pubkey, unblinded_pubkey)

    def test_password(self):
        for g in ALL_GROUPS:
            i = g.password_to_scalar(b"")
            self.assertTrue(0 <= i < g.order())

    def test_math_trivial(self):
        g = I23
        e1 = g.Base.scalarmult(1)
        e2 = g.Base.scalarmult(2)
        e3 = g.Base.scalarmult(3)
        e4 = g.Base.scalarmult(4)
        e5 = g.Base.scalarmult(5)
        e6 = g.Base.scalarmult(6)
        self.assertEqual([e1._e, e2._e, e3._e, e4._e, e5._e, e6._e],
                         [2, 4, 8, 16, 9, 18])
        self.assertElementsEqual(e1.add(e1), e1.scalarmult(2))
        self.assertElementsEqual(e1.scalarmult(2), e2)
        self.assertElementsEqual(e1.add(e2), e2.add(e1))
        self.assertElementsEqual(e2.add(e3), e1.add(e4))

I23 = groups.IntegerGroup(p=23, q=11, g=2)

class Parameters(unittest.TestCase):
    def test_params(self):
        for p in ALL_PARAMS:
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

    def test_default_is_ed25519(self):
        pw = b"password"
        sA,sB = SPAKE2_A(pw, params=ParamsEd25519), SPAKE2_B(pw)
        m1A,m1B = sA.start(), sB.start()
        kA,kB = sA.finish(m1B), sB.finish(m1A)
        self.assertEqual(hexlify(kA), hexlify(kB))
        self.assertEqual(len(kA), len(sha256().digest()))
