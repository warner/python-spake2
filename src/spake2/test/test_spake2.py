
import unittest
from spake2 import spake2
from spake2.parameters.i1024 import Params1024
from spake2.parameters.i3072 import Params3072
from spake2.spake2 import SPAKE2_A, SPAKE2_B, SPAKE2_Symmetric
from binascii import hexlify
from hashlib import sha256
from .common import PRG

class Basic(unittest.TestCase):
    def test_success(self):
        pw = b"password"
        sA,sB = SPAKE2_A(pw), SPAKE2_B(pw)
        m1A,m1B = sA.start(), sB.start()
        kA,kB = sA.finish(m1B), sB.finish(m1A)
        self.assertEqual(hexlify(kA), hexlify(kB))
        self.assertEqual(len(kA), len(sha256().digest()))

    def test_success_id(self):
        pw = b"password"
        sA = SPAKE2_A(pw, idA=b"alice", idB=b"bob")
        sB = SPAKE2_B(pw, idA=b"alice", idB=b"bob")
        m1A,m1B = sA.start(), sB.start()
        kA,kB = sA.finish(m1B), sB.finish(m1A)
        self.assertEqual(hexlify(kA), hexlify(kB))
        self.assertEqual(len(kA), len(sha256().digest()))

    def test_failure_wrong_password(self):
        pw = b"password"
        sA,sB = SPAKE2_A(pw), SPAKE2_B(b"passwerd")
        m1A,m1B = sA.start(), sB.start()
        kA,kB = sA.finish(m1B), sB.finish(m1A)
        self.assertNotEqual(hexlify(kA), hexlify(kB))
        self.assertEqual(len(kA), len(sha256().digest()))
        self.assertEqual(len(kB), len(sha256().digest()))

    def test_failure_wrong_id(self):
        pw = b"password"
        sA = SPAKE2_A(pw, idA=b"alice", idB=b"bob")
        sB = SPAKE2_B(pw, idA=b"not-alice", idB=b"bob")
        m1A,m1B = sA.start(), sB.start()
        kA,kB = sA.finish(m1B), sB.finish(m1A)
        self.assertNotEqual(hexlify(kA), hexlify(kB))

    def test_failure_swapped_id(self):
        pw = b"password"
        sA = SPAKE2_A(pw, idA=b"alice", idB=b"bob")
        sB = SPAKE2_B(pw, idA=b"bob", idB=b"alice")
        m1A,m1B = sA.start(), sB.start()
        kA,kB = sA.finish(m1B), sB.finish(m1A)
        self.assertNotEqual(hexlify(kA), hexlify(kB))

    def test_reflect(self):
        pw = b"password"
        s1 = SPAKE2_A(pw)
        m1 = s1.start()
        reflected = b"B" + m1[1:]
        self.assertRaises(spake2.ReflectionThwarted, s1.finish, reflected)


class OtherEntropy(unittest.TestCase):
    def test_entropy(self):
        fr = PRG(b"seed")
        pw = b"password"
        sA,sB = SPAKE2_A(pw, entropy_f=fr), SPAKE2_B(pw, entropy_f=fr)
        m1A1,m1B1 = sA.start(), sB.start()
        kA1,kB1 = sA.finish(m1B1), sB.finish(m1A1)
        self.assertEqual(hexlify(kA1), hexlify(kB1))

        # run it again with the same entropy stream: all messages should be
        # identical
        fr = PRG(b"seed")
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

    def test_success_id(self):
        pw = b"password"
        s1 = SPAKE2_Symmetric(pw, idSymmetric=b"sym")
        s2 = SPAKE2_Symmetric(pw, idSymmetric=b"sym")
        m1,m2 = s1.start(), s2.start()
        k1,k2 = s1.finish(m2), s2.finish(m1)
        self.assertEqual(hexlify(k1), hexlify(k2))

    def test_failure_wrong_password(self):
        s1,s2 = SPAKE2_Symmetric(b"password"), SPAKE2_Symmetric(b"wrong")
        m1,m2 = s1.start(), s2.start()
        k1,k2 = s1.finish(m2), s2.finish(m1)
        self.assertNotEqual(hexlify(k1), hexlify(k2))

    def test_failure_wrong_id(self):
        pw = b"password"
        s1 = SPAKE2_Symmetric(pw, idSymmetric=b"sym")
        s2 = SPAKE2_Symmetric(pw, idSymmetric=b"not-sym")
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

        sS = SPAKE2_Symmetric(pw)
        sS.start()
        self.assertRaises(spake2.OffSides, sS.finish, msgA)
        sS = SPAKE2_Symmetric(pw)
        sS.start()
        self.assertRaises(spake2.OffSides, sS.finish, msgB)


    def test_unserialize_wrong(self):
        s = SPAKE2_A(b"password", params=Params1024)
        s.start()
        data = s.serialize()
        SPAKE2_A.from_serialized(data, params=Params1024) # this is ok
        self.assertRaises(spake2.WrongGroupError,
                          SPAKE2_A.from_serialized, data) # default is P2048
        self.assertRaises(spake2.WrongGroupError,
                          SPAKE2_A.from_serialized, data,
                          params=Params3072)
        self.assertRaises(spake2.WrongSideSerialized,
                          SPAKE2_B.from_serialized, data,
                          params=Params1024)

        ss = SPAKE2_Symmetric(b"password", params=Params1024)
        ss.start()
        sdata = ss.serialize()

        SPAKE2_Symmetric.from_serialized(sdata, params=Params1024) # ok
        self.assertRaises(spake2.WrongGroupError, # default is P2048
                          SPAKE2_Symmetric.from_serialized, sdata)
        self.assertRaises(spake2.WrongGroupError,
                          SPAKE2_Symmetric.from_serialized, sdata,
                          params=Params3072)
        self.assertRaises(spake2.WrongSideSerialized,
                          SPAKE2_Symmetric.from_serialized, data, # from A
                          params=Params1024)

if __name__ == '__main__':
    unittest.main()

