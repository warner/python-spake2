from __future__ import division
import hashlib
from .six import integer_types
from .util import (size_bits, size_bytes, unbiased_randrange,
                   bytes_to_number, number_to_bytes)

class _GroupElement:
    def __init__(self, group, x):
        self._group = group
        self._x = x

    def __mul__(self, other):
        if not isinstance(other, integer_types):
            raise TypeError("GroupElement*N requires N be a scalar")
        return self._group.scalarmult(self, other)

    def __add__(self, other):
        if not (isinstance(other, _GroupElement) and
                other._group is self._group):
            raise TypeError("GroupElement+X requires X to be another group element")
        return self._group.add(self, other)

    def __sub__(self, other):
        if not (isinstance(other, _GroupElement) and
                other._group is self._group):
            raise TypeError("GroupElement-X requires X to be another group element")
        return self._group.add(self, other * -1)

    def to_bytes(self):
        return self._group.element_to_bytes(self)

class IntegerGroup:
    element_class = _GroupElement

    def __init__(self, p, q, g, element_hasher, scalar_hasher):
        # these are the public system parameters
        self.p = p # the field size
        self.q = q # the subgroup order, used for scalars
        self.g = g # generator of the subgroup
        self.element_size_bits = size_bits(self.p)
        self.element_size_bytes = size_bytes(self.p)
        self.scalar_size_bytes = size_bytes(self.q)
        _e = element_hasher(b"")
        assert isinstance(_e, bytes)
        assert len(_e) >= self.element_size_bytes
        self.element_hasher = element_hasher
        _s = scalar_hasher(b"")
        assert isinstance(_s, bytes)
        assert len(_s) >= self.scalar_size_bytes
        self.scalar_hasher = scalar_hasher

        # double-check that the generator has the right order
        gen = self.element_class(self, self.g)
        assert (gen * self.q)._x == 1

        self.identity = self.element_class(self, self.g)

    def random_scalar(self, entropy_f):
        exp = unbiased_randrange(0, self.q, entropy_f)
        return exp

    def random_element(self, entropy_f):
        # we know the discrete log of this value
        exp = self.random_scalar(entropy_f)
        element = self.scalarmult_base(exp)
        return exp, element

    def arbitrary_element(self, seed):
        # we do *not* know the discrete log of this one. Nobody should.
        assert isinstance(seed, bytes)
        processed_seed = self.element_hasher(seed)[:self.element_size_bytes]
        assert isinstance(processed_seed, bytes)
        assert len(processed_seed) == self.element_size_bytes
        # The larger (non-prime-order) group (Zp*) we're using has order
        # p-1. The smaller (prime-order) subgroup has order q. Subgroup
        # orders always divide the larger group order, so r*q=p-1 for
        # some integer r. If h is an arbitrary element of the larger
        # group Zp*, then e=h^r will be an element of the subgroup. If h
        # is selected uniformly at random, so will e, and nobody will
        # know its discrete log. We can enforce this for pre-selected
        # parameters by choosing h as the output of a hash function.
        r = (self.p - 1) // self.q
        assert r * self.q == self.p - 1
        h = bytes_to_number(processed_seed) % self.p
        element = self.element_class(self, pow(h, r, self.p))
        assert self.is_member(element)
        return element

    def is_member(self, e):
        if not e._group is self:
            return False
        if pow(e._x, self.q, self.p) == 1:
            return True
        return False

    def scalar_to_bytes(self, i):
        # both for hashing into transcript, and save/restore of
        # intermediate state
        assert isinstance(i, integer_types)
        assert 0 <= 0 < self.q
        return number_to_bytes(i, self.q)

    def scalar_from_bytes(self, b, allow_wrap):
        # for restore of intermediate state, and password_to_scalar .
        # Note that encoded scalars are stored locally, and not accepted
        # from external attackers.
        assert isinstance(b, bytes)
        assert len(b) == self.scalar_size_bytes
        i = bytes_to_number(b)
        if allow_wrap: # for password_to_scalar
            i = i % self.q
        assert 0 <= i < self.q, (0, i, self.q)
        return i

    def element_to_bytes(self, e):
        # for sending to other side, and hashing into transcript
        assert isinstance(e, _GroupElement)
        assert e._group is self
        return number_to_bytes(e._x, self.p)

    def element_from_bytes(self, b):
        # for receiving from other side: test group membership here
        assert isinstance(b, bytes)
        assert len(b) == self.element_size_bytes
        i = bytes_to_number(b)
        assert 1 <= i < self.p  # Zp* excludes 0
        e = self.element_class(self, i)
        assert self.is_member(e)
        return e

    def scalarmult(self, e1, i):
        assert isinstance(e1, _GroupElement)
        assert e1._group is self
        assert isinstance(i, integer_types)
        return self.element_class(self, pow(e1._x, i % self.q, self.p))

    def scalarmult_base(self, i):
        e1 = self.element_class(self, self.g)
        return self.scalarmult(e1, i)

    def add(self, e1, e2):
        assert isinstance(e1, _GroupElement)
        assert e1._group is self
        assert isinstance(e2, _GroupElement)
        assert e2._group is self
        return self.element_class(self, (e1._x * e2._x) % self.p)

    def invert_scalar(self, i):
        assert isinstance(i, integer_types)
        return (-i) % self.q

    def password_to_scalar(self, pw):
        assert isinstance(pw, bytes)
        b = self.scalar_hasher(pw)
        assert len(b) >= self.scalar_size_bytes
        # I don't think this needs to be uniform
        return self.scalar_from_bytes(b[:self.scalar_size_bytes],
                                      allow_wrap=True)

def sha256(b):
    return hashlib.sha256(b).digest()
def sha512(b):
    return hashlib.sha512(b).digest()
def hash1024(b):
    return b"".join([sha512(b"0:"+b), sha512(b"1:"+b)])
def hash2048(b):
    return b"".join([sha512(b"0:"+b), sha512(b"1:"+b),
                     sha512(b"2:"+b), sha512(b"3:"+b)])
def hash3072(b):
    return b"".join([sha512(b"0:"+b), sha512(b"1:"+b),
                     sha512(b"2:"+b), sha512(b"3:"+b),
                     sha512(b"4:"+b), sha512(b"5:"+b)])


# The original J-PAKE demo (java) code,
# http://haofeng66.googlepages.com/JPAKEDemo.java , recommended using groups
# from this NIST document:
# http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/DSA2_All.pdf

# L=1024, N=160
I1024 = IntegerGroup(
    p=0xE0A67598CD1B763BC98C8ABB333E5DDA0CD3AA0E5E1FB5BA8A7B4EABC10BA338FAE06DD4B90FDA70D7CF0CB0C638BE3341BEC0AF8A7330A3307DED2299A0EE606DF035177A239C34A912C202AA5F83B9C4A7CF0235B5316BFC6EFB9A248411258B30B839AF172440F32563056CB67A861158DDD90E6A894C72A5BBEF9E286C6B,
    q=0xE950511EAB424B9A19A2AEB4E159B7844C589C4F,
    g=0xD29D5121B0423C2769AB21843E5A3240FF19CACC792264E3BB6BE4F78EDD1B15C4DFF7F1D905431F0AB16790E1F773B5CE01C804E509066A9919F5195F4ABC58189FD9FF987389CB5BEDF21B4DAB4F8B76A055FFE2770988FE2EC2DE11AD92219F0B351869AC24DA3D7BA87011A701CE8EE7BFE49486ED4527B7186CA4610A75,
    element_hasher = hash1024,
    scalar_hasher = sha256)

# L=2048, N=224
I2048 = IntegerGroup(
    p=0xC196BA05AC29E1F9C3C72D56DFFC6154A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A067CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE428782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE619ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD92D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BFFAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E5320121496DC65B3930E38047294FF877831A16D5228418DE8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A0402A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83,
    q=0x90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D,
    g=0xA59A749A11242C58C894E9E5A91804E8FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35FC9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E5048B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B7159592E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E5745EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDFD049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E695515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED200AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085,
    element_hasher=hash2048,
    scalar_hasher=sha256)

# L=3072, N=256
I3072 = IntegerGroup(
    p=0x90066455B5CFC38F9CAA4A48B4281F292C260FEEF01FD61037E56258A7795A1C7AD46076982CE6BB956936C6AB4DCFE05E6784586940CA544B9B2140E1EB523F009D20A7E7880E4E5BFA690F1B9004A27811CD9904AF70420EEFD6EA11EF7DA129F58835FF56B89FAA637BC9AC2EFAAB903402229F491D8D3485261CD068699B6BA58A1DDBBEF6DB51E8FE34E8A78E542D7BA351C21EA8D8F1D29F5D5D15939487E27F4416B0CA632C59EFD1B1EB66511A5A0FBF615B766C5862D0BD8A3FE7A0E0DA0FB2FE1FCB19E8F9996A8EA0FCCDE538175238FC8B0EE6F29AF7F642773EBE8CD5402415A01451A840476B2FCEB0E388D30D4B376C37FE401C2A2C2F941DAD179C540C1C8CE030D460C4D983BE9AB0B20F69144C1AE13F9383EA1C08504FB0BF321503EFE43488310DD8DC77EC5B8349B8BFE97C2C560EA878DE87C11E3D597F1FEA742D73EEC7F37BE43949EF1A0D15C3F3E3FC0A8335617055AC91328EC22B50FC15B941D3D1624CD88BC25F3E941FDDC6200689581BFEC416B4B2CB73,
    q=0xCFA0478A54717B08CE64805B76E5B14249A77A4838469DF7F7DC987EFCCFB11D,
    g=0x5E5CBA992E0A680D885EB903AEA78E4A45A469103D448EDE3B7ACCC54D521E37F84A4BDD5B06B0970CC2D2BBB715F7B82846F9A0C393914C792E6A923E2117AB805276A975AADB5261D91673EA9AAFFEECBFA6183DFCB5D3B7332AA19275AFA1F8EC0B60FB6F66CC23AE4870791D5982AAD1AA9485FD8F4A60126FEB2CF05DB8A7F0F09B3397F3937F2E90B9E5B9C9B6EFEF642BC48351C46FB171B9BFA9EF17A961CE96C7E7A7CC3D3D03DFAD1078BA21DA425198F07D2481622BCE45969D9C4D6063D72AB7A0F08B2F49A7CC6AF335E08C4720E31476B67299E231F8BD90B39AC3AE3BE0C6B6CACEF8289A2E2873D58E51E029CAFBD55E6841489AB66B5B4B9BA6E2F784660896AFF387D92844CCB8B69475496DE19DA2E58259B090489AC8E62363CDF82CFD8EF2A427ABCD65750B506F56DDE3B988567A88126B914D7828E2B63A6D7ED0747EC59E0E0A23CE7D8A74C1D2C2A7AFB6A29799620F00E11C33787F7DED3B30E1A22D09F1FBDA1ABBBFBF25CAE05A13F812E34563F99410E73B,
    element_hasher=hash3072,
    scalar_hasher=sha256)
