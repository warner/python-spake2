
import os, binascii, re
from hashlib import sha256

# TODO: include idP and idQ as strings
# TODO: include X and Y in the hash
# TODO: switch to ECC


class PAKEError(Exception):
    pass
class BadUVString(Exception):
    """The U and V strings must be simple ASCII for serializability"""

def orderlen(order):
    return (1+len("%x"%order))//2 # bytes

def number_to_string(num, orderlen):
    if orderlen is None:
        s = "%x" % num
        if len(s)%2:
            s = "0"+s
        string = binascii.unhexlify(s)
    else:
        fmt_str = "%0" + str(2*orderlen) + "x"
        string = binascii.unhexlify(fmt_str % num)
        assert len(string) == orderlen, (len(string), orderlen)
    return string

def string_to_number(string):
    return int(binascii.hexlify(string), 16)

# inverse_mod is copied from my python-ecdsa package, originally written by
# Peter Pearson and placed in the public domain.
def inverse_mod( a, m ):
  """Inverse of a mod m."""

  if a < 0 or m <= a: a = a % m

  # From Ferguson and Schneier, roughly:

  c, d = a, m
  uc, vc, ud, vd = 1, 0, 0, 1
  while c != 0:
    q, c, d = divmod( d, c ) + ( c, )
    uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc

  # At this point, d is the GCD, and ud*a+vd*m = d.
  # If d == 1, this means that ud is a inverse.

  assert d == 1
  if ud > 0: return ud
  else: return ud + m

class Params:
    def __init__(self, p, q, g, u="public_U", v="public_V"):
        # these are the public system parameters
        self.p = p
        self.q = q
        self.g = g
        self.orderlen = orderlen(self.p)

        # u and v are defined as "randomly chosen elements of the group". It
        # is important that nobody knows their discrete log (if your
        # parameter-provider picked a secret 'haha' and told you to use
        # u=pow(g,haha,p), you couldn't tell that u wasn't randomly chosen,
        # but they could then mount an active attack against your PAKE
        # session).
        #
        # The safe way to choose these is to hash a public string. We require
        # a limited character set so we can serialize it later.

        if not re.search(r'^[0-9a-zA-Z_+-. ]*$', u):
            raise BadUVString()
        if not re.search(r'^[0-9a-zA-Z_+-. ]*$', v):
            raise BadUVString()

        self.u_str = u
        self.v_str = v
        self.u = string_to_number(sha256(u.encode("ascii")).digest()) % self.p
        self.v = string_to_number(sha256(v.encode("ascii")).digest()) % self.p
        self.inv_u = inverse_mod(self.u, self.p)
        self.inv_v = inverse_mod(self.v, self.p)

# params_80 is roughly as secure as an 80-bit symmetric key, and uses a
# 1024-bit modulus. params_112 uses a 2048-bit modulus, and params_128 uses a
# 3072-bit modulus.

params_80 = Params(p=0xfd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7,
                   q=0x9760508f15230bccb292b982a2eb840bf0581cf5,
                   g=0xf7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a)

# 112, 128 from NIST
params_112 = Params(p=0xC196BA05AC29E1F9C3C72D56DFFC6154A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A067CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE428782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE619ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD92D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BFFAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E5320121496DC65B3930E38047294FF877831A16D5228418DE8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A0402A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83,
                    q=0x90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D,
                    g=0xA59A749A11242C58C894E9E5A91804E8FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35FC9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E5048B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B7159592E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E5745EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDFD049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E695515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED200AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085)

params_128 = Params(p=0x90066455B5CFC38F9CAA4A48B4281F292C260FEEF01FD61037E56258A7795A1C7AD46076982CE6BB956936C6AB4DCFE05E6784586940CA544B9B2140E1EB523F009D20A7E7880E4E5BFA690F1B9004A27811CD9904AF70420EEFD6EA11EF7DA129F58835FF56B89FAA637BC9AC2EFAAB903402229F491D8D3485261CD068699B6BA58A1DDBBEF6DB51E8FE34E8A78E542D7BA351C21EA8D8F1D29F5D5D15939487E27F4416B0CA632C59EFD1B1EB66511A5A0FBF615B766C5862D0BD8A3FE7A0E0DA0FB2FE1FCB19E8F9996A8EA0FCCDE538175238FC8B0EE6F29AF7F642773EBE8CD5402415A01451A840476B2FCEB0E388D30D4B376C37FE401C2A2C2F941DAD179C540C1C8CE030D460C4D983BE9AB0B20F69144C1AE13F9383EA1C08504FB0BF321503EFE43488310DD8DC77EC5B8349B8BFE97C2C560EA878DE87C11E3D597F1FEA742D73EEC7F37BE43949EF1A0D15C3F3E3FC0A8335617055AC91328EC22B50FC15B941D3D1624CD88BC25F3E941FDDC6200689581BFEC416B4B2CB73,
                    q=0xCFA0478A54717B08CE64805B76E5B14249A77A4838469DF7F7DC987EFCCFB11D,
                    g=0x5E5CBA992E0A680D885EB903AEA78E4A45A469103D448EDE3B7ACCC54D521E37F84A4BDD5B06B0970CC2D2BBB715F7B82846F9A0C393914C792E6A923E2117AB805276A975AADB5261D91673EA9AAFFEECBFA6183DFCB5D3B7332AA19275AFA1F8EC0B60FB6F66CC23AE4870791D5982AAD1AA9485FD8F4A60126FEB2CF05DB8A7F0F09B3397F3937F2E90B9E5B9C9B6EFEF642BC48351C46FB171B9BFA9EF17A961CE96C7E7A7CC3D3D03DFAD1078BA21DA425198F07D2481622BCE45969D9C4D6063D72AB7A0F08B2F49A7CC6AF335E08C4720E31476B67299E231F8BD90B39AC3AE3BE0C6B6CACEF8289A2E2873D58E51E029CAFBD55E6841489AB66B5B4B9BA6E2F784660896AFF387D92844CCB8B69475496DE19DA2E58259B090489AC8E62363CDF82CFD8EF2A427ABCD65750B506F56DDE3B988567A88126B914D7828E2B63A6D7ED0747EC59E0E0A23CE7D8A74C1D2C2A7AFB6A29799620F00E11C33787F7DED3B30E1A22D09F1FBDA1ABBBFBF25CAE05A13F812E34563F99410E73B)


def randrange(order, entropy):
    """Return a random integer k such that 0 <= k < order, uniformly
    distributed across that range. For simplicity, this only behaves well if
    'order' is fairly close (but below) a power of 256. The try-try-again
    algorithm we use takes longer and longer time (on average) to complete as
    'order' falls, rising to a maximum of avg=512 loops for the worst-case
    (256**k)+1 . All of the standard curves behave well. There is a cutoff at
    10k loops (which raises RuntimeError) to prevent an infinite loop when
    something is really broken like the entropy function not working.

    Note that this function is not declared to be forwards-compatible: we may
    change the behavior in future releases. The entropy= argument (which
    should get a callable that behaves like os.entropy) can be used to
    achieve stability within a given release (for repeatable unit tests), but
    should not be used as a long-term-compatible key generation algorithm.
    """
    # we could handle arbitrary orders (even 256**k+1) better if we created
    # candidates bit-wise instead of byte-wise, which would reduce the
    # worst-case behavior to avg=2 loops, but that would be more complex. The
    # change would be to round the order up to a power of 256, subtract one
    # (to get 0xffff..), use that to get a byte-long mask for the top byte,
    # generate the len-1 entropy bytes, generate one extra byte and mask off
    # the top bits, then combine it with the rest. Requires jumping back and
    # forth between strings and integers a lot.

    assert order > 1
    num_bytes = orderlen(order)
    dont_try_forever = 10000 # gives about 2**-60 failures for worst case
    while dont_try_forever > 0:
        dont_try_forever -= 1
        candidate = string_to_number(entropy(num_bytes))
        if candidate < order:
            return candidate
        continue
    raise RuntimeError("randrange() tried hard but gave up, either something"
                       " is very wrong or you got realllly unlucky. Order was"
                       " %x" % order)

class SPAKE2:
    """This class manages one half of a SPAKE2 key negotiation.

    The protocol has four public system parameters: a group, a generator, and
    two group elements (one each for sides P and Q). The participants must
    agree ahead of time which role each will play (either P or Q).

    Create an instance with SPAKE2(password=pw, side='P') (or side='Q'), where
    'password' is either a number (0 < number < params.q-1) or a bytestring.
    You can also pass an optional params= value (one of [params_80,
    params_112, params_128], for increasing levels of security and CPU
    usage). Any two PAKE communicating instances must use different
    side= values.

    Once constructed, you will need to call one() and two() in order, passing
    the output of one() over the wire, where it forms the input to two():

        my_msg1 = p.one()
        send(my_msg1)
        their_msg1 = receive()
        key = p.two(their_msg1)

    The secret 'key' that comes out will be a bytestring (the output of a
    hash function). If both sides used the same password, both sides will
    wind up with the same key, otherwise they will have different keys. You
    will probably want to confirm this equivalence before relying upon it
    (but don't reveal the key to the other side in doing so, in case you
    aren't talking to the right party and your keys are really different).
    Note that this introduces an additional asymmetry to the protocol (one
    side learns of the mismatch before the other). For example:

        A: hhkey = sha256(sha256(Akey).digest()).digest()
        A: send(hhkey)
          B: hhkey = receive()
          B: assert sha256(sha256(Bkey).digest()).digest() == hhkey
          B: hkey = sha256(Bkey).digest()
          B: send(hkey)
        A: hkey = receive()
        A: assert sha256(Akey).digest() == hkey

    If you can't keep the SPAKE2 instance alive for the whole negotiation, you
    can persist the important data from an instance with data=p.to_json(),
    and then reconstruct the instance with p=SPAKE2.from_json(data). The
    instance data is sensitive: protect it better than you would the original
    password. An attacker who learns the instance state from both sides will
    be able to reconstruct the shared key. These functions return a
    dictionary: you are responsible for invoking e.g. simplejson.dumps() to
    serialize it into a string that can be written to disk. For params_80,
    the serialized JSON is typically about 1236 bytes after construction and
    1528 bytes after one().

     p = SPAKE2(password)
     send(p.one())
     open('save.json','w').write(simplejson.dumps(p.to_json()))
     ...
     p = SPAKE2.from_json(simplejson.loads(open('save.json').read()))
     key = p.two(receive())

    The message returned by one() is a small dictionary, safe to serialize as
    a JSON object, and will survive being deserialized in a javascript
    environment (i.e. the large numbers are encoded as hex strings, since JS
    does not have bigints). If you wish for smaller messages, the SPAKE2
    instance has pack_msg() and unpack_msg() methods to encode/decode these
    strings into smaller bytestrings. The encoding scheme is slightly
    different for each params= value. For params_80, a JSON encoding of
    one() is 265 bytes, and the pack_msg() encoding is 129 bytes.

      send(p.pack_msg(p.one()))
      key = p.two(p.unpack_msg(receive()))

    """

    def __init__(self, password, side, params=params_80, entropy=None):
        if entropy is None:
            entropy = os.urandom
        self.entropy = entropy
        if side not in ["P","Q"]:
            raise PAKEError("side= must be either P or Q")
        self.side = side
        self.params = params
        q = params.q
        if isinstance(password, int):
            assert password > 0
            assert password < q-1
            self.s = password
        else:
            assert isinstance(password, bytes)
            # we must convert the password (a variable-length string) into a
            # number from 1 to q-1 (inclusive).
            self.s = 1 + (string_to_number(sha256(password).digest()) % (q-1))

    def one(self):
        g = self.params.g; p = self.params.p; q = self.params.q
        # self.ab is known as alpha on side P, and beta on side Q
        self.ab = randrange(q, self.entropy) # [0,q)
        if self.side == "P":
            upw = pow(self.params.u, self.s, p)
            self.xy = XY = (pow(g, self.ab, p) * upw) % p
            return {"X": "%x"%XY}
        else:
            vpw = pow(self.params.v, self.s, p)
            self.xy = XY = (pow(g, self.ab, p) * vpw) % p
            return {"Y": "%x"%XY}
        # XY is known as X on side P, and Y on side Q
        # serialize it with a simple jsonable dict for now

    def two(self, msg):
        p = self.params.p
        if self.side == "P":
            X = self.xy
            Y = int(msg["Y"], 16)
            vpw_inv = pow(self.params.inv_v, self.s, p)  # 1/V*pw
            Z = pow((Y * vpw_inv) % p, self.ab, p)
        else:
            X = int(msg["X"], 16)
            Y = self.xy
            upw_inv = pow(self.params.inv_u, self.s, p)  # 1/U*pw
            Z = pow((X * upw_inv) % p, self.ab, p)


        # now compute H(s, (idP,idQ), X, Y, Z)
        t = "%x:%x:%x:%x" % (self.s, X, Y, Z)
        # we don't use the idP/idQ salts
        key = sha256(t).digest()
        return key

    def pack_msg(self, data):
        orderlen = self.params.orderlen
        def n2s(hexint):
            return number_to_string(int(hexint,16), orderlen)
        if "X" in data:
            side = "\x00"
            XY = data["X"]
        else:
            assert "Y" in data
            side = "\x01"
            XY = data["Y"]
        packed = side + n2s(XY)
        return packed

    def unpack_msg(self, packed):
        if packed[0] == "\x00":
            return {"X": binascii.hexlify(packed[1:])}
        else:
            return {"Y": binascii.hexlify(packed[1:])}

    def getattr_hex(self, name):
        if hasattr(self, name):
            return "%x" % getattr(self, name)
        return None

    def to_json(self):
        return {"side": self.side,
                "params.p": "%x" % self.params.p,
                "params.g": "%x" % self.params.g,
                "params.q": "%x" % self.params.q,

                "params.u_str": self.params.u_str,
                "params.v_str": self.params.v_str,

                "s": self.s,
                "ab": self.getattr_hex("ab"),
                "xy": self.getattr_hex("xy"),
                }

    @classmethod
    def from_json(klass, data, entropy=None):
        p = Params(p=int(data["params.p"], 16),
                   q=int(data["params.q"], 16),
                   g=int(data["params.g"], 16),
                   u=data["params.u_str"],
                   v=data["params.v_str"])
        self = klass(data["s"], data["side"], params=p, entropy=entropy)
        for name in ["ab", "xy"]:
            if data[name]:
                setattr(self, name, int(data[name], 16))
        return self

class SPAKE2_P(SPAKE2):
    def __init__(self, password, params=params_80, entropy=None):
        SPAKE2.__init__(self, password, "P", params, entropy)

class SPAKE2_Q(SPAKE2):
    def __init__(self, password, params=params_80, entropy=None):
        SPAKE2.__init__(self, password, "Q", params, entropy)


# add ECC version for smaller messages/storage
# consider timing attacks
# try for compatibility with Boneh's JS version
