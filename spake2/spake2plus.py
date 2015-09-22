
import os, json
from binascii import hexlify, unhexlify
from hashlib import sha256
from .params import Params, ParamsEd25519
from .util import xor_keys

DefaultParams = ParamsEd25519

class SPAKEError(Exception):
    pass
class OnlyCallStartOnce(SPAKEError):
    """start() may only be called once. Re-using a SPAKE2 instance is likely
    to reveal the password or the derived key."""
class OnlyCallFinishOnce(SPAKEError):
    """finish() may only be called once. Re-using a SPAKE2 instance is likely
    to reveal the password or the derived key."""
class OffSides(SPAKEError):
    """I received a message from someone on the same side that I'm on: I was
    expecting the opposite side."""
class SerializedTooEarly(SPAKEError):
    pass
class WrongSideSerialized(SPAKEError):
    """You tried to unserialize data stored for the other side."""
class WrongGroupError(SPAKEError):
    pass
class ReflectionThwarted(SPAKEError):
    """Someone tried to reflect our message back to us."""

SideA = b"A"
SideB = b"B"

# pi0,pi1 = H(pw, idA, idB)  (as scalars)
# L = scalarmult(g, pi1)

# x = random(Zp)
# X = scalarmult(g, x)
# X* = X + scalarmult(U, int(pi0))
#  y = random(Zp)
#  Y = scalarmult(g, y)
#  Y* = Y + scalarmult(V, int(pi0))
# KA = scalarmult(Y* + scalarmult(V, -int(pi0)), x)
# NA = scalarmult(Y* + scalarmult(V, -int(pi0)), pi1)
# key = H(idA, idB, X*, Y*, KA)
#  KB = scalarmult(X* + scalarmult(U, -int(pi0)), y)
#  NB = scalarmult(L, y)
#  key = H(idA, idB, X*, Y*, KB)

# to serialize intermediate state, just remember x and A-vs-B. And U/V.

def _hash_password_to_pi(password, idA=b"", idB=b"", group):
    s = b":".join([password, idA, idB])
    h = hashlib.sha512(s).digest()
    pi0 = group.password_to_scalar(h[0:256])
    pi1 = group.password_to_scalar(h[256:512])
    return (pi0, pi1)

def SPAKE2Plus_compute_verifier(password, idA=b"", idB=b"",
                                params=DefaultParams):
    g = params.group
    pi0, pi1 = _hash_password_to_pi(password, idA, idB, g)
    v0 = g.scalar_to_bytes(pi0)
    vL = g.Base.scalarmult(pi1).to_bytes()
    assert len(v0) == g.scalar_size_bytes
    assert len(vL) == g.element_size_bytes
    verifier = v0+vL
    return verifier

def _parse_verifier(v, g):
    assert len(v) == g.scalar_size_bytes + g.element_size_bytes
    v0 = v[:g.scalar_size_bytes]
    vL = v[g.scalar_size_bytes:]
    pi0 = g.bytes_to_scalar(v0)
    L = g.bytes_to_element(vL)
    return pi0, L
    

class _SPAKE2PlusCommon:
    "This class manages one side of a SPAKE2 key negotiation."

    side = None # set by the subclass

    def __init__(self, password, idA=b"", idB=b"",
                 params=DefaultParams, entropy_f=os.urandom):
        assert isinstance(password, bytes)
        self.pw = password
        self.pw_scalar = params.group.password_to_scalar(password)

        assert isinstance(idA, bytes), repr(idA)
        assert isinstance(idB, bytes), repr(idB)
        self.idA = idA
        self.idB = idB

        assert isinstance(params, Params), repr(params)
        self.params = params
        self.entropy_f = entropy_f

        self._started = False
        self._finished = False

    def start(self):
        if self._started:
            raise OnlyCallStartOnce("start() can only be called once")
        self._started = True

        g = self.params.group
        self.xy_scalar = g.random_scalar(self.entropy_f)
        self.xy_elem = g.Base.scalarmult(self.xy_scalar)
        self.compute_outbound_message()
        # Guard against both sides using the same side= by adding a side byte
        # to the message. This is not included in the transcript hash at the
        # end.
        outbound_side_and_message = self.side + self.outbound_message
        return outbound_side_and_message

    def compute_outbound_message(self):
        #message_elem = self.xy_elem + (self.my_blinding() * self.pw_scalar)
        pw_blinding = self.my_blinding().scalarmult(self.pw_scalar)
        message_elem = self.xy_elem.add(pw_blinding)
        self.outbound_message = message_elem.to_bytes()

    def finish(self, inbound_side_and_message):
        if self._finished:
            raise OnlyCallFinishOnce("finish() can only be called once")
        self._finished = True

        other_side = inbound_side_and_message[0:1]
        self.inbound_message = inbound_side_and_message[1:]

        if other_side not in (SideA, SideB):
            raise OffSides("I don't know what side they're on")
        if self.side == other_side:
            if self.side == SideA:
                raise OffSides("I'm A, but I got a message from A (not B).")
            else:
                raise OffSides("I'm B, but I got a message from B (not A).")

        g = self.params.group
        inbound_elem = g.bytes_to_element(self.inbound_message)
        if inbound_elem.to_bytes() == self.outbound_message:
            raise ReflectionThwarted
        #K_elem = (inbound_elem + (self.my_unblinding() * -self.pw_scalar)
        #          ) * self.xy_scalar
        pw_unblinding = self.my_unblinding().scalarmult(-self.pw_scalar)
        K_elem = inbound_elem.add(pw_unblinding).scalarmult(self.xy_scalar)
        K_bytes = K_elem.to_bytes()
        transcript = b":".join([self.idA, self.idB,
                                self.X_msg(), self.Y_msg(), K_bytes,
                                self.pw])
        key = sha256(transcript).digest()
        return key


    def hash_params(self):
        # We can't really reconstruct the group from static data, but we'll
        # record enough of the params to confirm that we're using the same
        # ones upon restore. Otherwise the failure mode is silent key
        # disagreement. Any changes to the group or the M/N seeds should
        # cause this to change.
        g = self.params.group
        pieces = [g.arbitrary_element(b"").to_bytes(),
                  g.scalar_to_bytes(g.password_to_scalar(b"")),
                  self.params.M.to_bytes(),
                  self.params.N.to_bytes(),
                  ]
        return sha256(b"".join(pieces)).hexdigest()

    def _serialize_to_dict(self):
        g = self.params.group
        d = {"hashed_params": self.hash_params(),
             "side": self.side.decode("ascii"),
             "idA": hexlify(self.idA).decode("ascii"),
             "idB": hexlify(self.idB).decode("ascii"),
             "password": hexlify(self.pw).decode("ascii"),
             "xy_scalar": hexlify(g.scalar_to_bytes(self.xy_scalar)).decode("ascii"),
             }
        return d

    def serialize(self):
        if not self._started:
            raise SerializedTooEarly("call .start() before .serialize()")
        return json.dumps(self._serialize_to_dict()).encode("ascii")

    @classmethod
    def _deserialize_from_dict(klass, d, params):
        def _should_be_unused(count): raise NotImplementedError
        self = klass(password=unhexlify(d["password"].encode("ascii")),
                     idA=unhexlify(d["idA"].encode("ascii")),
                     idB=unhexlify(d["idB"].encode("ascii")),
                     params=params, entropy_f=_should_be_unused)
        if d["side"].encode("ascii") != self.side:
            raise WrongSideSerialized
        if d["hashed_params"] != self.hash_params():
            err = ("SPAKE2.from_serialized() must be called with the same"
                   "params= that were used to create the serialized data."
                   "These are different somehow.")
            raise WrongGroupError(err)
        g = self.params.group
        self._started = True
        xy_scalar_bytes = unhexlify(d["xy_scalar"].encode("ascii"))
        self.xy_scalar = g.bytes_to_scalar(xy_scalar_bytes)
        self.xy_elem = g.Base.scalarmult(self.xy_scalar)
        self.compute_outbound_message()
        return self
    @classmethod
    def from_serialized(klass, data, params=DefaultParams):
        d = json.loads(data.decode("ascii"))
        return klass._deserialize_from_dict(d, params)

# applications should use SPAKE2_A and SPAKE2_B, not raw SPAKE2()

class SPAKE2_A(SPAKE2):
    side = SideA
    def my_blinding(self): return self.params.M
    def my_unblinding(self): return self.params.N
    def X_msg(self): return self.outbound_message
    def Y_msg(self): return self.inbound_message

class SPAKE2_B(SPAKE2):
    side = SideB
    def my_blinding(self): return self.params.N
    def my_unblinding(self): return self.params.M
    def X_msg(self): return self.inbound_message
    def Y_msg(self): return self.outbound_message

# consider timing attacks
# try for compatibility with Boneh's JS version
