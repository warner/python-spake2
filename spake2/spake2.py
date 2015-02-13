
import json
from binascii import hexlify, unhexlify
from hashlib import sha256
from .params import Params, Params2048
from .util import xor_keys

# TODO: switch to ECC

DefaultParams = Params2048

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

# x = random(Zp)
# X = scalarmult(g, x)
# X* = X + scalarmult(M, int(pw))
#  y = random(Zp)
#  Y = scalarmult(g, y)
#  Y* = Y + scalarmult(N, int(pw))
# KA = scalarmult(Y* + scalarmult(N, -int(pw)), x)
# key = H(idA, idB, X*, Y*, KA)
#  KB = scalarmult(X* + scalarmult(M, -int(pw)), y)
#  key = H(idA, idB, X*, Y*, KB)

# to serialize intermediate state, just remember x and A-vs-B. And U/V.

class SPAKE2:
    "This class manages one side of a SPAKE2 key negotiation."

    side = None # set by the subclass

    def __init__(self, password, idA=b"", idB=b"",
                 params=DefaultParams, entropy_f=None):
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

        group = self.params.group
        self.xy_exp = group.random_scalar(self.entropy_f)
        self.xy_elem = group.scalarmult_base(self.xy_exp)
        self.compute_outbound_message()
        # Guard against both sides using the same side= by adding a side byte
        # to the message. This is not included in the transcript hash at the
        # end.
        outbound_side_and_message = self.side + self.outbound_message
        return outbound_side_and_message

    def compute_outbound_message(self):
        message_elem = self.xy_elem + (self.my_blinding() * self.pw_scalar)
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

        group = self.params.group
        inbound_elem = group.element_from_bytes(self.inbound_message)
        if inbound_elem.to_bytes() == self.outbound_message:
            raise ReflectionThwarted
        K_elem = (inbound_elem + (self.my_unblinding() * -self.pw_scalar)
                  ) * self.xy_exp
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
        group = self.params.group
        pieces = [group.arbitrary_element(b"").to_bytes(),
                  group.scalar_to_bytes(group.password_to_scalar(b"")),
                  self.params.M.to_bytes(),
                  self.params.N.to_bytes(),
                  ]
        return sha256(b"".join(pieces)).hexdigest()

    def _serialize_to_dict(self):
        group = self.params.group
        d = {"hashed_params": self.hash_params(),
             "side": self.side.decode("ascii"),
             "idA": hexlify(self.idA).decode("ascii"),
             "idB": hexlify(self.idB).decode("ascii"),
             "password": hexlify(self.pw).decode("ascii"),
             "xy_exp": hexlify(group.scalar_to_bytes(self.xy_exp)).decode("ascii"),
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
        group = self.params.group
        self._started = True
        xy_exp_bytes = unhexlify(d["xy_exp"].encode("ascii"))
        self.xy_exp = group.scalar_from_bytes(xy_exp_bytes, allow_wrap=False)
        self.xy_elem = group.scalarmult_base(self.xy_exp)
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

class SPAKE2_Symmetric:
    def __init__(self, password, idA=b"", idB=b"",
                 params=DefaultParams, entropy_f=None):
        self.pw = password
        self.sA = SPAKE2_A(password, idA, idB, params, entropy_f)
        self.sB = SPAKE2_B(password, idA, idB, params, entropy_f)

    def start(self):
        mA = self.sA.start()
        mB = self.sB.start()
        return mA+mB

    def finish(self, inbound_side_and_message):
        l = len(inbound_side_and_message)
        assert l % 2 == 0
        inbound_A = inbound_side_and_message[:l//2]
        inbound_B = inbound_side_and_message[l//2:]
        assert len(inbound_A) == len(inbound_B)
        keyA = self.sA.finish(inbound_B)
        keyB = self.sB.finish(inbound_A)
        if keyA == keyB:
            raise ReflectionThwarted
        key = xor_keys(keyA, keyB)
        return key

    def serialize(self):
        d = {"password": hexlify(self.pw).decode("ascii"),
             "sA": self.sA._serialize_to_dict(),
             "sB": self.sB._serialize_to_dict(),
             }
        return json.dumps(d).encode("ascii")

    @classmethod
    def from_serialized(klass, data, params=DefaultParams):
        d = json.loads(data.decode("ascii"))
        pw = unhexlify(d["password"].encode("ascii"))
        self = klass(password=pw)
        self.sA = SPAKE2_A._deserialize_from_dict(d["sA"], params)
        self.sB = SPAKE2_B._deserialize_from_dict(d["sB"], params)
        return self

# add ECC version for smaller messages/storage
# consider timing attacks
# try for compatibility with Boneh's JS version
