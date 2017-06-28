import os, json
from binascii import hexlify, unhexlify
from hashlib import sha256
from .params import _Params
from .parameters.ed25519 import ParamsEd25519

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
SideSymmetric = b"S"

# x = random(Zp)
# X = scalarmult(g, x)
# X* = X + scalarmult(M, int(pw))
#  y = random(Zp)
#  Y = scalarmult(g, y)
#  Y* = Y + scalarmult(N, int(pw))
# KA = scalarmult(Y* + scalarmult(N, -int(pw)), x)
# key = H(H(pw) + H(idA) + H(idB) + X* + Y* + KA)
#  KB = scalarmult(X* + scalarmult(M, -int(pw)), y)
#  key = H(H(pw) + H(idA) + H(idB) + X* + Y* + KB)

# to serialize intermediate state, just remember x and A-vs-B. And M/N.

def finalize_SPAKE2(idA, idB, X_msg, Y_msg, K_bytes, pw):
    transcript = b"".join([sha256(pw).digest(),
                           sha256(idA).digest(), sha256(idB).digest(),
                           X_msg, Y_msg, K_bytes])
    key = sha256(transcript).digest()
    return key

def finalize_SPAKE2_symmetric(idSymmetric, msg1, msg2, K_bytes, pw):
    # since we don't know which side is which, we must sort the messages
    first_msg, second_msg = sorted([msg1, msg2])
    transcript = b"".join([sha256(pw).digest(),
                           sha256(idSymmetric).digest(),
                           first_msg, second_msg, K_bytes])
    key = sha256(transcript).digest()
    return key

class _SPAKE2_Base:
    "This class manages one side of a SPAKE2 key negotiation."

    side = None # set by the subclass

    def __init__(self, password,
                 params=DefaultParams, entropy_f=os.urandom):
        assert isinstance(password, bytes)
        self.pw = password
        self.pw_scalar = params.group.password_to_scalar(password)

        assert isinstance(params, _Params), repr(params)
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

        self.inbound_message = self._extract_message(inbound_side_and_message)

        g = self.params.group
        inbound_elem = g.bytes_to_element(self.inbound_message)
        if inbound_elem.to_bytes() == self.outbound_message:
            raise ReflectionThwarted
        #K_elem = (inbound_elem + (self.my_unblinding() * -self.pw_scalar)
        #          ) * self.xy_scalar
        pw_unblinding = self.my_unblinding().scalarmult(-self.pw_scalar)
        K_elem = inbound_elem.add(pw_unblinding).scalarmult(self.xy_scalar)
        K_bytes = K_elem.to_bytes()
        key = self._finalize(K_bytes)
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

    def serialize(self):
        if not self._started:
            raise SerializedTooEarly("call .start() before .serialize()")
        return json.dumps(self._serialize_to_dict()).encode("ascii")

    @classmethod
    def from_serialized(klass, data, params=DefaultParams):
        d = json.loads(data.decode("ascii"))
        return klass._deserialize_from_dict(d, params)

class _SPAKE2_Asymmetric(_SPAKE2_Base):
    def __init__(self, password, idA=b"", idB=b"",
                 params=DefaultParams, entropy_f=os.urandom):
        _SPAKE2_Base.__init__(self, password,
                              params=params, entropy_f=entropy_f)

        assert isinstance(idA, bytes), repr(idA)
        assert isinstance(idB, bytes), repr(idB)
        self.idA = idA
        self.idB = idB

    def _extract_message(self, inbound_side_and_message):
        other_side = inbound_side_and_message[0:1]
        inbound_message = inbound_side_and_message[1:]

        if other_side not in (SideA, SideB):
            raise OffSides("I don't know what side they're on")
        if self.side == other_side:
            if self.side == SideA:
                raise OffSides("I'm A, but I got a message from A (not B).")
            else:
                raise OffSides("I'm B, but I got a message from B (not A).")
        return inbound_message

    def _finalize(self, K_bytes):
        return finalize_SPAKE2(self.idA, self.idB,
                               self.X_msg(), self.Y_msg(),
                               K_bytes, self.pw)

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


# applications should use SPAKE2_A and SPAKE2_B, not raw _SPAKE2_Base()

class SPAKE2_A(_SPAKE2_Asymmetric):
    side = SideA
    def my_blinding(self): return self.params.M
    def my_unblinding(self): return self.params.N
    def X_msg(self): return self.outbound_message
    def Y_msg(self): return self.inbound_message

class SPAKE2_B(_SPAKE2_Asymmetric):
    side = SideB
    def my_blinding(self): return self.params.N
    def my_unblinding(self): return self.params.M
    def X_msg(self): return self.inbound_message
    def Y_msg(self): return self.outbound_message

class SPAKE2_Symmetric(_SPAKE2_Base):
    side = SideSymmetric
    def __init__(self, password, idSymmetric=b"",
                 params=DefaultParams, entropy_f=os.urandom):
        _SPAKE2_Base.__init__(self, password,
                              params=params, entropy_f=entropy_f)
        self.idSymmetric = idSymmetric

    def my_blinding(self): return self.params.S
    def my_unblinding(self): return self.params.S

    def _extract_message(self, inbound_side_and_message):
        other_side = inbound_side_and_message[0:1]
        inbound_message = inbound_side_and_message[1:]
        if other_side == SideA:
            raise OffSides("I'm Symmetric, but I got a message from A")
        if other_side == SideB:
            raise OffSides("I'm Symmetric, but I got a message from B")
        assert other_side == SideSymmetric
        return inbound_message

    def _finalize(self, K_bytes):
        return finalize_SPAKE2_symmetric(self.idSymmetric,
                                         self.inbound_message,
                                         self.outbound_message,
                                         K_bytes, self.pw)

    def hash_params(self):
        g = self.params.group
        pieces = [g.arbitrary_element(b"").to_bytes(),
                  g.scalar_to_bytes(g.password_to_scalar(b"")),
                  self.params.S.to_bytes(),
                  ]
        return sha256(b"".join(pieces)).hexdigest()

    def _serialize_to_dict(self):
        g = self.params.group
        d = {"hashed_params": self.hash_params(),
             "side": self.side.decode("ascii"),
             "idS": hexlify(self.idSymmetric).decode("ascii"),
             "password": hexlify(self.pw).decode("ascii"),
             "xy_scalar": hexlify(g.scalar_to_bytes(self.xy_scalar)).decode("ascii"),
             }
        return d

    @classmethod
    def _deserialize_from_dict(klass, d, params):
        if d["side"].encode("ascii") != SideSymmetric:
            raise WrongSideSerialized
        def _should_be_unused(count): raise NotImplementedError
        self = klass(password=unhexlify(d["password"].encode("ascii")),
                     idSymmetric=unhexlify(d["idS"].encode("ascii")),
                     params=params, entropy_f=_should_be_unused)
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

# add ECC version for smaller messages/storage
# consider timing attacks
# try for compatibility with Boneh's JS version
