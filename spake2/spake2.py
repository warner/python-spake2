
import json
from binascii import hexlify, unhexlify
from hashlib import sha256
from .params import Params, Params1024

# TODO: switch to ECC

class PAKEError(Exception):
    pass
class BadSide(PAKEError):
    pass
class OnlyCallStartOnce(PAKEError):
    """start() may only be called once. Re-using a SPAKE2 instance is likely
    to reveal the password or the derived key."""
class OnlyCallFinishOnce(PAKEError):
    """finish() may only be called once. Re-using a SPAKE2 instance is likely
    to reveal the password or the derived key."""
class OffSides(PAKEError):
    """I received a message from someone on the same side that I'm on: I was
    expecting the opposite side."""
class SerializedTooEarly(PAKEError):
    pass
class WrongGroupError(PAKEError):
    pass

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
    """This class manages one side of a SPAKE2 key negotiation.

    Two instances of this class, each with the same password, in separate
    processes on either side of a network connection, can cooperatively agree
    upon a strong random session key.

    Both sides must be using the same 'parameters' and the same passwords.
    The sides must play different roles: one side is A, the other side is B.

    Create an instance with SPAKE2(password=pw, side=SideA) (or side=SideB),
    where 'password' is a bytestring. You can also pass an optional params=
    value (one of [params.Params1024, Params2048, Params3072], for increasing
    levels of security and CPU usage). Any two PAKE communicating instances
    must use identical params=, and different side= values.

    Once constructed, you will need to call start() and finish() in order,
    passing the output of start() over the wire, where it forms the input to
    the other instance's finish():

        from spake2 import SPAKE2, SideA
        p = SPAKE2('password', SideA)
        outbound_message = p.start()
        send(outbound_message) # send to other side, somehow
        inbound_message = receive() # get this from other side, somehow
        key = p.finish(inbound_message)

    (The other side, which receives 'outbound_message' and creates
    'inbound_message', will use `SPAKE2('password', SideB)`).

    The secret 'key' that comes out will be a bytestring of length 256 (the
    output of a SHA256 hash function). If both sides used the same password,
    both sides will wind up with the same key, otherwise they will have
    different keys. You will probably want to confirm this equivalence before
    relying upon it (but don't reveal the key to the other side in doing so,
    in case you aren't talking to the right party and your keys are really
    different). Note that this introduces an additional asymmetry to the
    protocol (one side learns of the mismatch before the other). For example:

        A: hhkey = sha256(sha256(Akey).digest()).digest()
        A: send(hhkey)
          B: hhkey = receive()
          B: assert sha256(sha256(Bkey).digest()).digest() == hhkey
          B: hkey = sha256(Bkey).digest()
          B: send(hkey)
        A: hkey = receive()
        A: assert sha256(Akey).digest() == hkey

    Sometimes, you can't hold the SPAKE2 instance in memory for the whole
    negotiation: perhaps all your program state is stored in a database, and
    nothing lives in RAM for more than a few moments. You can persist the
    data from an instance with `data = p.serialize()`, after the call to
    `start`. Then later, when the inbound message is received, you can
    reconstruct the instance with `p = SPAKE2.from_serialized(data)` and can
    `finish`. The instance data is sensitive: protect it better than you
    would the original password. An attacker who learns the instance state
    from both sides, or an eavesdropper who learns the instance state from
    just one side, will be able to reconstruct the shared key. `data` is a
    printable ASCII string (the JSON-encoding of a small dictionary). For
    params_80, the serialized data is typically about 1528 bytes.

     def first():
       p = SPAKE2(password, SideA)
       send(p.start())
       open('saved','w').write(p.serialize())

     def second(inbound_message):
       p = SPAKE2.from_serialized(open('saved').read())
       key = p.finish(inbound_message)
       return key

    The message returned by start() is a bytestring (about 129 bytes long for
    params_80). You may need to base64-encode it before sending it over a
    non-8-bit-clean connection.

    """

    def __init__(self, password, side, idA=b"", idB=b"",
                 params=Params1024, entropy_f=None):
        assert isinstance(password, bytes)
        self.pw = password
        self.pw_scalar = params.group.password_to_scalar(password)

        # These names come from the Abdalla/Pointcheval paper.
        #  variable .. known as .. on A's side, and .. on B's side:
        #           MN          M                   N
        #           NM          N                   M
        #           xy          x                   y
        if side == SideA:
            (self.MN, self.NM) = (params.M, params.N)
        elif side == SideB:
            (self.MN, self.NM) = (params.N, params.M)
        else:
            raise BadSide("side= must be either SideA or SideB")
        self.side = side

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
        message_elem = self.xy_elem + (self.MN * self.pw_scalar)
        self.outbound_message = message_elem.to_bytes()

    def finish(self, inbound_side_and_message):
        if self._finished:
            raise OnlyCallFinishOnce("finish() can only be called once")
        self._finished = True

        other_side = inbound_side_and_message[0:1]
        inbound_message = inbound_side_and_message[1:]
        if self.side == SideA:
            if other_side != SideB:
                raise OffSides("I'm A, but I got a message from A (not B).")
            X_msg = self.outbound_message
            Y_msg = inbound_message
        else:
            if other_side != SideA:
                raise OffSides("I'm B, but I got a message from B (not A).")
            X_msg = inbound_message
            Y_msg = self.outbound_message

        group = self.params.group
        inbound_elem = group.element_from_bytes(inbound_message)
        K_elem = (inbound_elem + (self.NM * -self.pw_scalar)) * self.xy_exp
        K_bytes = K_elem.to_bytes()
        transcript = b":".join([self.idA, self.idB,
                                X_msg, Y_msg, K_bytes,
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

    def serialize(self):
        if not self._started:
            raise SerializedTooEarly("call .start() before .serialize()")
        group = self.params.group
        d = {"hashed_params": self.hash_params(),
             "side": self.side.decode("ascii"),
             "idA": hexlify(self.idA).decode("ascii"),
             "idB": hexlify(self.idB).decode("ascii"),
             "password": hexlify(self.pw).decode("ascii"),
             "xy_exp": hexlify(group.scalar_to_bytes(self.xy_exp)).decode("ascii"),
             }
        return json.dumps(d).encode("ascii")

    @classmethod
    def from_serialized(klass, data, params=Params1024):
        d = json.loads(data.decode("ascii"))
        side = d["side"].encode("ascii")
        assert side in (SideA, SideB)
        def _should_be_unused(count): raise NotImplementedError
        self = klass(unhexlify(d["password"]), side,
                     idA=unhexlify(d["idA"]), idB=unhexlify(d["idB"]),
                     params=params, entropy_f=_should_be_unused)
        if d["hashed_params"] != self.hash_params():
            err = ("SPAKE2.from_serialized() must be called with the same"
                   "params= that were used to create the serialized data."
                   "These are different somehow.")
            raise WrongGroupError(err)
        group = self.params.group
        self._started = True
        self.xy_exp = group.scalar_from_bytes(unhexlify(d["xy_exp"]),
                                              allow_wrap=False)
        self.xy_elem = group.scalarmult_base(self.xy_exp)
        self.compute_outbound_message()
        return self

class SPAKE2_A(SPAKE2):
    def __init__(self, password, params=Params1024, entropy_f=None):
        SPAKE2.__init__(self, password, SideA, params=params,
                        entropy_f=entropy_f)

class SPAKE2_B(SPAKE2):
    def __init__(self, password, params=Params1024, entropy_f=None):
        SPAKE2.__init__(self, password, SideB, params=params,
                        entropy_f=entropy_f)


# add ECC version for smaller messages/storage
# consider timing attacks
# try for compatibility with Boneh's JS version
