
# Pure-Python SPAKE2

* License: MIT
* Dependencies: none (pure-python)
* Compatible With: Python 2.6, 2.7, 3.3, 3.4, 3.5, pypy2
* [![Build Status](https://travis-ci.org/warner/python-spake2.png?branch=master)](https://travis-ci.org/warner/python-spake2) [![Coverage Status](https://coveralls.io/repos/warner/python-spake2/badge.svg)](https://coveralls.io/r/warner/python-spake2)

This library implements the SPAKE2 password-authenticated key exchange
("PAKE") algorithm. This allows two parties, who share a weak password, to
safely derive a strong shared secret (and therefore build an
encrypted+authenticated channel).

A passive attacker who eavesdrops on the connection learns no information
about the password or the generated secret. An active attacker
(man-in-the-middle) gets exactly one guess at the password, and unless they
get it right, they learn no information about the password or the generated
secret. Each execution of the protocol enables one guess. The use of a weak
password is made safer by the rate-limiting of guesses: no off-line
dictionary attack is available to the network-level attacker, and the
protocol does not depend upon having previously-established confidentiality
of the network (unlike e.g. sending a plaintext password over TLS).

The protocol requires the exchange of one pair of messages, so only one round
trip is necessary to establish the session key. If key-confirmation is
necessary, that will require a second round trip.

All messages are bytestrings. For the default security level (using the
Ed25519 elliptic curve, roughly equivalent to an 128-bit symmetric key), the
message is 33 bytes long.

## What Is It Good For?

PAKE can be used in a pairing protocol, like the initial version of Firefox
Sync (the one with J-PAKE), to introduce one device to another and help them
share secrets. In this mode, one device creates a random code, the user
copies that code to the second device, then both devices use the code as a
one-time password and run the PAKE protocol. Once both devices have a shared
strong key, they can exchange other secrets safely.

PAKE can also be used (carefully) in a login protocol, where SRP is perhaps
the best-known approach. Traditional non-PAKE login consists of sending a
plaintext password through a TLS-encrypted channel, to a server which then
checks it (by hashing/stretching and comparing against a stored verifier). In
a PAKE login, both sides put the password into their PAKE protocol, and then
confirm that their generated key is the same. This nominally does not require
the initial TLS-protected channel. However note that it requires other,
deeper design considerations (the PAKE protocol must be bound to whatever
protected channel you end up using, else the attacker can wait for PAKE to
complete normally and then steal the channel), and is not simply a drop-in
replacement. In addition, the server cannot hash/stretch the password very
much (see the note on "Augmented PAKE" below), so unless the client is
willing to perform key-stretching before running PAKE, the server's stored
verifier will be vulnerable to a low-cost dictionary attack.

## Usage

Alice and Bob both initialize their SPAKE2 instances with the same (weak)
password. They will exchange messages to (hopefully) derive a shared secret
key. The protocol is symmetric: for each operation that Alice does, Bob will
do the same.

However, there are two roles in the SPAKE2 protocol, "A" and "B". The two
sides must agree ahead of time which one will play which role (the messages
they generate depend upon which side they play). There are two separate
classes, `SPAKE2_A` and `SPAKE2_B`, and a complete interaction will use one
of each (one `SPAKE2_A` on one computer, and one `SPAKE2_B` on the other
computer).

Each instance of a SPAKE2 protocol uses a set of shared parameters. These
include a group, a generator, and a pair of arbitrary group elements. This
library comes with several pre-generated parameter sets, with various
security levels.

You start by creating an instance (either `SPAKE2_A` or `SPAKE2_B`) with the
password. Then you ask the instance for the outbound message by calling
`msg_out=s.start()`, and send it to your partner. Once you receive the
corresponding inbound message, you pass it into the instance and extract the
(shared) key bytestring with `key=s.finish(msg_in)`. For example, the
client-side might do:

```python
from spake2 import SPAKE2_A
s = SPAKE2_A(b"our password")
msg_out = s.start()
send(msg_out) # this is message A->B
msg_in = receive()
key = s.finish(msg_in)
```

while the server-side might do:

```python
from spake2 import SPAKE2_B
q = SPAKE2_B(b"our password")
msg_out = q.start()
send(msg_out)
msg_in = receive() # this is message A->B
key = q.finish(msg_in)
```

If both sides used the same password, and there is no man-in-the-middle, then
both sides will obtain the same `key`. If not, the two sides will get
different keys, so using "key" for data encryption will result in garbled
data.

The shared "key" can be used as an HMAC key to provide data integrity on
subsequent messages, or as an authenticated-encryption key (e.g.
nacl.secretbox). It can also be fed into [HKDF] [1] to derive other session
keys as necessary.

The `SPAKE2` instances, and the messages they create, are single-use. Create
a new one for each new session.

### Key Confirmation

To safely test for identical keys before use, you can perform a second
message exchange at the end of the protocol, before actually using the key
(be careful to not simply send the shared key over the wire: this would allow
a MitM to learn the key that they could otherwise not guess).

Alice does this:

```python
...
key = s.finish(msg_in)
confirm_A = HKDF(key, info="confirm_A", length=32)
expected_confirm_B = HKDF(key, info="confirm_B", length=32)
send(confirm_A)
confirm_B = receive()
assert confirm_B == expected_confirm_B
```

And Bob does this:
```python
...
key = q.finish(msg_in)
expected_confirm_A = HKDF(key, info="confirm_A", length=32)
confirm_B = HKDF(key, info="confirm_B", length=32)
send(confirm_B)
confirm_A = receive()
assert confirm_A == expected_confirm_A
```

## Symmetric Usage

A single SPAKE2 instance must be used asymmetrically: the two sides must
somehow decide (ahead of time) which role they will each play. The
implementation includes the side identifier in the exchanged message to guard
against an `SPAKE2_A` talking to another `SPAKE2_A`. Typically a "client"
will take on the `A` role, and the "server" will be `B`.

This is a nuisance for more egalitarian protocols, where there's no clear way
to assign these roles ahead of time. In this case, use `SPAKE2_Symmetric` on
both sides. This uses a different set of parameters (so it is not
interoperable with `SPAKE2_A` or `SPAKE2_B`, but should otherwise behave the
same way.

Carol does:

```python
s1 = SPAKE2_Symmetric(pw)
outmsg1 = s1.start()
send(outmsg1)
```

Dave does the same:
```python
s2 = SPAKE2_Symmetric(pw)
outmsg2 = s2.start()
send(outmsg2)
```

Carol then processes Dave's incoming message:
```python
inmsg2 = receive() # this is outmsg1
key = s1.finish(inmsg2)
```

And Dave does the same:
```python
inmsg1 = receive() # this is outmsg2
key = s2.finish(inmsg1)
```

## Identifier Strings

The SPAKE2 protocol includes a pair of "identity strings" `idA` and `idB`
that are included in the final key-derivation hash. This binds the key to a
single pair of parties, or for some specific purpose.

For example, when user "alice" logs into "example.com", both sides should set
`idA = b"alice"` and `idB = b"example.com"`. This prevents an attacker from
substituting messages from unrelated login sessions (other users on the same
server, or other servers for the same user).

This also makes sure the session is established with the correct service. If
Alice has one password for "example.com" but uses it for both login and
file-transfer services, `idB` should be different for the two services.
Otherwise if Alice is simultaneously connecting to both services, and
attacker could rearrange the messages and cause her login client to connect
to the file-transfer server, and vice versa.

If provided, `idA` and `idB` must be bytestrings. They default to an empty
string.

`SPAKE2_Symmetric` uses a single `idSymmetric=` string, instead of `idA` and
`idB`. Both sides must provide the same `idSymmetric=`, or leave it empty.

## Serialization

Sometimes, you can't hold the SPAKE2 instance in memory for the whole
negotiation: perhaps all your program state is stored in a database, and
nothing lives in RAM for more than a few moments. You can persist the data
from a SPAKE2 instance with `data = p.serialize()`, after the call to
`start`. Then later, when the inbound message is received, you can
reconstruct the instance with `p = SPAKE2_A.from_serialized(data)` before
calling `p.finish(msg)`.

```python
def first():
    p = SPAKE2_A(password)
    send(p.start())
    open('saved','w').write(p.serialize())
 
def second(inbound_message):
    p = SPAKE2_A.from_serialized(open('saved').read())
    key = p.finish(inbound_message)
    return key
```

The instance data is highly sensitive and includes the password: protect it
carefully. An eavesdropper who learns the instance state from just one side
will be able to reconstruct the shared key. `data` is a printable ASCII
bytestring (the JSON-encoding of a small dictionary). For `ParamsEd25519`,
the serialized data requires 221 bytes.

Note that you must restore the instance with the same side (`SPAKE2_A` vs
`SPAKE2_B`) and `params=` (if overridden) as you used when first creating it.
Otherwise `from_serialized()` will throw an exception. If you use non-default
parameters, you might want to store an indicator along with the serialized
state.

Also remember that you must never re-use a SPAKE2 instance for multiple key
agreements: that would reveal the key and/or password. Never use
`.from_serialized()` more than once on the same saved state, and delete the
state as soon as the incoming message is processed. SPAKE2 has internal
checks to throw exceptions when instances are used multiple times, but the
serialize/restore process can bypass those checks, so use with care.

Database-backed applications should store the outbound message (`p.start()`)
in the DB next to the serialized SPAKE2 state, so they can re-send the same
message if the application crashes before it has been successfully delivered.
`p.start()` cannot be called on the instance that `.from_serialized()`
produces.

## Security

SPAKE2's strength against cryptographic attacks depends upon the parameters
you use, which also influence the execution speed. Use the strongest
parameters your time budget can afford.

The library defaults to the fast and secure Ed25519 elliptic-curve group
through the `ParamsEd25519` parameter set. This offers a 128-bit security
level, small messages, and fairly fast execution speed.

If for some reason you don't care for elliptic curves, the `spake2.params`
module includes three integer-group parameter sets: `Params1024`,
`Params2048`, `Params3072`, offering 80-bit, 112-bit, and 128-bit security
levels respectively.

To override the default parameters, include a `params=` value when you create
the SPAKE2 instance. Both sides must use the same parameters.

```python
from spake2 import SPAKE2_A, params
s = SPAKE2_A(b"password", params=params.Params3072)
```

Note that if you serialize an instance with non-default `params=`, you must
restore it with the same parameters, otherwise you will get an exception:

```python
s = SPAKE2_A.from_serialized(data, params=params.Params3072)
```

This library is very much *not* constant-time, and does not protect against
timing attacks. Do not allow attackers to measure how long it takes you to
create or respond to a message.

This library depends upon a strong source of random numbers. Do not use it on
a system where os.urandom() is weak.

## Speed

To run the built-in speed tests, just run `python setup.py speed`.

SPAKE2 consists of two phases, separated by a single message exchange. The
time these phases take is split roughly 40/60. On my 2012 Mac Mini (2.6GHz
Core-i7), the default `ParamsEd25519` security level takes about 14ms to
complete both phases. For the integer groups, larger groups are slower and
require larger messages (and their serialized state is larger), but are more
secure. The complete output of `python setup.py speed` is:

    ParamsEd25519: msglen= 33, statelen=221, full=13.9ms, start= 5.5ms
    Params1024   : msglen=129, statelen=197, full= 4.3ms, start= 1.8ms
    Params2048   : msglen=257, statelen=213, full=20.8ms, start= 8.5ms
    Params3072   : msglen=385, statelen=221, full=41.5ms, start=16.5ms

A slower CPU (1.8GHz Intel Atom) takes about 8x as long (76/32/157/322ms).

This library uses only Python. A version which used C speedups for the large
modular multiplication operations would probably be an order of magnitude
faster.

## Testing

To run the built-in test suite from a source directory, for all supported
python versions, do:

    tox

On my computer, the tests take approximately two seconds (per version).

## History

The protocol was described as "PAKE2" in ["cryptobook"] [2] from Dan Boneh
and Victor Shoup. This is a form of "SPAKE2", defined by Abdalla and
Pointcheval at [RSA 2005] [3]. Additional recommendations for groups and
distinguished elements were published in [Ladd's IETF draft] [4].

The Ed25519 implementation uses code adapted from Daniel Bernstein (djb),
Matthew Dempsky, Daniel Holth, Ron Garret, with further optimizations by
Brian Warner[5]. The "arbitrary element" computation, which must be the same
for both participants, is from python-pure25519 version 0.5.

The Boneh/Shoup chapter that defines PAKE2 also defines an augmented variant
named "PAKE2+", which changes one side (typically a server) to record a
derivative of the password instead of the actual password. In PAKE2+, a
server compromise does not immediately give access to the passwords: instead,
the attacker must perform an offline dictionary attack against the stolen
data before they can learn the passwords. PAKE2+ support is planned, but not
yet implemented.

The security of the symmetric case was proved by Kobara/Imai[6] in 2003, and
uses different (slightly weaker?) reductions than that of the asymmetric
form. See also Mike Hamburg's analysis[7] from 2015.

Brian Warner first wrote this Python version in July 2010.

#### footnotes

[1]: https://tools.ietf.org/html/rfc5869 "HKDF"
[2]: http://crypto.stanford.edu/~dabo/cryptobook/  "cryptobook"
[3]: http://www.di.ens.fr/~pointche/Documents/Papers/2005_rsa.pdf "RSA 2005"
[4]: https://tools.ietf.org/html/draft-ladd-spake2-01 "Ladd's IETF draft"
[5]: https://github.com/warner/python-pure25519
[6]: http://eprint.iacr.org/2003/038.pdf "Pretty-Simple Password-Authenticated Key-Exchange Under Standard Assumptions"
[7]: https://moderncrypto.org/mail-archive/curves/2015/000419.html "PAKE questions"
