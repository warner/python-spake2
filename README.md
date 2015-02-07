
# Pure-Python SPAKE2

* License: MIT
* Dependencies: none (pure-python)
* [![Build Status](https://travis-ci.org/warner/python-spake2.png?branch=master)](https://travis-ci.org/warner/python-spake2) [![Coverage Status](https://coveralls.io/repos/warner/python-spake2/badge.svg)](https://coveralls.io/r/warner/python-spake2)

This library implements the SPAKE2 password-authenticated key exchange
algorithm. This allows two parties, who share a weak password, to safely
derive a strong shared secret (and therefore build an encrypted+authenticated
channel).

A passive attacker who eavesdrops on the connection learns no information
about the password or the generated secret. An active attacker
(man-in-the-middle) gets exactly one guess at the password, and unless they
get it right, they learn no information about the password or the generated
secret. Each execution of the protocol enables one guess. The use of a weak
password is made safer by the rate-limiting of guesses: no off-line attack is
possible.

The protocol requires the exchange of one pair of messages, so only one round
trip is necessary to establish the session key. If key-confirmation is
necessary, that will require a second round trip.

All messages are bytestrings. For the default security level (using a
1024-bit modulus, roughly equivalent to an 80-bit symmetric key), the message
is 129 bytes long.

## Usage

Alice and Bob both initialize their SPAKE2 instances with the same (weak)
password. They will exchange messages to (hopefully) derive a shared secret
key. The protocol is symmetric: for each operation that Alice does, Bob will
do the same.

However, there are two roles in the SPAKE2 protocol, "A" and "B". The two
sides must agree ahead of time which one will play which role (the messages
they generate depend upon which side they play). There are two separate
classes, `SPAKE2_A` and `SPAKE2_B`, and a complete interaction will use one
of each.

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

The shared "key" can be used as an AES data-encryption key, or as an HMAC key
to provide data integrity. It can also be fed into [HKDF] [1] to derive other
session keys as necessary.

The `SPAKE2` instances, and the messages they create, are single-use. Create
a new one for each new session.

### Key Confirmation

To safely test for identical keys before use, you can perform a second
message exchange at the end of the protocol, before actually using the key
(be careful to not simply send the shared key over the wire wire: this would
allow a MitM to learn the key that they could otherwise not guess). This
key-confirmation step is asymmetric: one side will always learn about the
success or failure of the protocol before the other.

Alice does this:

```python
...
key = s.finish(msg_in)
hhkey = sha256(sha256(key).digest()).digest()
send(hhkey)
```

Then Bob does this:
```python
...
key = q.finish(msg_in)
their_hhkey = receive()
my_hhkey = sha256(sha256(key).digest()).digest()
assert my_hhkey == their_hhkey # Bob learns about success first
hkey = sha256(key).digest()
send(hkey)
```

And finally Alice does this:
```python
their_hkey = receive()
my_hkey = sha256(key).digest()
assert my_hkey == their_hkey
```

## Symmetric Usage

A single SPAKE2 instance must be used asymmetrically: the two sides must
somehow decide (ahead of time) which role they will each play. The
implementation includes the side identifier in the exchanged message to guard
against an `SPAKE2_A` talking to another `SPAKE2_A`. Typically a "client"
will take on the `A` role, and the "server" will be `B`.

This is a nuisance for more egalitarian protocols, where there's no clear way
to assign these roles ahead of time. One suggestion is to run two instances
of the protocol at the same time, crossed, and XOR the resulting keys
together:

Carol would do:

```python
sa,sb = SPAKE2_A(pw), SPAKE2_B(pw)
ma,mb = sa.start(), sb.start()
send((ma,mb))
```

Dave does the same:
```python
sa,sb = SPAKE2_A(pw), SPAKE2_B(pw)
ma,mb = sa.start(), sb.start()
send((ma,mb))
```

Carol then swaps Dave's incoming messages, and builds both keys:
```python
(inmsg_a, inmsg_b) = receive()
k1 = sa.finish(inmsg_b)
k2 = sb.finish(inmsg_a)
key = spake2.util.xor_keys(k1, k2)
```

and Dave does the same. Since the keys are combined before use, this should
not improve the attacker's chances of guessing the password.

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
bytestring (the JSON-encoding of a small dictionary). For `Params1024`, the
serialized data requires 194 bytes.

Note that you must restore the instance with the same side (`SPAKE2_A` vs
`SPAKE2_B`) and `params=` (if overridden) as you used when first creating it.
Otherwise `from_serialized()` will throw an exception.

Also remember that you must never re-use a SPAKE2 instance for multiple key
agreements: that would reveal the key and/or password. Never use
`.from_serialized()` more than once on the same saved state, and delete the
state as soon as the incoming message is processed. SPAKE2 has internal
checks to throw exceptions when instances are used multiple times, but the
serialize/restore process can bypass those checks, so use with care.

## Security

SPAKE2's strength against cryptographic attacks depends upon the parameters
you use, which also influence the execution speed. Use the strongest
parameters your time budget can afford.

The library comes with three parameter sets in the `spake2.params` module:
`Params1024` (the default), `Params2048`, and `Params3072`, offering 80-bit,
112-bit, and 128-bit security levels respectively.

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

This library does not currently protect against timing attacks. Do not allow
attackers to measure how long it takes you to create or respond to a message.

This library depends upon a strong source of random numbers. Do not use it on
a system where os.urandom() is weak.

## Speed

To run the built-in speed tests, just run `python setup.py speed`.

SPAKE2 consists of two phases, separated by a single message exchange. The
two phases take roughly equal time. On my 2012 Mac Mini (2.6GHz Core-i7), the
default `Params1024` security level takes about 3.4ms to complete both
phases. Larger parameter sets are slower and require larger messages (and
their serialized state is larger), but are more secure. The complete output
of `python setup.py speed` is:

    Params1024: msglen=129, statelen=194, full=3.4ms, start=1.7ms
    Params2048: msglen=257, statelen=210, full=16.3ms, start=8.2ms
    Params3072: msglen=385, statelen=218, full=32.4ms, start=16.1ms

A slower CPU (1.8GHz Intel Atom) takes about 8x as long (26ms/125ms/255ms).

This library uses only Python. A version which used C speedups for the large
modular multiplication operations would probably be an order of magnitude
faster. A future release will include a pure-python elliptic-curve group
(Ed25519) for higher security speed.

## Testing

To run the built-in test suite from a source directory, do:

    python setup.py test

The tests take approximately half a second on my computer.

## History

The protocol was described as "PAKE2" in ["cryptobook"] [2] from Dan Boneh
and Victor Shoup. This is a form of "SPAKE2", defined by Abdalla and
Pointcheval at [RSA 2005] [3]. Additional recommendations for groups and
distinguished elements were published in [Ladd's IETF draft] [4].

The Boneh/Shoup chapter that defines PAKE2 also defines an augmented variant
named "PAKE2+", which changes one side (typically a server) to record a
derivative of the password instead of the actual password. In PAKE2+, a
server compromise does not immediately give access to the passwords: instead,
the attacker must perform an offline dictionary attack against the stolen
data before they can learn the passwords. PAKE2+ support is planned, but not
yet implemented.

Brian Warner first wrote this Python version in July 2010.

#### footnotes

[1]: https://tools.ietf.org/html/rfc5869 "HKDF"
[2]: http://crypto.stanford.edu/~dabo/cryptobook/  "cryptobook"
[3]: http://www.di.ens.fr/~pointche/Documents/Papers/2005_rsa.pdf "RSA 2005"
[4]: https://tools.ietf.org/html/draft-ladd-spake2-01 "Ladd's IETF draft"
