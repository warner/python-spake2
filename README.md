
# Pure-Python SPAKE2

[![Build Status](https://travis-ci.org/warner/python-spake2.png?branch=master)](https://travis-ci.org/warner/python-spake2)
[![Coverage Status](https://coveralls.io/repos/warner/python-spake2/badge.svg)](https://coveralls.io/r/warner/python-spake2)

This is an easy-to-use implementation of the SPAKE2 password-authenticated
key exchange algorithm, implemented purely in Python, released under the MIT
license. This allows two parties, who share a weak password, to safely derive
a strong shared secret (and therefore build an encrypted+authenticated
channel). A passive attacker who eavesdrops on the connection learns no
information about the password or the generated secret. An active attacker
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

## Dependencies

This package is pure-python: no C code or compiled extension modules are
used. It requires the 'simplejson' module for data serialization.

## Speed

To run the built-in speed tests, just run `python setup.py speed`.

SPAKE2 consists of two phases, separated by a single message exchange. On my
2012 Mac Mini (2.6GHz Core-i7), the default `Params1024` security level takes
about 3.3ms to complete both phases. The `Params2048` level takes about 16ms,
and `Params3072` takes about 32ms. The two phases take roughly equal time.

This library uses only Python. A version which used C speedups for the large
modular multiplication operations would probably be an order of magnitude
faster.

## History

The protocol comes from Dan Boneh and Victor Shoup, described as "PAKE2" in
their ["cryptobook"] [1]. This is a form of "SPAKE2", defined by Abdalla and
Pointcheval at [RSA 2005] [2]. Additional recommendations for groups and
distinguished elements were published in [Ladd's IETF draft] [3].

The Boneh/Shoup chapter that defines PAKE2 also defines an augmented variant
named "PAKE2+", which changes one side (typically a server) to record a
derivative of the password instead of the actual password. In PAKE2+, a
server compromise does not immediately give access to the passwords: instead,
the attacker must perform an offline dictionary attack against the stolen
data before they can learn the passwords. PAKE2+ support is planned, but not
yet implemented.

Brian Warner wrote this Python version in July 2010, based upon the algorithm
from their book.

## Testing

To run the built-in test suite from a source directory, do:

   python setup.py test

The tests take approximately half a second on my computer.

## Security

This library does not protect against timing attacks. Do not allow attackers
to measure how long it takes you to create or respond to a message. This
library depends upon a strong source of random numbers. Do not use it on a
system where os.urandom() is weak.

## Usage

Alice and Bob both initialize their SPAKE2 instances with the same (weak)
password. They will exchange messages to (hopefully) derive a shared secret
key "K". The protocol is symmetric: for each operation that Alice does, Bob
will do the same. For each message that Alice sends, Bob will send a
corresponding message.

However, there are two roles in the SPAKE2 protocol, "A" and "B". The two
sides must agree ahead of time which one will play which role (the messages
they generate depend upon which side they play). For environments in which
one piece of code always plays the same role, there are two separate classes
`SPAKE2_A` and `SPAKE2_B` to make this easier to set up.

Each instance of a SPAKE2 protocol uses a set of shared parameters. These
include a group, a generator, and a pair of arbitrary group elements. The
python-spake2 implementation comes with several pre-generated parameter sets,
with various security levels.

You start by creating a SPAKE2 instance, using the password and the side
indicator (`spake2.SideA` or `spake2.SideB`). You can override an option to
increase the security level (at the expense of processing speed). Then you
ask the instance for the outbound message by calling `msg_out=s.start()`, and
send it to your partner. Once you receive the corresponding inbound message,
you pass it into the instance and extract the (shared) key bytestring with
`key=s.finish(msg_in)`. For example, the client-side might do:

```python
from spake2 import SPAKE2_A
s = SPAKE2_A(b"our password")
msg_out = s.start()
send(msg_out)
msg_in = receive()
key = s.finish(msg_in)
```

while the server-side might do:

```python
from spake2 import SPAKE2_B
q = SPAKE2_B(b"our password")
msg_out = q.start()
send(msg_out)
msg_in = receive()
key = q.finish(msg_in)
```

If both sides used the same password, and there is no man-in-the-middle, then
both sides will obtain the same key. If not, the two sides will get different
keys, so using "key" for data encryption will result in garbled data. To
safely test for identical keys before use, you can perform a second message
exchange at the end of the protocol, before actually using the key (be
careful to not simply send the shared key over the encrypted wire: this would
allow a MitM to learn the key that they could otherwise not guess). This
key-confirmation step is asymmetric: one side will always learn about the
success or failure of the protocol before the other.

```python
# Alice does this:
...
key = s.finish(msg_in)
hhkey = sha256(sha256(key).digest()).digest()
send(hhkey)

# and Bob does this:
...
key = q.finish(msg_in)
their_hhkey = receive()
my_hhkey = sha256(sha256(key).digest()).digest()
assery my_hhkey == their_hhkey
hkey = sha256(key).digest()
send(hkey)

# and then Alice does this:
their_hkey = receive()
my_hkey = sha256(key).digest()
assert my_hkey == their_hkey
```

The shared "key" can be used as an AES data-encryption key, and/or an HMAC
key to provide data integrity. It can also be used to derive other session
keys as necessary.

#### footnotes

[1]: http://crypto.stanford.edu/~dabo/cryptobook/  "cryptobook"
[2]: http://www.di.ens.fr/~pointche/Documents/Papers/2005_rsa.pdf "RSA 2005"
[3]: https://tools.ietf.org/html/draft-ladd-spake2-01 "Ladd's IETF draft"
