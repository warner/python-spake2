
from .groups import I1024, I2048, I3072
from .ed25519_group import Ed25519Group

# M and N are defined as "randomly chosen elements of the group". It is
# important that nobody knows their discrete log (if your
# parameter-provider picked a secret 'haha' and told you to use
# M=pow(g,haha,p), you couldn't tell that M wasn't randomly chosen, but
# they could then mount an active attack against your PAKE session). S
# is the same, but used for both sides of a symmetric session.
#
# The safe way to choose these is to hash a public string.

class Params:
    def __init__(self, group, M=b"M", N=b"N", S=b"symmetric"):
        self.group = group
        self.M = group.arbitrary_element(seed=M)
        self.N = group.arbitrary_element(seed=N)
        self.S = group.arbitrary_element(seed=S)
        self.M_str = M
        self.N_str = N
        self.S_str = S

# Params1024 is roughly as secure as an 80-bit symmetric key, and uses a
# 1024-bit modulus. Params2048 has 112-bit security and comes from NIST.
# Params3072 has 128-bit security.
Params1024 = Params(I1024)
Params2048 = Params(I2048)
Params3072 = Params(I3072)

ParamsEd25519 = Params(Ed25519Group)
