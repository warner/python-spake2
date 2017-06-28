
# M and N are defined as "randomly chosen elements of the group". It is
# important that nobody knows their discrete log (if your
# parameter-provider picked a secret 'haha' and told you to use
# M=pow(g,haha,p), you couldn't tell that M wasn't randomly chosen, but
# they could then mount an active attack against your PAKE session). S
# is the same, but used for both sides of a symmetric session.
#
# The safe way to choose these is to hash a public string.

class _Params:
    def __init__(self, group, M=b"M", N=b"N", S=b"symmetric"):
        self.group = group
        self.M = group.arbitrary_element(seed=M)
        self.N = group.arbitrary_element(seed=N)
        self.S = group.arbitrary_element(seed=S)
        self.M_str = M
        self.N_str = N
        self.S_str = S
