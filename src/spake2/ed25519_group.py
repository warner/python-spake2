from . import ed25519_basic
from .groups import password_to_scalar

class _Ed25519Group:
    def random_scalar(self, entropy_f):
        return ed25519_basic.random_scalar(entropy_f)
    def scalar_to_bytes(self, i):
        return ed25519_basic.scalar_to_bytes(i)
    def bytes_to_scalar(self, b):
        return ed25519_basic.bytes_to_scalar(b)
    def password_to_scalar(self, pw):
        return password_to_scalar(pw, self.scalar_size_bytes, self.order())
    def arbitrary_element(self, seed):
        return ed25519_basic.arbitrary_element(seed)
    def bytes_to_element(self, b):
        return ed25519_basic.bytes_to_element(b)
    def order(self):
        return ed25519_basic.L

Ed25519Group = _Ed25519Group()
Ed25519Group.Base = ed25519_basic.Base
Ed25519Group.Zero = ed25519_basic.Zero
Ed25519Group.scalar_size_bytes = 32
Ed25519Group.element_size_bytes = 32
