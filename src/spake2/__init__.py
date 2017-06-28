
from .spake2 import SPAKE2_A, SPAKE2_B, SPAKE2_Symmetric, SPAKEError
SPAKE2_A, SPAKE2_B, SPAKE2_Symmetric, SPAKEError # hush pyflakes

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
