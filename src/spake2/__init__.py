
from .spake2 import SPAKE2_A, SPAKE2_B, SPAKE2_Symmetric, SPAKEError
SPAKE2_A, SPAKE2_B, SPAKE2_Symmetric, SPAKEError # hush pyflakes

from . import _version
__version__ = _version.get_versions()['version']
