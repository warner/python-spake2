
from .spake2 import (SPAKE2, SPAKE2_A, SPAKE2_B,
                     PAKEError, SideA, SideB)
from .params import Params1024, Params2048, Params3072
_hush_pyflakes = [SPAKE2, SPAKE2_A, SPAKE2_B, PAKEError, SideA, SideB,
                  Params1024, Params2048, Params3072]
del _hush_pyflakes

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
