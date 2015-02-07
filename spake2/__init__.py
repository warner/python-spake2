
from .spake2 import (SPAKE2_A, SPAKE2_B, PAKEError)
from .params import Params1024, Params2048, Params3072
_hush_pyflakes = [SPAKE2_A, SPAKE2_B, PAKEError,
                  Params1024, Params2048, Params3072]
del _hush_pyflakes

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
