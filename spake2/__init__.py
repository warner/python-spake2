
from spake2 import SPAKE2, SPAKE2_P, SPAKE2_Q, PAKEError, \
     params_80, params_112, params_128
_hush_pyflakes = [SPAKE2, SPAKE2_P, SPAKE2_Q, PAKEError,
                  params_80, params_112, params_128]
del _hush_pyflakes

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
