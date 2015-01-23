
from spake2 import SPAKE2, SPAKE2_P, SPAKE2_Q, PAKEError, \
     params_80, params_112, params_128
_hush_pyflakes = [SPAKE2, SPAKE2_P, SPAKE2_Q, PAKEError,
                  params_80, params_112, params_128]
del _hush_pyflakes

try:
    from _version import __version__ as v
    __version__ = v
    del v
except ImportError:
    __version__ = "UNKNOWN"

