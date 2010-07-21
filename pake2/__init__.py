
from pake2 import PAKE2, PAKE2_P, PAKE2_Q, PAKEError, \
     params_80, params_112, params_128
_hush_pyflakes = [PAKE2, PAKE2_P, PAKE2_Q, PAKEError,
                  params_80, params_112, params_128]
del _hush_pyflakes

try:
    from _version import __version__ as v
    __version__ = v
    del v
except ImportError:
    __version__ = "UNKNOWN"

