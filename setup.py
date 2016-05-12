#!/usr/bin/env python

from __future__ import print_function
import timeit
from setuptools import setup, Command
import versioneer

cmdclass = {}
cmdclass.update(versioneer.get_cmdclass())

class Speed(Command):
    description = "run speed benchmarks"
    user_options = []
    boolean_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        def do(setup_statements, statement):
            # extracted from timeit.py
            t = timeit.Timer(stmt=statement,
                             setup="\n".join(setup_statements))
            # determine number so that 0.2 <= total time < 2.0
            for i in range(1, 10):
                number = 10**i
                x = t.timeit(number)
                if x >= 0.2:
                    break
            return x / number

        def abbrev(t):
            if t > 1.0:
                return "%.3fs" % t
            if t > 1e-3:
                return "%.1fms" % (t*1e3)
            return "%.1fus" % (t*1e6)

        for params in ["ParamsEd25519",
                       "Params1024", "Params2048", "Params3072"]:
            S1 = "from spake2 import SPAKE2_A, SPAKE2_B, %s" % params
            S2 = "sB = SPAKE2_B(b'password', params=%s)" % params
            S3 = "mB = sB.start()"
            S4 = "sA = SPAKE2_A(b'password', params=%s)" % params
            S5 = "mA = sA.start()"
            S8 = "key = sA.finish(mB)"

            full = do([S1, S2, S3], ";".join([S4, S5, S8]))
            start = do([S1], ";".join([S4, S5]))
            # how large is the generated message?
            from spake2 import params as all_params
            from spake2 import SPAKE2_A
            p = getattr(all_params, params)
            s = SPAKE2_A(b"pw", params=p)
            msglen = len(s.start())
            statelen = len(s.serialize())
            print("%-13s: msglen=%3d, statelen=%3d, full=%6s, start=%6s"
                  % (params, msglen, statelen, abbrev(full), abbrev(start)))
cmdclass["speed"] = Speed

setup(name="spake2",
      version=versioneer.get_version(),
      description="SPAKE2 password-authenticated key exchange (pure python)",
      author="Brian Warner",
      author_email="warner-pyspake2@lothar.com",
      url="http://github.com/warner/python-spake2",
      package_dir={"": "src"},
      packages=["spake2", "spake2.test"],
      license="MIT",
      cmdclass=cmdclass,
      classifiers=[
          "Intended Audience :: Developers",
          "License :: OSI Approved :: MIT License",
          "Programming Language :: Python",
          "Programming Language :: Python :: 2.6",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3.3",
          "Programming Language :: Python :: 3.4",
          "Programming Language :: Python :: 3.5",
          "Topic :: Security :: Cryptography",
          ],
      install_requires=["hkdf"],
      )
