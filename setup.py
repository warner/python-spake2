#!/usr/bin/env python

from __future__ import print_function
import sys, subprocess
from distutils.core import setup, Command
import versioneer
versioneer.VCS = "git"
versioneer.versionfile_source = "spake2/_version.py"
versioneer.versionfile_build = versioneer.versionfile_source
versioneer.tag_prefix = "v"
versioneer.parentdir_prefix = "python-spake2-"

cmdclass = {}
cmdclass.update(versioneer.get_cmdclass())

class Test(Command):
    description = "run unit tests"
    user_options = []
    boolean_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        from spake2 import test_spake2
        test_spake2.unittest.main(module=test_spake2, argv=["dummy"])
cmdclass["test"] = Test

class Speed(Command):
    description = "run speed benchmarks"
    user_options = []
    boolean_options = []
    def initialize_options(self):
        pass
    def finalize_options(self):
        pass
    def run(self):
        p = subprocess.Popen([sys.executable, "spake2/bench_spake2.py"])
        rc = p.wait()
        if rc != 0:
            sys.exit(rc)
cmdclass["speed"] = Speed

setup(name="spake2",
      version=versioneer.get_version(),
      description="SPAKE2 password-authenticated key exchange (pure python)",
      author="Brian Warner",
      author_email="warner-pyspake2@lothar.com",
      url="http://github.com/warner/python-spake2",
      packages=["spake2"],
      license="MIT",
      cmdclass=cmdclass,
      )
