#!/usr/bin/env python

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
        for t in ["spake2/test_spake2.py",
                  ]:
            rc = self.do_test(t)
            if rc != 0:
                sys.exit(rc)

    def do_test(self, which):
        print "======= running %s" % which
        p = subprocess.Popen([sys.executable, which])
        rc = p.wait()
        if rc != 0:
            print >>sys.stderr, "Test (%s) FAILED" % which
        print "== finished %s" % which
        return rc
cmdclass["test"] = Test

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
