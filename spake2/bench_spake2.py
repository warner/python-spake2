
import timeit, sys
from spake2 import SPAKE2_P, SPAKE2_Q, params_80, params_112, params_128
hush_pyflakes = [params_80, params_112, params_128]

class Harness:
    def setup(self, params=params_80):
        self.params = params
        self.pw = pw = "password"
        self.jA = SPAKE2_P(pw, params=params)
        self.jB = SPAKE2_Q(pw, params=params)
        self.m1A,self.m1B = self.jA.one(), self.jB.one()
        #kA,kB = self.jA.two(m1B), self.jB.two(m1A)
    def construct(self):
        SPAKE2_P(self.pw, params=self.params)
    def one(self):
        self.jA.one()
    def two(self):
        self.jA.two(self.m1B)

h = Harness()

if __name__ == "__main__":
    if len(sys.argv) == 1:
        all_params = ["params_80", "params_112", "params_128"]
        all_names = ["construct", "one", "two"]
    else:
        params,name = sys.argv[1].split(".")
        all_params = [params]
        all_names = [name]
    for params in all_params:
        for name in all_names:
            print "%s %s:" % (params, name),
            timeit.main(["--setup",
                         ("import bench_spake2; "
                          "bench_spake2.h.setup(bench_spake2.%s)" % params),
                         "bench_spake2.h.%s()" % name,
                         ])

# 78:warner@Cookies% python spake2/bench_spake2.py
# params_80 construct: 100000 loops, best of 3: 13.6 usec per loop
# params_80 one: 100 loops, best of 3: 19.3 msec per loop
# params_80 two: 100 loops, best of 3: 19.2 msec per loop
# params_112 construct: 100000 loops, best of 3: 13.4 usec per loop
# params_112 one: 10 loops, best of 3: 92.3 msec per loop
# params_112 two: 10 loops, best of 3: 92.4 msec per loop
# params_128 construct: 100000 loops, best of 3: 12.2 usec per loop
# params_128 one: 10 loops, best of 3: 211 msec per loop
# params_128 two: 10 loops, best of 3: 211 msec per loop
