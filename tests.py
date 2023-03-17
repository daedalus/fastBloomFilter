from fastBloomFilter.bloom import *
from fastBloomFilter.lib.timing import *

bf0 = BloomFilter(array_size=128 * (1024 ** 2))
bf0.save("1.b")
bf0.calc_hashid()
bf0.stat()

bf0.add("30000")
bf0.add("1230213")
bf0.add("1")

bf1 = BloomFilter()
bf1.calc_hashid()
bf1.stat()

bf1.load("1.b")
bf1.calc_hashid()
bf1.stat()

assert bf1.update("1") == False
assert bf1.update("2") == False
assert bf1.query("1")

@timing
def test_timing_add(L=10**5):
  for i in range(0, L + 1):
    bf0.add(str(i))

@timing
def test_timing_query(L=10**5):
  for i in range(0, L + 1):
    bf0.query(str(i))

test_timing_add()
test_timing_query()
