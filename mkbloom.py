import sys
import bloom

try:
	array_size = int(sys.argv[2])
except:
	array_size = (1024**3)*1

bf = bloom.BloomFilter(array_size=array_size,do_bkp=False,do_hashing=False, bitshuffle=False,fast=False)
filename = sys.argv[1]
bf.save(filename)

