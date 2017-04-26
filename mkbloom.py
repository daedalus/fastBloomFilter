import sys
import bloom

try:
	array_size = int(sys.argv[2])
except:
	array_size = (1024**3)*5

bf = bloom.BloomFilter(array_size=array_size,do_bkp=False, bitshuffle=True)
bf.filename = sys.argv[1]
bf.save()

