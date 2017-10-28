import sys
import bloom

filename = sys.argv[1]

try:
	Gigs = int(sys.argv[2])
except ValueError as verr:
	print "Plase input the correct number of Gigabytes of RAM to be used."
	exit(1)

if Gigs > 0:
	bf = bloom.BloomFilter(array_size=Gigs*(1024**3),do_bkp=False,do_hashing=False,fast=False)
	bf.save(filename)
