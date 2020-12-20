import sys
import bloom

filename = sys.argv[1]

try:
    gigs = int(sys.argv[2])
    if gigs > 0:
        bf = bloom.BloomFilter(array_size=gigs * (1024 ** 3), do_bkp=False, do_hashing=False, fast=False)
        bf.save(filename)
except ValueError as _:
    print("Please input the correct number of Gigabytes of RAM to be used.")
    exit(1)
