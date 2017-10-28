#!/usr/bin/env python
# Author Dario Clavijo 2017
# GPlv3

import bloom
import sys

bf = bloom.BloomFilter()

fp = open(sys.argv[1],'r')
for line in fp:
	bf.add(line.rstrip())
fp.close()

bf.save(sys.argv[2])

