#!/usr/bin/env python
"""A simple Bloom Filter implementation
Calculating optimal filter size: 
            Where:
            m is: self.bitcount (how many bits in self.filter)
            n is: the number of expected values added to self.filter
            k is: the number of hashes being produced
            (1 - math.exp(-float(k * n) / m)) ** k 
http://en.wikipedia.org/wiki/Bloom_filter
"""

#from hashlib import *
import sha3
import hashlib
import mmap
import math
import time

def blake2b512(s):
	h = hashlib.new('blake2b512')
	h.update(s)
	return h

def sha3(s):
	h = hashlib.sha3_256()
	h.update(s)
	return h

class BloomFilter(object):
    """A simple bloom filter for lots of int()"""

    def __init__(self, array_size=((1024**3) *1 ), hashes=17):
        """Initializes a BloomFilter() object:
            Expects:
                array_size (in bytes): 4 * 1024 for a 4KB filter
                hashes (int): for the number of hashes to perform"""

	self.mm = None
        self.filter = bytearray(array_size)     # The filter itself
        self.bitcount = array_size * 8          # Bits in the filter
        self.hashes = hashes                    # The number of hashes to use
	self.bitset = 0
	
    def calc(error_rate,capacity):
	hashes = int(math.ceil(math.log(1.0 / error_rate, 2)))
	bits_per_hash = int(math.ceil((capacity * abs(math.log(error_rate))) /(num_slices * (math.log(2) ** 2))))
	bitcount = bits_per_hash * hashes
	print self.hashes,self.bits_per_hash,self.bitcount

    def _hash(self, value):
        """Creates a hash of an int and yields a generator of hash functions
        Expects:
            value: int()
        Yields:
            generator of ints()"""

        # Build an int() around the sha256 digest of int() -> value
        #value = value.__str__() # Comment out line if you're filtering strings()
	digest = int(blake2b512(value).hexdigest(),16)

        for _ in range(self.hashes):
            # bitwise AND of the digest and all of the available bit positions 
            # in the filter
            yield digest & (self.bitcount - 1)
            # Shift bits in digest to the right, based on 256 (in sha256)
            # divided by the number of hashes needed be produced. 
            # Rounding the result by using int().
            # So: digest >>= (256 / 13) would shift 19 bits to the right.
            digest >>= (256 / self.hashes)
	del digest

    def add(self, value):
        """Bitwise OR to add value(s) into the self.filter
        Expects:
            value: generator of digest ints()
        """
	_hash = self._hash(value)
	self._add(_hash)

    def _add(self,_hash):
        for digest in _hash:
            # In-place bitwise OR of the filter, position is determined 
            # by the (digest / 8) digest is described above in self._hash()
            # Bitwise OR is undertaken on the value at the location and 
            # 2 to the power of digest modulo 8. Ex: 2 ** (30034 % 8) 
            # to grantee the value is <= 128, the bytearray not being able 
            # to store a value >= 256. Q: Why not use ((modulo 9) -1) then?
            self.filter[(digest / 8)] |= (2 ** (digest % 8))
            # The purpose here is to spread out the hashes to create a unique 
            # "fingerprint" with unique locations in the filter array, 
            # rather than just a big long hash blob.
	self.bitset += self.hashes

    def query(self, value):
        """Bitwise AND to query values in self.filter
        Expects:
            value: value to check filter against (assumed int())"""
        # If all() hashes return True from a bitwise AND (the opposite 
        # described above in self.add()) for each digest returned from 
        # self._hash return True, else False
	_hash = self._hash(value)
	return self._query(_hash)    

    def _query(self,_hash):
	return all(self.filter[(digest / 8)] & (2 ** (digest % 8)) 
            for digest in _hash)

    def update(self,value):
	_hash = self._hash(value)
	r = self._query(_hash)
	if not r:
		self._add(_hash)
	return r

    def stat(self):
	print "BLOOM: Bits set: %d of %d" % (self.bitset,self.bitcount), "%3.8f" %  ((float(self.bitset)/self.bitcount)*100) + "%"

if __name__ == "__main__":
    bf = BloomFilter()

    bf.add('30000')
    bf.add('1230213')
    bf.add('1')

    bf.stat()

    print("Filter size {0} bytes").format(bf.filter.__sizeof__())
    print bf.query('1') # True
    print bf.query('1230213') # True
    print bf.query('12') # False
