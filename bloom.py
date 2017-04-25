#!/usr/bin/env python
# based on https://gist.github.com/josephkern/2897618
"""A simple Bloom Filter implementation
Calculating optimal filter size: 
            Where:
            m is: self.bitcount (how many bits in self.filter)
            n is: the number of expected values added to self.filter
            k is: the number of hashes being produced
            (1 - math.exp(-float(k * n) / m)) ** k 
http://en.wikipedia.org/wiki/Bloom_filter
"""

import sha3
import hashlib
import mmap
import math
import time
import zlib
import lz4
import lzo
import bz2
import os
import numpy
import bitshuffle

#global bfilter

def blake2b512(s):
	h = hashlib.new('blake2b512')
	h.update(s)
	return h

def sha3(s):
	h = hashlib.sha3_256()
	h.update(s)
	return h

def sha256(s):
	h = hashlib.sha256()
	h.update(s)
	return h

def shannon_entropy(data, iterator=None):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0

    if iterator is None:
	iterator = []	
	for i in range(0,255):
	    iterator+=chr(i)

    for x in (ord(c) for c in iterator):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
	
    del p_x
    del iterator

    return entropy

def buff_shuffle(buff):
        buff = numpy.frombuffer(buff)
        buff = bitshuffle.bitshuffle(buff).tostring()
        return buff

def buff_unshuffle(buff):
	buff = numpy.frombuffer(buff)
	buff = bitshuffle.bitunshuffle(buff).tostring()
	return buff

class BloomFilter(object):
    """A simple bloom filter for lots of int()"""

    def __init__(self, array_size=((1024**3)*10), slices=17,slice_bits=256,do_hashes=True,filename=None,do_bkp=True,bitshuffle=False):
        """Initializes a BloomFilter() object:
            Expects:
                array_size (in bytes): 4 * 1024 for a 4KB filter
                hashes (int): for the number of hashes to perform"""


	self.do_bkp = do_bkp
	self.saving = False	
	self.merging = False		
	self.shuffle = bitshuffle  				# shuffling the data before compression, it gains more compression ratio.
	self.header = 'BLOOM:\0\0\0\0'

	self.slices = slices                    	# The number of hashes to use
	self.slice_bits = slice_bits			# n bits of the hash
	self.bitset = 0					# n bits set in the bloom filter
	self.do_hashes = do_hashes			# use a provided hash o compute it.
	
	self.filename = filename
	if filename !=None and self.load() == True:
		print "BLOOM: Loaded OK"
	else:
	        self.bfilter = bytearray(array_size)    # The filter itself
        	self.bitcount = array_size * 8          # Bits in the filter



	print "BLOOM: filename: %s, do_hashes: %s, slices: %d, bits_per_slice: %d, do_bkp: %s, shuffle: %s" % (self.filename, self.do_hashes, self.slices, self.slice_bits,self.do_bkp,self.shuffle)

    def len(self):
    	return len(self.bfilter)
	
    def calc_capacity(error_rate,capacity):
	hashes = int(math.ceil(math.log(1.0 / error_rate, 2)))
	bits_per_hash = int(math.ceil((capacity * abs(math.log(error_rate))) /(num_slices * (math.log(2) ** 2))))
	bitcount = bits_per_hash * hashes
	print self.hashes,self.bits_per_hash,self.bitcount

    def calc_entropy(self):
	self.entropy = shannon_entropy(self.bfilter)
	print "Entropy: %1.8f" % self.entropy 

    def calc_hashid(self):
	data = str(self.bfilter)
	self.hashid = blake2b512(data)
	del data
	print "BLOOM: HASHID:", self.hashid.hexdigest()[0:8]

    def _raw_merge(self,bfilter):
	if self.merging = False:
		self.merging = True
		print "BLOOM: Merging..."
		if len(bfilter) == len(self.bfilter):
			for i in range(0,len(bfilter)-1):
				self.bfilter[i] |= bfilter[i]
		print "BLOOM: Merged Ok"
		else:
			print "Bloom filters are not conformable"
		self.merging = False

    def _hash(self, value):
        """Creates a hash of an int and yields a generator of hash functions
        Expects:
            value: int()
        Yields:
            generator of ints()"""

        # Build an int() around the sha256 digest of int() -> value
        #value = value.__str__() # Comment out line if you're filtering strings()
	if self.do_hashes:
		digest = int(blake2b512(value).hexdigest(),16)
	else:
		digest = value

        for _ in range(self.slices):
            # bitwise AND of the digest and all of the available bit positions 
            # in the filter
            yield digest & (self.bitcount - 1)
            # Shift bits in digest to the right, based on 256 (in sha256)
            # divided by the number of hashes needed be produced. 
            # Rounding the result by using int().
            # So: digest >>= (256 / 13) would shift 19 bits to the right.
            digest >>= (self.slice_bits / self.slices)
	del digest

    def add(self, value):
        """Bitwise OR to add value(s) into the self.filter
        Expects:
            value: generator of digest ints()
        """
	_hash = self._hash(value)
	self._add(_hash)
	del _hash

    def _add(self,_hash):
	#global filter
        for digest in _hash:
            # In-place bitwise OR of the filter, position is determined 
            # by the (digest / 8) digest is described above in self._hash()
            # Bitwise OR is undertaken on the value at the location and 
            # 2 to the power of digest modulo 8. Ex: 2 ** (30034 % 8) 
            # to grantee the value is <= 128, the bytearray not being able 
            # to store a value >= 256. Q: Why not use ((modulo 9) -1) then?
            self.bfilter[(digest / 8)] |= (2 ** (digest % 8))
            # The purpose here is to spread out the hashes to create a unique 
            # "fingerprint" with unique locations in the filter array, 
            # rather than just a big long hash blob.
	self.bitset += self.slices

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
	#global bfilter
	return all(self.bfilter[(digest / 8)] & (2 ** (digest % 8)) 
            for digest in _hash)

    def update(self,value):
	_hash = self._hash(value)
	r = self._query(_hash)
	if not r:
		self._add(_hash)
	del _hash
	return r

    def _readfile(self,filename):
	data = ''
	SIZE=1024*128
        fp = open(filename,'rb')
        recvbuf = fp.read(SIZE)
        while len(recvbuf) > 0:
                data += recvbuf
                recvbuf = fp.read(1024*128)
        fp.close()
	del recvbuf
	del fp
	del SIZE
	return data
   
    def _decompress(self,data):
	data = bz2.decompress(data)
        data = zlib.decompress(data)
        #data = zlib.decompress(data)
        data = data.decode('zlib')
	try:
		data = lzo.decompress(data)
	except:
		pass
        try:
        	data = lz4.decompress(data)
        except:
        	pass

	if self.shuffle == True:
		try:
			print "unshuffling..."
			data = buff_unshuffle(data)
			print "data unshuffled..."
		except:
			pass

	return data

    def load(self,filename=None):
	t0 = time.time()
	if filename != None:
		fn = filename
	else:
		fn = self.filename
	print "loading bloom file:",fn
	data = self._readfile(fn)
	ld = len(data)
	if ld >0:
		data = self._decompress(data)
		self.header=data[0:10]
		print "HEADER:", self.header.encode('hex')
		if self.header[0:6] == 'BLOOM:':
			self.bfilter = bytearray()
			self.hashid = blake2b512(data[10:])
			self.bfilter.extend(data[10:])
		else:
			print "BLOOM: HEADER ERROR, FILTER IS NOT REALIABLE!!!"
			self.bfilter = bytearray()
			#self.hashid = blake2b512(data)
                        self.bfilter.extend(data)
                self.bitcount = len(self.bfilter) * 8
                self.bitset = 0
		#return True	

	del data	
	del fn
	t1 = time.time()
	print "Loaded: %d bytes, Inflated: %d bytes" % (ld,len(self.bfilter))
	print "In: %d sec" % (t1-t0) 
	print "HASHID: ", self.hashid.hexdigest()[:8],self.header[6:].encode('hex')
	del ld
	del t1 
	del t0
	return True

    def _dump(self):
	print "Dumping filter contents..."
	for i in xrange(0,len(self.bfilter)-1,64):
		print str(self.bfilter[i:i+64]).encode('hex')


    def _writefile(self,data,filename):
        fp = open(filename,'wb')
	SIZE = 1024*128
	for i in xrange(0,len(data)-1,SIZE):
		fp.write(data[i:i+SIZE])
        fp.close()
	del fp
	del SIZE

    def _bkp(self,filename):
	f1 = os.path.getsize(filename)
	f2 = os.path.getsize('%s.bkp' % filename)
	if f1 > f2:
	    os.system('cp %s %s.bkp' % (filename,filename))
	del f2
	del f1

    def _compress(self, data):
	if self.shuffle == True:
		try:
			print "shuffling..."
			data = buff_shuffle(data)
			print "data shuffled..."
		except:
			pass
	try:
		data = lz4.compress(data)
	except:
		pass
	try:
		data = lzo.compress(data)
	except:
		pass
	print "Compressing..."
	data = data.encode('zlib')
	#data = zlib.compress(data,1)
	data = zlib.compress(data,9)
	data = bz2.compress(data,9)
    	return data
	
    def save(self,filename=None):
	if not self.saving:
	    self.saving = True
	    t0 = time.time()
	    if filename != None:
		fn = filename
	    else:
		fn = self.filename
	    if self.do_bkp:
	    	self._bkp(fn)
	    print "Saving bloom to:",fn

	    data = str(self.bfilter)
            self.hashid = blake2b512(data)
	    self.header = "BLOOM:" + self.hashid.digest()[0:4]
	    #print len(self.header)
	    data = self._compress(self.header+data)
	    print "Writing..."
	    self._writefile(data,fn)
	    del data
	    t1 = time.time()
	    d = (t1-t0)
	    del t1 
            del t0
	    print "Saved in %d sec, HASHID: %s" % (d,self.hashid.hexdigest()[0:8])
	    self.saving = False
	    return d
 
    def stat(self):
	print "BLOOM: Bits set: %d of %d" % (self.bitset,self.bitcount), "%3.8f" %  ((float(self.bitset)/self.bitcount)*100) + "%"

    def info(self):
	print "BLOOM: filename: %s do_hashes: %s slices: %d bits_per_slice: %d" % (self.filename, self.do_hashes, self.slices, self.slice_bits)
	self.calc_hashid()
	self.calc_entropy()
	self.stat()	

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

    t0 = time.time()
    #bf.save('/tmp/test.bloom')
    t1 = time.time()
    t2 = t1 -t0
    print t2
