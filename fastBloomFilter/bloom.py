#!/usr/bin/env python
# based on https://gist.github.com/josephkern/2897618
"""
A simple Bloom Filter implementation
Calculating optimal filter size:
            Where:
            m is: self.bitcount (how many bits in self.filter)
            n is: the number of expected values added to self.filter
            k is: the number of hashes being produced
            (1 - math.exp(-float(k * n) / m)) ** k
http://en.wikipedia.org/wiki/Bloom_filter
"""
# Author Dario Clavijo 2017
# GPLv3

import sys

if sys.version_info < (3, 6):
    import sha3
import hashlib
import math
import time
import os
import bitarray
import binascii
from lib.pickling import *

is_python3 = sys.version_info.major == 3


def blake2b512(s):
    h = hashlib.new("blake2b512")
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
        for i in range(0, 255):
            iterator += chr(i)
    for x in (ord(c) for c in iterator):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)
    del p_x
    del iterator
    return entropy


def display(digest):
    str_i = "Display: "
    for i in digest:
        str_i += str(i) + " "
    sys.stderr.write(str_i)


class BloomFilter(object):
    def __init__(
        self,
        array_size=((1024 ** 3) * 1),
        slices=10,
        slice_bits=256,
        do_hashing=True,
        filename=None,
        fast=False,
        data_is_hex=False,
    ):
        """
        Initializes a BloomFilter() object:
        Expects:
            array_size (in bytes): 4 * 1024 for a 4KB filter
            hashes (int): for the number of hashes to perform
        """

        self.saving = False
        self.loading = False
        self.bitcalc = False
        self.merging = False
        self.fast = fast
        self.data_is_hex = data_is_hex  # ignored when do_hashes = True
        self.header = "BLOOM:\0\0\0\0"

        self.slices = slices  # The number of hashes to use
        self.slice_bits = slice_bits  # n bits of the hash
        self.bitset = 0  # n bits set in the bloom filter
        self.do_hashes = do_hashing  # use a provided hash o compute it.
        self.hits = 0
        self.queryes = 0
        try:
            self.hashfunc = blake2b512
        except:
            self.hashfunc = sha3

        self.filename = filename
        if filename != None and self.load() == True:
            sys.stderr.write("BLOOM: Loaded OK\n")
        else:
            # self.bfilter = bytearray(array_size)    # The filter itself
            self.bfilter = bitarray.bitarray(array_size * 8, endian="little")
            self.bfilter.setall(0)
            self.bitcount = array_size * 8  # Bits in the filter

        sys.stderr.write(
            "BLOOM: filename: %s, do_hashes: %s, slices: %d, bits_per_hash: %d, func:%s\n"
            % (
                self.filename,
                self.do_hashes,
                self.slices,
                self.slice_bits,
                str(self.hashfunc).split(" ")[1],
            )
        )

    def len(self):
        return len(self.bfilter)

    def calc_capacity(self, error_rate, capacity):
        hashes = int(math.ceil(math.log(1.0 / error_rate, 2)))
        bits_per_hash = int(
            math.ceil(
                (capacity * abs(math.log(error_rate)))
                / (self.slices * (math.log(2) ** 2))
            )
        )
        bitcount = bits_per_hash * hashes
        sys.stderr.write(
            "Hashes: %d, bit_per_hash: %d bitcount: %d\n"
            % (self.hashes, self.bits_per_hash, bitcount)
        )

    def calc_entropy(self):
        self.entropy = shannon_entropy(self.bfilter)
        sys.stderr.write("Entropy: %1.8f\n" % self.entropy)

    def calc_hashid(self):
        data = self.bfilter.tobytes()
        self.hashid = self.hashfunc(data)
        del data
        sys.stderr.write("BLOOM: HASHID: %s\n" % self.hashid.hexdigest()[0:8])

    def _raw_merge(self, bfilter):
        """
        Merges two conforming in size binary filters.
        """
        if self.merging == False:
            self.merging = True
            sys.stderr.write("BLOOM: Merging...\n")
            if len(bfilter) == len(self.bfilter):
                for i in range(0, len(bfilter)):
                    self.bfilter[i] |= bfilter[i]
                sys.stderr.write("BLOOM: Merged Ok\n")
            else:
                sys.stderr.write("BLOOM: filters are not conformable\n")
            self.merging = False

    def __add__(self, otherFilter):
        self._raw_merge(otherFilter)
        return self

    def _hash(self, value):
        """
        Creates a hash of an int and yields a generator of hash functions
        Expects:
            value: int()
        Yields:
            generator of ints()
        """

        # Build an int() around the sha256 digest of int() -> value
        # value = value.__str__() # Comment out line if you're filtering strings()
        if self.do_hashes:
            digest = int.from_bytes(self.hashfunc(value.encode("utf8")).digest(), "big")
        else:
            if self.data_is_hex:
                digest = int(value, 16)
            else:
                try:
                    digest = int(value.hex(), 16)
                except:
                    digest = int(binascii.hexlify(value), 16)
        if self.fast:
            yield (digest % self.bitcount)
        else:
            for _ in range(0, self.slices):
                # bitwise AND of the digest and all of the available bit positions
                # in the filter
                yield digest & (self.bitcount - 1)
                # Shift bits in digest to the right, based on 256 (in sha256)
                # divided by the number of hashes needed be produced.
                # Rounding the result by using int().
                # So: digest >>= (256 / 13) would shift 19 bits to the right.
                digest >>= int(self.slice_bits / self.slices)
        del digest

    def add(self, value):
        """
        Bitwise OR to add value(s) into the self.filter
        Expects:
            value: generator of digest ints()
        """
        if not self.saving and not self.loading and not self.merging:
            _hash = self._hash(value)
            self._add(_hash)
            del _hash

    def _add(self, __hash):
        # global filter
        for digest in __hash:
            # In-place bitwise OR of the filter, position is determined
            # by the (digest / 8) digest is described above in self._hash()
            # Bitwise OR is undertaken on the value at the location and
            # 2 to the power of digest modulo 8. Ex: 2 ** (30034 % 8)
            # to grantee the value is <= 128, the bytearray not being able
            # to store a value >= 256. Q: Why not use ((modulo 9) -1) then?
            self.bfilter[digest] = True

            # The purpose here is to spread out the hashes to create a unique
            # hash with unique locations in the filter array,
            # rather than just a big long hash blob.
        if self.fast:
            self.bitset += 1
        else:
            self.bitset += self.slices

    def query(self, value):
        """
        Bitwise AND to query values in self.filter
        Expects:
            value: value to check filter against (assumed int())
        """
        # If all() hashes return True from a bitwise AND (the opposite
        # described above in self.add()) for each digest returned from
        # self._hash return True, else False
        __hash = self._hash(value)
        return self._query(__hash)

    def _query(self, __hash):
        # global bfilter
        ret = all(self.bfilter[digest] for digest in __hash)
        if ret:
            self.hits += 1
        self.queryes += 1
        return ret

    def update(self, value):
        """ 
        This function first queryies the filter for a value then adds it.
        Very useful for caches, where we want to know if an element was already seen.
        update(value)= alread_seen(value)
        """
        if not self.saving and not self.loading and not self.merging:
            __hash = [*(self._hash(value))]
            r = self._query(__hash)
            if r == False:
                self._add(__hash)
            del __hash
            return r
 
    def load(self, filename):
        if not self.loading:
            self.loading = True
            BF = decompress_pickle(filename)      
            self.filename = filename
            self.do_hashes = BF.do_hashes 
            self.data_is_hex = BF.data_is_hex
            self.slices = BF.slices
            self.slice_bits = BF.slice_bits
            self.hashfunc = BF.hashfunc
            self.bfilter = BF.bfilter
            self.fast = BF.fast
            self.bitcount = BF.bitcount
            self.bitset = BF.bitset
            self.loading = False
            return True

    def save(self, filename = None):
        if not self.saving:
            if filename is None and self.filename is None:
                sys.stderr.write("A Filename must be provided\n")
                return False
            else:
                self.saving = True
                if filename is not None:
                    self.filename = filename
                compress_pickle(self.filename, self)     
                self.saving = False
                return True

    def stat(self):
        if self.bitcalc:
            sys.stderr.write(
                "BLOOM: Bits set: %d of %d" % (self.bitset, self.bitcount)
                + " %3.8f" % ((float(self.bitset) / self.bitcount) * 100)
                + "%\n"
            )
            sys.stderr.write(
                "BLOOM: Hits %d over Querys: %d, hit_ratio: %3.8f"
                % (self.hits, self.queryes, (float(self.hits / self.queryes) * 100))
                + "%\n"
            )
        bytes_ = (self.bitcount - self.bitset) / 8.0
        Mfree = bytes_ / (1024 ** 2)
        sys.stderr.write("BLOOM: Free: %d Megs\n" % Mfree)

    def info(self):
        sys.stderr.write(
            "BLOOM: filename: %si, do_hashes: %s, slices: %d, bits_per_slice: %d, fast: %s\n"
            % (self.filename, self.do_hashes, self.slices, self.slice_bits, self.fast)
        )
        self.calc_hashid()
        self.calc_entropy()
        self.stat()
