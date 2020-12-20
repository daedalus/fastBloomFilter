#!/usr/bin/env python
# based on https://gist.github.com/josephkern/2897618
"""A simple Bloom Filter implementation
Calculating optimal filter size:
            Where:
            m is: self.bit_count (how many bits in self.filter)
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
import zlib
import lz4
import lzo
import bz2
import lzma
import os
import bitarray
import binascii

is_python3 = (sys.version_info.major == 3)


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
        for i in range(0, 255):
            iterator += chr(i)

    for x in (ord(c) for c in iterator):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)

    del p_x
    del iterator

    return entropy


def display(digest):
    str_i = "Display: "
    for i in digest:
        str_i += str(i) + " "
    sys.stderr.write(str_i)


class BloomFilter(object):
    """A simple bloom filter for lots of int()"""

    def __init__(self, array_size=((1024 ** 3) * 1), slices=10, slice_bits=256, do_hashing=True,
                 filename=None, do_bkp=True, re_flink=False, fast=False, data_is_hex=False):
        """
        Initializes a BloomFilter() object:
            Expects:
                array_size (in bytes): 4 * 1024 for a 4KB filter
                hashes (int): for the number of hashes to perform
        """

        self.re_flink = re_flink  # if supported by the underlying FS it will spare some copy cicles.
        self.do_bkp = do_bkp
        self.saving = False
        self.bitcalc = False
        self.merging = False
        self.fast = fast
        self.data_is_hex = data_is_hex  # ignored when do_hashes = True
        self.header = 'BLOOM:\0\0\0\0'

        self.slices = slices  # The number of hashes to use
        self.slice_bits = slice_bits  # n bits of the hash
        self.bitset = 0  # n bits set in the bloom filter
        self.do_hashes = do_hashing  # use a provided hash o compute it.
        self.hits = 0
        self.queries = 0
        self.size = 1024 * 128
        try:
            self.hash_func = blake2b512
        except:
            self.hash_func = sha3

        self.filename = filename
        if filename is not None and self.load() is True:
            sys.stderr.write("BLOOM: Loaded OK\n")
        else:
            self.bf = bitarray.bitarray(array_size * 8, endian='little')
            self.bit_count = array_size * 8  # Bits in the filter

    def len(self):
        return len(self.bf)

    def calc_capacity(self, error_rate, capacity):
        hashes = int(math.ceil(math.log(1.0 / error_rate, 2)))
        bits_per_hash = int(math.ceil((capacity * abs(math.log(error_rate))) / (self.slices * (math.log(2) ** 2))))
        bit_count = bits_per_hash * hashes
        sys.stderr.write("Hashes: %d, bit_per_hash: %d bit_count: %d\n" % (hashes, bits_per_hash, bit_count))

    def calc_entropy(self):
        self.entropy = shannon_entropy(self.bf)
        sys.stderr.write("Entropy: %1.8f\n" % self.entropy)

    def calc_hashed(self):
        data = self.bf.tobytes()
        self.hashed = self.hash_func(data)
        del data
        sys.stderr.write("BLOOM: hashed: %s\n" % self.hashed.hexdigest()[0:8])

    def _raw_merge(self, bf):
        if self.merging is False:
            self.merging = True
            sys.stderr.write("BLOOM: Merging...\n")
            if len(bf) == len(self.bf):
                for i in range(0, len(bf) - 1):
                    self.bf[i] |= bf[i]
                sys.stderr.write("BLOOM: Merged Ok\n")
            else:
                sys.stderr.write("BLOOM: filters are not conformable\n")
            self.merging = False

    def _hash(self, value):
        """Creates a hash of an int and yields a generator of hash functions
        Expects:
            value: int()
        Yields:
            generator of ints()"""

        # Build an int() around the sha256 digest of int() -> value
        # value = value.__str__() # Comment out line if you're filtering strings()
        if self.do_hashes:
            digest = int(self.hash_func(value).hexdigest(), 16)
        else:
            if self.data_is_hex:
                digest = int(value, 16)
            else:
                try:
                    digest = int(value.hex(), 16)
                except:
                    digest = int(binascii.hexlify(value), 16)
        if self.fast:
            yield digest % self.bit_count
        else:
            for _ in range(0, self.slices):
                # bitwise AND of the digest and all of the available bit positions
                # in the filter
                yield digest & (self.bit_count - 1)
                # Shift bits in digest to the right, based on 256 (in sha256)
                # divided by the number of hashes needed be produced.
                # Rounding the result by using int().
                # So: digest >>= (256 / 13) would shift 19 bits to the right.
                digest >>= int(self.slice_bits / self.slices)
        del digest

    def add(self, value):
        """Bitwise OR to add value(s) into the self.filter
        Expects:
            value: generator of digest ints()
        """
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
            self.bf[digest] = True

            # The purpose here is to spread out the hashes to create a unique
            # hash with unique locations in the filter array,
            # rather than just a big long hash blob.
        if self.fast:
            self.bitset += 1
        else:
            self.bitset += self.slices

    def query(self, value):
        """Bitwise AND to query values in self.filter
        Expects:
            value: value to check filter against (assumed int())"""
        # If all() hashes return True from a bitwise AND (the opposite
        # described above in self.add()) for each digest returned from
        # self._hash return True, else False
        __hash = self._hash(value)
        return self._query(__hash)

    def _query(self, __hash):
        # global bf
        ret = all(self.bf[digest] for digest in __hash)
        if ret:
            self.hits += 1
        self.queries += 1
        return ret

    def update(self, value):
        __hash = list(self._hash(value))
        r = self._query(__hash)
        if r is False:
            self._add(__hash)
        del __hash
        return r

    def _read_file(self, filename):
        data = []
        fp = open(filename, 'rb')
        recvbuf = fp.read(self.size)
        while len(recvbuf) > 0:
            data += recvbuf
            recvbuf = fp.read(self.size)
        fp.close()
        del recvbuf
        del fp
        del self.size
        if is_python3:
            return bytes(data)
        else:
            return bytes("".join(data))

    def _decompress(self, data):  # a decompression function like lrzip in spirit: lzma<bz2<zlib<lz0<lz4
        try:
            data = lzma.decompress(data)
            sys.stderr.write("lzma ok\n")
        except:
            sys.stderr.write("lzma err\n")
            pass
        try:
            data = bz2.decompress(data)
            sys.stderr.write("bz2 ok\n")
        except:
            sys.stderr.write("bz2 err\n")
            pass
        try:
            data = zlib.decompress(data)
            sys.stderr.write("zlib ok\n")
        except:
            sys.stderr.write("zlib err\n")
            pass
        try:
            data = lzo.decompress(data)
            sys.stderr.write("lzo ok\n")
        except:
            sys.stderr.write("lzo err\n")
            pass
        try:
            data = lz4.block.decompress(data)
            sys.stderr.write("lz4 ok\n")
        except:
            sys.stderr.write("lz4 err\n")
            pass
        return data

    def load(self, filename=None):
        t0 = time.time()
        if filename is not None:
            fn = filename
        else:
            fn = self.filename
        sys.stderr.write("BLOOM: loading filter from file: %s\n" % fn)
        data = self._read_file(fn)
        ld = len(data)
        if ld > 0:
            data = self._decompress(data)
            self.header = data[0:10]
            try:
                sys.stderr.write("HEADER: %s\n" % self.header.encode('hex'))
            except:
                sys.stderr.write("HEADER: %s\n" % self.header.hex())

            if self.header[0:6] == b'BLOOM:':
                self.bf = bitarray.bitarray(endian='little')
                # self.hashed = self.hash_func(data[10:])
                self.bf.frombytes(data[10:])
                del data
                self.hashed = self.hash_func(self.bf.tobytes())
            else:
                sys.stderr.write("BLOOM: HEADER ERROR, FILTER IS NOT REALIABLE!!!\n")
                # self.bf = bytearray()
                self.bf = bitarray.bitarray(endian='little')
                # self.hashed = self.hash_func(data)
                self.bf.frombytes(data)
                del data
            self.bit_count = len(self.bf)
            self.bitset = 0
        else:
            return False

        # del data
        del fn
        t1 = time.time()
        sys.stderr.write(
            "BLOOM: Loaded: %d bytes, Inflated: %d bytes in: %d sec\n" % (ld, (self.bit_count / 8), (t1 - t0)))
        try:
            sys.stderr.write("BLOOM: hashed: %s %s\n" % (self.hashed.hexdigest()[:8], self.header[6:].encode('hex')))
        except:
            sys.stderr.write("BLOOM: hashed: %s %s\n" % (self.hashed.hexdigest()[:8], self.header[6:].hex()))
        del ld
        del t1
        del t0
        return True

    def _dump(self):
        sys.stderr.write("BLOOM: Dumping filter contents...\n")
        for i in range(0, len(self.bf) - 1, 64):
            sys.stderr.write(str(self.bf[i:i + 64]))

    @staticmethod
    def _write_file(data, filename):
        fp = open(filename, 'wb')

        for i in range(0, len(data) - 1, self.size):
            fp.write(data[i:i + self.size])
        fp.close()
        del fp
        del self.size

    @staticmethod
    def _bkp(filename, mv=False, re_flink=False):
        f1 = os.path.getsize(filename)
        f2 = os.path.getsize('%s.bkp' % filename)
        if f1 > f2:
            if mv:
                cmd = 'mv %s %s.bkp' % (filename, filename)
            else:
                if re_flink:
                    cmd = 'cp --re_flink=auto %s %s.bkp' % (filename, filename)
                else:
                    cmd = 'cp %s %s.bkp' % (filename, filename)
            os.system(cmd)
        del f2
        del f1
        del cmd

    @staticmethod
    def _compress(data):  # a compression function like lrzip in spirit: lz4>lz0>zlib>bz2>lzma
        sys.stderr.write("BLOOM: Compressing...\n")
        try:
            data = lz4.block.compress(data)  # will fail if filter > 1GB
            data = lzo.compress(data)  # will fail if filter > 1GB
            data = zlib.compress(data)
            data = bz2.compress(data)
            data = lzma.compress(data)
        except Exception as e:  # noqa
            sys.stderr.write("CompressError: %s\n" % e)
        return data

    def save(self, filename=None):
        if not self.saving:
            self.saving = True
            t0 = time.time()
            if filename is not None:
                fn = filename
            else:
                fn = self.filename
            sys.stderr.write("BLOOM: Saving filter to file: %s\n" % fn)

            try:
                if self.do_bkp:
                    self._bkp(fn)
            except Exception as e:  # noqa
                sys.stderr.write("BKPError: %s\n" % e)

            data = self.bf.tobytes()
            self.hashed = self.hash_func(data)
            self.header = b'BLOOM:' + bytes(self.hashed.digest()[0:4])
            # sys.stderr.write( len(self.header)
            data = self._compress(self.header + data)
            sys.stderr.write("BLOOM: Writing...\n")
            self._write_file(data, fn)
            lc = len(data)
            del data
            t1 = time.time()
            d = (t1 - t0)
            del t1
            del t0
            sys.stderr.write(
                "BLOOM: Saved %d MB in %d sec, hashed: %s\n" % (d, (lc // (1024 ** 2)), self.hashed.hexdigest()[0:8])
            )
            self.saving = False
            del lc
            return d

    def stats(self):
        if self.bitcalc:
            i = self.bf.buffer_info()
            sys.stderr.write(str(i))
            self.bitset = (i[1] - i[4])
            del i
            sys.stderr.write(
                "BLOOM: Bits set: %d of %d" % (self.bitset, self.bit_count) + " %3.8f" % (
                        (float(self.bitset) / self.bit_count) * 100) + "%\n"
            )
            sys.stderr.write(
                "BLOOM: Hits %d over queries: %d, hit_ratio: %3.8f" % (
                    self.hits, self.queries, (float(self.hits / self.queries) * 100)) + "%\n"
            )

    def info(self):
        sys.stderr.write(
            "BLOOM: filename: %si, do_hashes: %s, slices: %d, bits_per_slice: %d, fast: %s\n" % (
                self.filename, self.do_hashes, self.slices, self.slice_bits, self.fast)
        )
        self.calc_hashed()
        self.calc_entropy()
        self.stats()
