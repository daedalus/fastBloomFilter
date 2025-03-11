#!/usr/bin/env python
# based on https://gist.github.com/josephkern/2897618
# Enhanced with memory mapping for better memory management
"""
A Bloom Filter implementation with memory mapping support
Calculating optimal filter size:
            Where:
            m is: self.bitcount (how many bits in self.filter)
            n is: the number of expected values added to self.filter
            k is: the number of hashes being produced
            (1 - math.exp(-float(k * n) / m)) ** k
http://en.wikipedia.org/wiki/Bloom_filter
"""
# Original Author Dario Clavijo 2017, Memory mapping enhancements added 2025
# GPLv3

import sys
import os
import mmap
import hashlib
import math
import time
import bitarray
import binascii
from tqdm import tqdm
from fastBloomFilter.lib.pickling import *

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
        str_i += f"{str(i)} "
    sys.stderr.write(str_i)

class MemoryMappedBitArray:
    """
    A memory-mapped implementation of a bit array.
    Uses disk instead of RAM for large filters.
    """
    def __init__(self, size_in_bits, filepath=None, create_new=True):
        """
        Initialize a memory-mapped bit array
        
        Args:
            size_in_bits (int): Size of the bit array in bits
            filepath (str): Path to the file to map, if None a temp file is created
            create_new (bool): Whether to create a new file or use existing
        """
        self.size_in_bits = size_in_bits
        self.size_in_bytes = (size_in_bits + 7) // 8  # Round up to nearest byte
        
        # Create a temporary file if filepath not provided
        self.temp_file = False
        if filepath is None:
            import tempfile
            self.temp_file = True
            self.file_obj = tempfile.NamedTemporaryFile(delete=False)
            self.filepath = self.file_obj.name
        else:
            self.filepath = filepath
            
        # Create or open the file
        if create_new or not os.path.exists(self.filepath):
            with open(self.filepath, 'wb') as f:
                f.write(b'\x00' * self.size_in_bytes)
        
        # Open the file for memory mapping
        self.file_obj = open(self.filepath, 'r+b')
        self.mmap = mmap.mmap(self.file_obj.fileno(), self.size_in_bytes)
        
        sys.stderr.write(f"BLOOM: Created memory-mapped bit array of {self.size_in_bytes / (1024**2):.2f} MB at {self.filepath}\n")
    
    def __getitem__(self, index):
        """Get the bit at the specified index"""
        if index >= self.size_in_bits:
            raise IndexError("Bit index out of range")
            
        byte_index = index // 8
        bit_offset = index % 8
        return bool((self.mmap[byte_index] >> bit_offset) & 1)
    
    def __setitem__(self, index, value):
        """Set the bit at the specified index"""
        if index >= self.size_in_bits:
            raise IndexError("Bit index out of range")
            
        byte_index = index // 8
        bit_offset = index % 8
        
        # Read the current byte
        current_byte = self.mmap[byte_index]
        
        if value:
            # Set the bit
            new_byte = current_byte | (1 << bit_offset)
        else:
            # Clear the bit
            new_byte = current_byte & ~(1 << bit_offset)
            
        # Write the new byte
        self.mmap[byte_index] = new_byte
    
    def __len__(self):
        """Return the size of the bit array in bits"""
        return self.size_in_bits
    
    def tobytes(self):
        """Return a copy of the underlying bytes"""
        self.mmap.flush()  # Ensure all changes are written to disk
        return self.mmap[:]
    
    def setall(self, value):
        """Set all bits to the given value"""
        fill_byte = 0xFF if value else 0x00
        self.mmap[:] = bytes([fill_byte] * self.size_in_bytes)
    
    def frombytes(self, byte_data):
        """Load from bytes"""
        if len(byte_data) != self.size_in_bytes:
            raise ValueError(f"Data size mismatch: {len(byte_data)} bytes provided, {self.size_in_bytes} bytes required")
        self.mmap[:] = byte_data
    
    def close(self):
        """Close the memory-mapped file"""
        if hasattr(self, 'mmap') and self.mmap is not None:
            self.mmap.flush()
            self.mmap.close()
            self.mmap = None
            
        if hasattr(self, 'file_obj') and self.file_obj is not None:
            self.file_obj.close()
            self.file_obj = None
            
        # Delete the temporary file if it was created
        if self.temp_file and os.path.exists(self.filepath):
            try:
                os.unlink(self.filepath)
            except:
                pass
                
    def __del__(self):
        """Destructor to ensure resources are released"""
        self.close()

class BloomFilter(object):
    def __init__(
        self,
        array_size=((1024 ** 2) * 128),
        slices=10,
        slice_bits=256,
        do_hashing=True,
        filename=None,
        fast=False,
        data_is_hex=False,
        use_mmap=False,
        mmap_file=None,
        memory_threshold=(1024 ** 2) * 64  # 64MB threshold for auto memory mapping
    ):
        """
        Initializes a BloomFilter() object:
        Expects:
            array_size (in bytes): 4 * 1024 for a 4KB filter
            hashes (int): for the number of hashes to perform
            use_mmap (bool): Whether to use memory mapping (for large filters)
            mmap_file (str): Path to the file to use for memory mapping
            memory_threshold (int): Size threshold beyond which to auto-use memory mapping
        """

        self.saving = False
        self.loading = False
        self.bitcalc = False
        self.merging = False
        self.fast = fast
        self.data_is_hex = data_is_hex  # ignored when do_hashes = True
        self.header = "BLOOM:\0\0\0\0"
        self.use_mmap = use_mmap or (array_size > memory_threshold)
        self.mmap_file = mmap_file

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
            # Initialize the filter based on memory mapping preference
            if self.use_mmap:
                self.bfilter = MemoryMappedBitArray(array_size * 8, filepath=self.mmap_file)
                self.bfilter.setall(0)
            else:
                self.bfilter = bitarray.bitarray(array_size * 8, endian="little")
                self.bfilter.setall(0)
                
            self.bitcount = array_size * 8  # Bits in the filter

        memory_type = "Memory-mapped" if self.use_mmap else "In-memory"
        sys.stderr.write(
            f"BLOOM: filename: {self.filename}, do_hashes: {self.do_hashes}, slices: {self.slices}, "
            f"bits_per_hash: {self.slice_bits}, func:{str(self.hashfunc).split(' ')[1]}, "
            f"size:{(self.bitcount // 8) / (1024**2):.2f}MB, type: {memory_type}\n"
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
            % (self.slices, self.slice_bits, bitcount)
        )
        return bitcount

    def calc_entropy(self):
        self.entropy = shannon_entropy(self.bfilter.tobytes())
        sys.stderr.write("Entropy: %1.8f\n" % self.entropy)

    def calc_hashid(self):
        data = self.bfilter.tobytes()
        self.hashid = self.hashfunc(data)
        del data
        sys.stderr.write("BLOOM: HASHID: %s\n" % self.hashid.hexdigest()[:8])

    def _raw_merge(self, bfilter):
        """
        Merges two conforming in size binary filters.
        """
        if self.merging == False:
            self.merging = True
            sys.stderr.write("BLOOM: Merging...\n")
            if len(bfilter) == len(self.bfilter):
                A = bytearray(self.bfilter.tobytes())
                B = bytearray(bfilter.tobytes())
                for i in tqdm(range(0, len(A))):
                    A[i] |= B[i]
                
                # Create appropriate filter based on memory mapping preference
                if self.use_mmap:
                    # For memory-mapped filters, we update in place
                    self.bfilter.frombytes(bytes(A))
                else:
                    bfilternew = bitarray.bitarray()
                    bfilternew.frombytes(bytes(A))
                    self.bfilter = bfilternew 
                    
                del A, B
                sys.stderr.write("BLOOM: Merged Ok\n")
            else:
                sys.stderr.write("BLOOM: filters are not conformable: %d - %d\n" % (len(self.bfilter), len(bfilter)))
            self.merging = False

    def __add__(self, otherFilter):
        self._raw_merge(otherFilter.bfilter)
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
        elif self.data_is_hex:
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
                # Shift bits in digest to the right, based on slice_bits
                # divided by the number of hashes needed be produced.
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
            # Set the bit at the digest position to True
            self.bfilter[digest] = True

            # The purpose here is to spread out the hashes to create a unique
            # hash with unique locations in the filter array,
            # rather than just a big long hash blob.
        self.bitset += 1 if self.fast else self.slices

    def query(self, value):
        """
        Bitwise AND to query values in self.filter
        Expects:
            value: value to check filter against (assumed int())
        """
        # If all() hashes return True from a bitwise AND for each digest 
        # returned from self._hash, return True, else False
        __hash = self._hash(value)
        return self._query(__hash)

    def _query(self, __hash):
        # global bfilter
        ret = all(self.bfilter[digest] for digest in __hash)
        if ret:
            self.hits += 1
        self.queryes += 1
        return ret

    def __getitem__(self, value):
        return self.query(value)

    def update(self, value):
        """ 
        This function first queries the filter for a value then adds it.
        Very useful for caches, where we want to know if an element was already seen.
        update(value)= already_seen(value)
        """
        if not self.saving and not self.loading and not self.merging:
            __hash = [*(self._hash(value))]
            r = self._query(__hash)
            if r == False:
                self._add(__hash)
            del __hash
            return r
 
    def load(self, filename=None):
        if not self.loading:
            self.loading = True
            if filename is not None:
                self.filename = filename
                
            try:
                BF = decompress_pickle(self.filename)
                self.do_hashes = BF.do_hashes 
                self.data_is_hex = BF.data_is_hex
                self.slices = BF.slices
                self.slice_bits = BF.slice_bits
                self.hashfunc = BF.hashfunc
                self.bitcount = BF.bitcount
                self.bitset = BF.bitset
                self.fast = BF.fast
                
                # Handle memory-mapped attribute if present in saved filter
                if hasattr(BF, 'use_mmap'):
                    self.use_mmap = BF.use_mmap
                
                # Create appropriate filter based on memory mapping preference
                if self.use_mmap:
                    # For memory-mapped filters, we create a new one and copy the data
                    self.bfilter = MemoryMappedBitArray(self.bitcount, filepath=self.mmap_file)
                    self.bfilter.frombytes(BF.bfilter.tobytes())
                else:
                    # For in-memory filters, just use the loaded one
                    self.bfilter = BF.bfilter
                
                self.loading = False
                return True
            except Exception as e:
                sys.stderr.write(f"BLOOM: Error loading filter: {str(e)}\n")
                self.loading = False
                return False

    def save(self, filename=None):
        if self.saving:
            return False
            
        if filename is None and self.filename is None:
            sys.stderr.write("A Filename must be provided\n")
            return False
            
        self.saving = True
        if filename is not None:
            self.filename = filename
            
        try:
            # Ensure any memory-mapped changes are flushed to disk
            if self.use_mmap and hasattr(self.bfilter, 'mmap') and self.bfilter.mmap is not None:
                self.bfilter.mmap.flush()
                
            compress_pickle(self.filename, self)
            self.saving = False
            return True
        except Exception as e:
            sys.stderr.write(f"BLOOM: Error saving filter: {str(e)}\n")
            self.saving = False
            return False

    def stat(self):
        if self.bitcalc:
            sys.stderr.write(
                "BLOOM: Bits set: %d of %d" % (self.bitset, self.bitcount)
                + " %3.8f" % ((float(self.bitset) / self.bitcount) * 100)
                + "%\n"
            )
            sys.stderr.write(
                "BLOOM: Hits %d over Querys: %d, hit_ratio: %3.8f"
                % (self.hits, self.queryes, (float(self.hits / self.queryes) * 100) if self.queryes > 0 else 0)
                + "%\n"
            )
        bytes_ = (self.bitcount - self.bitset) / 8.0
        Mfree = bytes_ / (1024 ** 2)
        sys.stderr.write("BLOOM: Free: %d Megs\n" % Mfree)

    def info(self):
        memory_type = "Memory-mapped" if self.use_mmap else "In-memory"
        sys.stderr.write(
            f"BLOOM: filename: {self.filename}, do_hashes: {self.do_hashes}, slices: {self.slices}, "
            f"bits_per_slice: {self.slice_bits}, fast: {self.fast}, type: {memory_type}\n"
        )
        self.calc_hashid()
        self.calc_entropy()
        self.stat()
        
    def close(self):
        """
        Release resources explicitly
        """
        if hasattr(self, 'bfilter') and hasattr(self.bfilter, 'close'):
            self.bfilter.close()
            
    def __del__(self):
        """
        Ensure resources are released when the object is garbage collected
        """
        self.close()

# Example usage with memory mapping
if __name__ == "__main__":
    # Create a large bloom filter using memory mapping
    bf = BloomFilter(
        array_size=(1024 ** 2) * 256,  # 256MB filter
        use_mmap=True,
        mmap_file="/tmp/large_bloom_filter.dat"
    )
    
    # Add some elements
    for i in range(1000):
        bf.add(f"test_element_{i}")
    
    # Query elements
    for i in range(2000):
        result = bf.query(f"test_element_{i}")
        if i < 1000:
            assert result, f"False negative for element {i}"
        # Note: we can't assert for elements >= 1000 because of potential false positives
    
    # Save the filter
    bf.save()
    
    # Close resources
    bf.close()
    
    # Load the filter back
    bf2 = BloomFilter(filename="/tmp/large_bloom_filter.dat")
    
    # Verify it works
    for i in range(1000):
        assert bf2.query(f"test_element_{i}"), f"Failed to load correctly for element {i}"
