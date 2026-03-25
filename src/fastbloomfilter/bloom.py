#!/usr/bin/env python
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

from __future__ import annotations

import binascii
import hashlib
import math
import mmap
import os
import sys
from typing import IO, TYPE_CHECKING, Any, TypeVar

import bitarray

from fastbloomfilter.lib.pickling import compress_pickle, decompress_pickle

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable

tqdm: Any = None
try:
    from tqdm import tqdm as _tqdm

    tqdm = _tqdm
except ImportError:
    pass

T = TypeVar("T")


def blake2b512(s: str) -> hashlib._Hash:
    h = hashlib.new("blake2b512")
    h.update(s.encode("utf8"))
    return h


def sha3(s: str) -> hashlib._Hash:
    h = hashlib.sha3_256()
    h.update(s.encode("utf8"))
    return h


def sha256(s: str) -> hashlib._Hash:
    h = hashlib.sha256()
    h.update(s.encode("utf8"))
    return h


def shannon_entropy(data: bytes, iterator: list[int] | None = None) -> float:
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0.0
    entropy = 0.0
    if iterator is None:
        iterator = list(range(0, 255))
    for x in iterator:
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)
    return entropy


class MemoryMappedBitArray:
    """
    A memory-mapped implementation of a bit array.
    Uses disk instead of RAM for large filters.
    """

    def __init__(
        self, size_in_bits: int, filepath: str | None = None, create_new: bool = True
    ) -> None:
        self.size_in_bits = size_in_bits
        self.size_in_bytes = (size_in_bits + 7) // 8

        self.temp_file = False
        self.file_obj: IO[bytes] | None = None
        if filepath is None:
            import tempfile

            self.temp_file = True
            self.file_obj = tempfile.NamedTemporaryFile(delete=False)
            self.filepath = self.file_obj.name
        else:
            self.filepath = filepath

        if create_new or not os.path.exists(self.filepath):
            with open(self.filepath, "wb") as f:
                f.write(b"\x00" * self.size_in_bytes)

        self.file_obj = open(self.filepath, "r+b")
        self.mmap: mmap.mmap = mmap.mmap(self.file_obj.fileno(), self.size_in_bytes)

        sys.stderr.write(
            f"BLOOM: Created memory-mapped bit array of {self.size_in_bytes / (1024**2):.2f} MB at {self.filepath}\n"
        )

    def __getitem__(self, index: int) -> bool:
        if index >= self.size_in_bits:
            raise IndexError("Bit index out of range")

        byte_index = index // 8
        bit_offset = index % 8
        return bool((self.mmap[byte_index] >> bit_offset) & 1)

    def __setitem__(self, index: int, value: bool) -> None:
        if index >= self.size_in_bits:
            raise IndexError("Bit index out of range")

        byte_index = index // 8
        bit_offset = index % 8

        current_byte = self.mmap[byte_index]

        if value:
            new_byte = current_byte | (1 << bit_offset)
        else:
            new_byte = current_byte & ~(1 << bit_offset)

        self.mmap[byte_index] = new_byte

    def __len__(self) -> int:
        return self.size_in_bits

    def tobytes(self) -> bytes:
        self.mmap.flush()
        return self.mmap[:]

    def setall(self, value: bool) -> None:
        fill_byte = 0xFF if value else 0x00
        self.mmap[:] = bytes([fill_byte] * self.size_in_bytes)

    def frombytes(self, byte_data: bytes) -> None:
        if len(byte_data) != self.size_in_bytes:
            raise ValueError(
                f"Data size mismatch: {len(byte_data)} bytes provided, {self.size_in_bytes} bytes required"
            )
        self.mmap[:] = byte_data

    def close(self) -> None:
        if hasattr(self, "mmap") and self.mmap is not None:
            self.mmap.flush()
            self.mmap.close()
            self.mmap = None  # type: ignore[assignment]

        if hasattr(self, "file_obj") and self.file_obj is not None:
            self.file_obj.close()
            self.file_obj = None

        if self.temp_file and os.path.exists(self.filepath):
            try:
                os.unlink(self.filepath)
            except Exception:
                pass

    def __del__(self) -> None:
        self.close()


class BloomFilter:
    bfilter: MemoryMappedBitArray | bitarray.bitarray
    hashfunc: Any

    def __init__(
        self,
        array_size: int = ((1024**2) * 128),
        slices: int = 10,
        slice_bits: int = 256,
        do_hashing: bool = True,
        filename: str | None = None,
        fast: bool = False,
        data_is_hex: bool = False,
        use_mmap: bool = False,
        mmap_file: str | None = None,
        memory_threshold: int = (1024**2) * 64,
    ) -> None:
        self.saving = False
        self.loading = False
        self.bitcalc = False
        self.merging = False
        self.fast = fast
        self.data_is_hex = data_is_hex
        self.header = "BLOOM:\0\0\0\0"
        self.use_mmap = use_mmap or (array_size > memory_threshold)
        self.mmap_file = mmap_file

        self.slices = slices
        self.slice_bits = slice_bits
        self.bitset = 0
        self.do_hashes = do_hashing
        self.hits = 0
        self.queryes = 0
        try:
            self.hashfunc = blake2b512
        except Exception:
            self.hashfunc = sha3

        self.filename = filename
        if filename is not None and self.load() is True:
            sys.stderr.write("BLOOM: Loaded OK\n")
        else:
            if self.use_mmap:
                self.bfilter = MemoryMappedBitArray(
                    array_size * 8, filepath=self.mmap_file
                )
                self.bfilter.setall(False)
            else:
                self.bfilter = bitarray.bitarray(array_size * 8, endian="little")
                self.bfilter.setall(False)

            self.bitcount = array_size * 8

        memory_type = "Memory-mapped" if self.use_mmap else "In-memory"
        sys.stderr.write(
            f"BLOOM: filename: {self.filename}, do_hashes: {self.do_hashes}, slices: {self.slices}, "
            f"bits_per_hash: {self.slice_bits}, func:{str(self.hashfunc).split(' ')[1]}, "
            f"size:{(self.bitcount // 8) / (1024**2):.2f}MB, type: {memory_type}\n"
        )

    def len(self) -> int:
        return len(self.bfilter)

    def calc_capacity(self, error_rate: float, capacity: int) -> int:
        hashes = int(math.ceil(math.log(1.0 / error_rate, 2)))
        bits_per_hash = int(
            math.ceil(
                (capacity * abs(math.log(error_rate)))
                / (self.slices * (math.log(2) ** 2))
            )
        )
        bitcount = bits_per_hash * hashes
        sys.stderr.write(
            f"Hashes: {self.slices}, bit_per_hash: {self.slice_bits} bitcount: {bitcount}\n"
        )
        return bitcount

    def calc_entropy(self) -> float:
        self.entropy = shannon_entropy(self.bfilter.tobytes())
        sys.stderr.write(f"Entropy: {self.entropy:1.8f}\n")
        return self.entropy

    def calc_hashid(self) -> str:
        data = self.bfilter.tobytes()
        self.hashid = self.hashfunc(str(data))
        del data
        hex_digest: str = self.hashid.hexdigest()[:8]
        result = f"BLOOM: HASHID: {hex_digest}\n"
        sys.stderr.write(result)
        return hex_digest

    def _raw_merge(self, other: BloomFilter) -> None:
        if self.merging is False:
            self.merging = True
            sys.stderr.write("BLOOM: Merging...\n")
            if len(other.bfilter) == len(self.bfilter):
                a = bytearray(self.bfilter.tobytes())
                b = bytearray(other.bfilter.tobytes())
                if tqdm is not None:
                    iterator = tqdm(range(0, len(a)))
                else:
                    iterator = range(0, len(a))
                for i in iterator:
                    a[i] |= b[i]

                if self.use_mmap:
                    self.bfilter.frombytes(bytes(a))
                else:
                    bfilternew = bitarray.bitarray(endian="little")
                    bfilternew.frombytes(bytes(a))
                    self.bfilter = bfilternew

                del a, b
                sys.stderr.write("BLOOM: Merged Ok\n")
            else:
                sys.stderr.write(
                    f"BLOOM: filters are not conformable: {len(self.bfilter)} - {len(other.bfilter)}\n"
                )
            self.merging = False

    def __add__(self, other_filter: BloomFilter) -> BloomFilter:
        self._raw_merge(other_filter)
        return self

    def _hash(self, value: str) -> Generator[int, None, None]:
        if self.do_hashes:
            digest = int.from_bytes(self.hashfunc(value).digest(), "big")
        elif self.data_is_hex:
            digest = int(value, 16)
        else:
            try:
                digest = int(binascii.hexlify(value.encode("utf8")), 16)
            except Exception:
                digest = int(binascii.hexlify(value.encode()), 16)
        if self.fast:
            yield digest % self.bitcount
        else:
            for _ in range(0, self.slices):
                yield digest & (self.bitcount - 1)
                digest >>= int(self.slice_bits / self.slices)

    def add(self, value: str) -> None:
        if not self.saving and not self.loading and not self.merging:
            hash_gen = self._hash(value)
            self._add(hash_gen)

    def _add(self, hash_iter: Iterable[int]) -> None:
        for digest in hash_iter:
            self.bfilter[digest] = True
        self.bitset += 1 if self.fast else self.slices

    def query(self, value: str) -> bool:
        hash_gen = self._hash(value)
        return self._query(hash_gen)

    def _query(self, hash_iter: Iterable[int]) -> bool:
        ret = all(self.bfilter[digest] for digest in hash_iter)
        if ret:
            self.hits += 1
        self.queryes += 1
        return ret

    def __getitem__(self, value: str) -> bool:
        return self.query(value)

    def update(self, value: str) -> bool:
        if not self.saving and not self.loading and not self.merging:
            hash_list = list(self._hash(value))
            r = self._query(iter(hash_list))
            if r is False:
                self._add(iter(hash_list))
            return r
        return False

    def load(self, filename: str | None = None) -> bool:
        if not self.loading:
            self.loading = True
            if filename is not None:
                self.filename = filename

            try:
                assert self.filename is not None
                loaded_filter: Any = decompress_pickle(self.filename)
                self.do_hashes = loaded_filter.do_hashes
                self.data_is_hex = loaded_filter.data_is_hex
                self.slices = loaded_filter.slices
                self.slice_bits = loaded_filter.slice_bits
                self.hashfunc = loaded_filter.hashfunc
                self.bitcount = loaded_filter.bitcount
                self.bitset = loaded_filter.bitset
                self.fast = loaded_filter.fast

                if hasattr(loaded_filter, "use_mmap"):
                    self.use_mmap = loaded_filter.use_mmap

                if self.use_mmap:
                    self.bfilter = MemoryMappedBitArray(
                        self.bitcount, filepath=self.mmap_file
                    )
                    self.bfilter.frombytes(loaded_filter.bfilter.tobytes())
                else:
                    self.bfilter = loaded_filter.bfilter

                self.loading = False
                return True
            except Exception as e:
                sys.stderr.write(f"BLOOM: Error loading filter: {str(e)}\n")
                self.loading = False
                return False
        return False

    def save(self, filename: str | None = None) -> bool:
        if self.saving:
            return False

        if filename is None and self.filename is None:
            sys.stderr.write("A Filename must be provided\n")
            return False

        self.saving = True
        if filename is not None:
            self.filename = filename

        try:
            if (
                self.use_mmap
                and hasattr(self.bfilter, "mmap")
                and self.bfilter.mmap is not None
            ):
                self.bfilter.mmap.flush()

            assert self.filename is not None
            compress_pickle(self.filename, self)
            self.saving = False
            return True
        except Exception as e:
            sys.stderr.write(f"BLOOM: Error saving filter: {str(e)}\n")
            self.saving = False
            return False

    def stat(self) -> None:
        if self.bitcalc:
            sys.stderr.write(
                f"BLOOM: Bits set: {self.bitset} of {self.bitcount}"
                f" {(float(self.bitset) / self.bitcount) * 100:3.8f}%\n"
            )
            sys.stderr.write(
                f"BLOOM: Hits {self.hits} over Querys: {self.queryes}, "
                f"hit_ratio: {(float(self.hits / self.queryes) * 100) if self.queryes > 0 else 0:3.8f}%\n"
            )
        bytes_ = (self.bitcount - self.bitset) / 8.0
        mfree = bytes_ / (1024**2)
        sys.stderr.write(f"BLOOM: Free: {int(mfree)} Megs\n")

    def info(self) -> None:
        memory_type = "Memory-mapped" if self.use_mmap else "In-memory"
        sys.stderr.write(
            f"BLOOM: filename: {self.filename}, do_hashes: {self.do_hashes}, slices: {self.slices}, "
            f"bits_per_slice: {self.slice_bits}, fast: {self.fast}, type: {memory_type}\n"
        )
        self.calc_hashid()
        self.calc_entropy()
        self.stat()

    def close(self) -> None:
        if hasattr(self, "bfilter") and hasattr(self.bfilter, "close"):
            self.bfilter.close()

    def __del__(self) -> None:
        self.close()
