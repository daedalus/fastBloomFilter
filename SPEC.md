# SPEC.md — fastBloomFilter

## Purpose

A fast and memory-efficient Bloom Filter implementation in Python with support for memory mapping, compression, saving/loading, merging, and entropy analysis.

## Scope

### In Scope
- Bloom filter creation with configurable size, hash functions, and slice parameters
- Memory-mapped bit array for large filters (avoids loading entire filter into RAM)
- Add, query, and update operations
- Save/load filters with bz2 compression using pickle
- Merge two conforming filters
- Statistics: bit usage, hit ratio, entropy, hash ID
- Multiple hash functions: blake2b512, sha3_256, sha256
- Fast mode (single hash) and accurate mode (multiple slices)
- CLI entry point via `python -m fastbloomfilter`

### Not In Scope
- Counting bloom filters (element removal)
- Scalable bloom filters
- Distributed/clustered filters
- Redis or other external storage backends

## Public API / Interface

### `BloomFilter` class

```python
class BloomFilter:
    def __init__(
        self,
        array_size: int = ((1024 ** 2) * 128),
        slices: int = 10,
        slice_bits: int = 256,
        do_hashing: bool = True,
        filename: str | None = None,
        fast: bool = False,
        data_is_hex: bool = False,
        use_mmap: bool = False,
        mmap_file: str | None = None,
        memory_threshold: int = (1024 ** 2) * 64
    ) -> None: ...
```

**Parameters:**
- `array_size`: Size of filter in bytes (default: 128MB)
- `slices`: Number of hash functions to use
- `slice_bits`: Bits per hash slice
- `do_hashing`: Whether to hash input values
- `filename`: Path to load/save filter
- `fast`: Use single hash mode (faster, less accurate)
- `data_is_hex`: Input data is hexadecimal
- `use_mmap`: Force memory mapping
- `mmap_file`: Path for memory-mapped file
- `memory_threshold`: Auto-enable mmap above this size

**Methods:**
- `add(value: str) -> None`: Add a value to the filter
- `query(value: str) -> bool`: Check if value might be in filter
- `update(value: str) -> bool`: Query and add if not present; returns True if already existed
- `save(filename: str | None = None) -> bool`: Save filter to compressed pickle
- `load(filename: str | None = None) -> bool`: Load filter from file
- `stat() -> None`: Print usage statistics
- `info() -> None`: Print full filter info
- `calc_capacity(error_rate: float, capacity: int) -> int`: Calculate required bit count
- `calc_entropy() -> float`: Calculate and print Shannon entropy
- `calc_hashid() -> str`: Calculate filter hash ID
- `close() -> None`: Release resources

**Magic Methods:**
- `__getitem__(value: str) -> bool`: Alias for query
- `__add__(other: BloomFilter) -> BloomFilter`: Merge two filters

### Module Functions

```python
def blake2b512(s: str) -> hashlib.HASH: ...
def sha3(s: str) -> hashlib.HASH: ...
def sha256(s: str) -> hashlib.HASH: ...
def shannon_entropy(data: bytes, iterator: Iterable | None = None) -> float: ...
```

## Data Formats

- **Filter Storage**: bz2-compressed pickle (.bz2)
- **Input Values**: UTF-8 encoded strings
- **Hash Output**: Hexadecimal digest strings

## Edge Cases

1. Empty filter creation (array_size=0) - should work but with warning
2. Querying non-existent element - returns False (no false negatives)
3. Adding duplicate values - silently succeeds, bits already set
4. Loading corrupted file - returns False, prints error to stderr
5. Memory-mapped file on read-only filesystem - raises exception
6. Merging non-conforming filters (different sizes) - prints error, no merge
7. Very large filters (GB+) - uses memory mapping automatically
8. Fast mode vs accurate mode trade-offs

## Performance & Constraints

- Target: Python 3.11+
- Memory: Auto-switches to memory mapping above 64MB threshold
- Hash functions: blake2b512 preferred, falls back to sha3_256
- Dependencies: bitarray, tqdm (for merge progress)
