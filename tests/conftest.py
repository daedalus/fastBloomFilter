import os
import tempfile
from collections.abc import Generator

import pytest

from fastbloomfilter.bloom import BloomFilter


@pytest.fixture
def small_filter() -> Generator[BloomFilter, None, None]:
    bf = BloomFilter(array_size=1024 * 128, slices=10)
    yield bf
    bf.close()


@pytest.fixture
def temp_filter_file() -> Generator[str, None, None]:
    fd, path = tempfile.mkstemp(suffix=".blf")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def populated_filter(small_filter: BloomFilter) -> BloomFilter:
    for i in range(100):
        small_filter.add(f"test_element_{i}")
    return small_filter
