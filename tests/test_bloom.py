import random

from fastbloomfilter.bloom import (
    BloomFilter,
    blake2b512,
    sha3,
    sha256,
    shannon_entropy,
)


class TestHashFunctions:
    def test_blake2b512_returns_hash(self) -> None:
        result = blake2b512("test")
        assert result is not None
        assert len(result.hexdigest()) == 128

    def test_sha3_returns_hash(self) -> None:
        result = sha3("test")
        assert result is not None
        assert len(result.hexdigest()) == 64

    def test_sha256_returns_hash(self) -> None:
        result = sha256("test")
        assert result is not None
        assert len(result.hexdigest()) == 64


class TestShannonEntropy:
    def test_entropy_empty_data(self) -> None:
        assert shannon_entropy(b"") == 0

    def test_entropy_uniform_data(self) -> None:
        data = b"A" * 100
        entropy = shannon_entropy(data)
        assert entropy == 0.0

    def test_entropy_random_data(self) -> None:
        data = bytes([random.randint(0, 255) for _ in range(1000)])
        entropy = shannon_entropy(data)
        assert entropy > 0


class TestBloomFilterCreation:
    def test_create_default_filter(self) -> None:
        bf = BloomFilter(array_size=1024 * 128)
        assert bf.slices == 10
        assert bf.slice_bits == 256
        assert bf.do_hashes is True
        bf.close()

    def test_create_small_filter(self) -> None:
        bf = BloomFilter(array_size=1024)
        assert bf.bitcount == 1024 * 8
        bf.close()

    def test_create_fast_filter(self) -> None:
        bf = BloomFilter(array_size=1024 * 128, fast=True)
        assert bf.fast is True
        bf.close()

    def test_create_with_custom_slices(self) -> None:
        bf = BloomFilter(array_size=1024 * 128, slices=5)
        assert bf.slices == 5
        bf.close()


class TestBloomFilterAdd:
    def test_add_single_element(self, small_filter: BloomFilter) -> None:
        small_filter.add("test_value")
        assert small_filter.query("test_value") is True

    def test_add_multiple_elements(self, small_filter: BloomFilter) -> None:
        for i in range(10):
            small_filter.add(f"element_{i}")
        for i in range(10):
            assert small_filter.query(f"element_{i}") is True

    def test_add_duplicate(self, small_filter: BloomFilter) -> None:
        small_filter.add("test")
        small_filter.add("test")
        assert small_filter.query("test") is True


class TestBloomFilterQuery:
    def test_query_existing_element(self, populated_filter: BloomFilter) -> None:
        assert populated_filter.query("test_element_0") is True

    def test_query_nonexistent_element(self, populated_filter: BloomFilter) -> None:
        assert populated_filter.query("nonexistent") is False

    def test_query_with_getitem_syntax(self, populated_filter: BloomFilter) -> None:
        assert populated_filter["test_element_0"] is True
        assert populated_filter["nonexistent"] is False


class TestBloomFilterUpdate:
    def test_update_new_element(self, small_filter: BloomFilter) -> None:
        result = small_filter.update("new_element")
        assert result is False
        assert small_filter.query("new_element") is True

    def test_update_existing_element(self, populated_filter: BloomFilter) -> None:
        result = populated_filter.update("test_element_0")
        assert result is True


class TestBloomFilterSaveLoad:
    def test_save_and_load(
        self, populated_filter: BloomFilter, temp_filter_file: str
    ) -> None:
        populated_filter.save(temp_filter_file)
        bf2 = BloomFilter(filename=temp_filter_file)
        assert bf2.query("test_element_0") is True
        assert bf2.query("test_element_50") is True
        bf2.close()

    def test_load_nonexistent_file(self) -> None:
        bf = BloomFilter(filename="/nonexistent/file.blf")
        assert bf.filename == "/nonexistent/file.blf"


class TestBloomFilterMerge:
    def test_merge_conforming_filters(self) -> None:
        bf1 = BloomFilter(array_size=1024 * 128, slices=10)
        bf2 = BloomFilter(array_size=1024 * 128, slices=10)
        bf1.add("element_a")
        bf2.add("element_b")
        bf3 = bf1 + bf2
        assert bf3.query("element_a") is True
        assert bf3.query("element_b") is True
        bf1.close()
        bf2.close()
        bf3.close()


class TestBloomFilterStats:
    def test_calc_capacity(self, small_filter: BloomFilter) -> None:
        bitcount = small_filter.calc_capacity(0.01, 1000)
        assert bitcount > 0

    def test_calc_entropy(self, small_filter: BloomFilter) -> None:
        small_filter.add("test")
        entropy = small_filter.calc_entropy()
        assert entropy >= 0

    def test_calc_hashid(self, small_filter: BloomFilter) -> None:
        hashid = small_filter.calc_hashid()
        assert hashid is not None


class TestBloomFilterEdgeCases:
    def test_empty_filter_query(self, small_filter: BloomFilter) -> None:
        assert small_filter.query("anything") is False

    def test_large_number_of_elements(self) -> None:
        bf = BloomFilter(array_size=1024 * 1024)
        for i in range(10000):
            bf.add(f"element_{i}")
        for i in range(10000):
            assert bf.query(f"element_{i}") is True
        bf.close()

    def test_unicode_strings(self, small_filter: BloomFilter) -> None:
        small_filter.add("hello")
        small_filter.add("你好")
        small_filter.add("🎉")
        assert small_filter.query("hello") is True
        assert small_filter.query("你好") is True
        assert small_filter.query("🎉") is True

    def test_special_characters(self, small_filter: BloomFilter) -> None:
        special_chars = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
        for char in special_chars:
            small_filter.add(char)
        for char in special_chars:
            assert small_filter.query(char) is True
