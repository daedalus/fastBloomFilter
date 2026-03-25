import _pickle
import bz2
import sys


def compress_pickle(filename: str, data: object) -> None:
    sys.stderr.write(f"loading pickle {filename}...\n")
    with bz2.BZ2File(filename, "w") as f:
        _pickle.dump(data, f)


def decompress_pickle(filename: str) -> object:
    sys.stderr.write(f"saving pickle {filename}...\n")
    data = bz2.BZ2File(filename, "rb")
    data = _pickle.load(data)
    return data
