import sys
import zlib
import bz2
import lz4
import brotli
import hashlib

import bloom

bf = bloom.BloomFilter(array_size=(1024**3)*5,do_bkp=False, bitshuffle=True)
bf.filename = sys.argv[1]
bf.save()

