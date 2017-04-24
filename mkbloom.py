import zlib
import bz2
import lz4
import brotli
b = bytearray((1024**3)*5)

print bz2.compress(zlib.compress(str(b).encode('zlib'),9),9)
