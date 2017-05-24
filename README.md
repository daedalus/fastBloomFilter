# Simple and fast pythonic bloomfilter

This filter supports: 

    Saving, reloading, compressed bloomfilter file lrzip like
        for compression: lz4>lzo>zlib>bz2>lzma
        for decompression: lzma>bz2>zlib>lzo>lz4
    Stats
    Entropy analysis
    Internal and external hashing of data.
    raw filter merging

Installing Dependencies:

    sudo pip install lz4 lzo bz2 zlib sha3 hashlib bitarray

External creating of the bloom filter file:

    python mkbloom.py /tmp/filter.blf

Importing:

    bf = BloomFilter(filename='/tmp/filter.blf')

Adding data to it:

    bf.add('30000')
    bf.add('1230213')
    bf.add('1')
    
Adding data and at the same time querying it:

    print bf.update('1') # True
    print bf.update('1') # True
    
    print bf.update('2') # False
    print bf.update('2') # True

Printing stats:

    bf.stat()
    
Or:
    
    bf.info()

Querying data:

    print bf.query('1') # True
    print bf.query('1230213') # True
    print bf.query('12') # False
