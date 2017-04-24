# pythonic bloomfilter

This filter supports: 

    Saving, reloading, compressed bloomfilter file
    Stats
    Entropy analysis
    Internal and external hashing of data.

Installing Dependencies:

    sudo pip install lz4 lzo bz2 zlib bitshuffle sha3 hashlib numpy

External creating of the bloom filter file:

    python mkbloom.py > /tmp/filter.blf

Importing:

    bf = BloomFilter()

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
