# Simple and fast pythonic bloomfilter

From wikipedia: "A Bloom filter is a space-efficient probabilistic data structure, conceived by Burton Howard Bloom in 1970, that is used to test whether an element is a member of a set. False positive matches are possible, but false negatives are not – in other words, a query returns either "possibly in set" or "definitely not in set". Elements can be added to the set, but not removed (though this can be addressed with a "counting" filter); the more elements that are added to the set, the larger the probability of false positives."

This filter supports: 

    Saving, reloading, compressed bloomfilter file lrzip like
        for compression: lz4>lzo>zlib>bz2>lzma
        for decompression: lzma>bz2>zlib>lzo>lz4
    Stats
    Entropy analysis
    Internal and external hashing of data.
    raw filter merging

Installing:

    sudo pip install fastbloomfilter

External creating of the bloom filter file:

    python mkbloom.py /tmp/filter.blf

Importing:

    from fastBloomFilter import bloom

    bf = bloom.BloomFilter(filename='/tmp/filter.blf')

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
