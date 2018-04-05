from fastBloomFilter import Bloom

bf = Bloom.BloomFilter(filename='/tmp/filter.blf')

bf.add('30000') 
bf.add('1230213') 
bf.add('1')

print bf.update('1') 
print bf.update('2') 

print bf.query('1')

bf.stat()
bf.info()
