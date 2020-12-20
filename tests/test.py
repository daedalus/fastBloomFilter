from fastBloomFilter.bloom import BloomFilter

bf = BloomFilter(filename='./filter.blf')
bf.add('30000'.encode("utf-8"))
bf.add('1230213'.encode("utf-8"))
bf.add('1'.encode("utf-8"))

print(bf.update('1'.encode("utf-8")))  # True
print(bf.update('1'.encode("utf-8")))  # True
print(bf.update('2'.encode("utf-8")))  # False
print(bf.update('2'.encode("utf-8")))  # True
print(bf.query('1'.encode("utf-8")))  # True
print(bf.query('1230213'.encode("utf-8")))  # True
print(bf.query('12'.encode("utf-8")))  # False

bf.stats()
bf.info()
