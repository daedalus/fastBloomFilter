[![Libraries.io SourceRank](https://badges.weareopensource.me/librariesio/sourcerank/pypi/fastBloomFilter)](https://libraries.io/pypi/fastBloomFilter)
![pypi downloads](https://img.shields.io/pypi/dm/fastbloomfilter?label=pypi%20downloads)
![lint_python](https://github.com/daedalus/fastBloomFilter/workflows/lint_python/badge.svg)
![Upload Python Package](https://github.com/daedalus/fastBloomFilter/workflows/Upload%20Python%20Package/badge.svg)
![CodeQL](https://github.com/daedalus/fastBloomFilter/workflows/CodeQL/badge.svg)
[![GitHub issues](https://img.shields.io/github/issues/daedalus/fastBloomFilter.svg)](https://github.com/daedalus/fastBloomFilter/issues)
[![GitHub forks](https://img.shields.io/github/forks/daedalus/fastBloomFilter.svg)](https://github.com/daedalus/fastBloomFilter/network)
[![GitHub stars](https://img.shields.io/github/stars/daedalus/fastBloomFilter.svg)](https://github.com/daedalus/fastBloomFilter/stargazers)
[![GitHub license](https://img.shields.io/github/license/daedalus/fastBloomFilter.svg)](https://github.com/daedalus/fastBloomFilter)

# Simple and fast pythonic bloomfilter

From wikipedia: "A Bloom filter is a space-efficient probabilistic data structure, conceived by Burton Howard Bloom in 1970, that is used to test whether an element is a member of a set. False positive matches are possible, but false negatives are not – in other words, a query returns either "possibly in set" or "definitely not in set". Elements can be added to the set, but not removed (though this can be addressed with a "counting" filter); the more elements that are added to the set, the larger the probability of false positives."


### This filter supports: ###

```
- Saving, reloading with pickle. 
- Stats
- Entropy analysis
- Internal and external hashing of data.
- raw filter merging
```


### Installing: ###

```
sudo pip install fastbloomfilter
```

### External creation of the bloom filter file: ###

```
python mkbloom.py /tmp/filter.blf
```

### Importing: ###

```
>>> from fastBloomFilter import bloom
>>> bf = bloom.BloomFilter(array_size=1024**3)
```

Or

```
>>> from fastBloomFilter import bloom
>>> bf = bloom.BloomFilter(filename='/tmp/filter.blf')
```

### Adding data to it: ###

```
>>> bf.add('30000')
>>> bf.add('1230213')
>>> bf.add('1')
```

### Printing stats: ###

```
>>> bf.stat()
```
   
Or:

```
>>> bf.info()
```

### Querying data: ###

```
>>> print(bf.query('1'))
True
>>> print(bf.query('1230213'))
True
>>> print(bf.query('12'))
False
>>> print(bf['1'])
True
```   

### Querying data and at the same time adding it: ###

```
>>> print(bf.update('1'))
False 
# False means the object wasn't existing and was added.
>>> print(bf.update('1')) 
True  
# True means the object existed and nothing new was added.
>>> print(bf.update('2'))
False
>>> print(bf.update('2'))
True
```

### Merging two filters: ###
Create first filter:
```
>>> from fastBloomFilter import bloom
>>> bf1 = bloom.BloomFilter(array_size=1024**3)
>>> bf1.add("1")
```
Create second filter:
```
>>> from fastBloomFilter import bloom
>>> bf2 = bloom.BloomFilter(array_size=1024**3)
>>> bf2.add("2")
```
Merge the two filters into a third filter:
```
>>> bf3 = bf1 + bf2
```
Check the elements in the third filter:
```
>>> print(bf3["1"])
True
>>> print(bf3["2"])
True
```

### Contributing ###
```
Contributons:
    Are welcome!
    Criteria: - They should not include hidden folders or files of any ide environment.
              - They should not delete big portions of the project.
              - They should not include files that does not have anything to do with the project.
              - They should not change the API. (API changes should be proposed with Issues as enhancements)
              - They should not include any obfuscated code.
              - They should not include binaries.
              - They should be in small PRs for faster reviewing process.
              - They should include a small testcase.
              - Any contribution not hornoring this criteria will be rejected until it does.
```
