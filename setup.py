from setuptools import setup

VERSION = '0.0.4'
BASE_CVS_URL = 'http://github.com/daedalus/bloomfilter'

setup(
    name='fastBloomFilter',
    packages=['fastBloomFilter', ],
    version=VERSION,
    author='Dario Clavijo',
    author_email='dclavijo@protonmail.com',
    install_requires=[x.strip() for x in open('requirements.txt').readlines()],
    url=BASE_CVS_URL,
    download_url='{}/tarball/{}'.format(BASE_CVS_URL, VERSION),
    test_suite='tests',
    tests_require=[x.strip() for x in open('requirements_test.txt').readlines()],
    keywords=[],
    classifiers=[
        "Development Status :: 1 - Planning",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: GNU General Public License (GPL)",
    ],
    description = ("A fast and simple probabilistic bloom filter that supports compression"),
    long_description=open('README.rst','r+').read(),
)
