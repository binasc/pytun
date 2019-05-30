def bxor_add(b1, b2): # use xor for bytes
    result = b""
    for b1, b2 in zip(b1, b2):
        result += bytes([b1 ^ b2])
    return result

def bxor_inplace(b1, b2):
    result = bytearray(b1)
    for i, b in enumerate(b2):
        result[i] ^= b
    return bytes(result)

def bxor_join(b1, b2): # use xor for bytes
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)

def bxor_append(b1, b2): # use xor for bytes
    result = bytearray()
    for b1, b2 in zip(b1, b2):
        result.append(b1 ^ b2)
    return bytes(result)

from itertools import cycle, islice
from Crypto.Util.strxor import strxor
from math import ceil
def _xor(key, data):
    return strxor(data, bytes(bytearray(islice(cycle(key), len(data)))))

def bxor_crypto(b1, b2):
    return strxor(b1, bytes(bytearray(islice(cycle(b2), len(b1)))))

def bxor_crypto_v2(b1, b2):
    return strxor(b1, bytes((ceil(len(b1) / len(b2)) * b2))[:len(b1)])

import numpy

def bxor_numpy(b1, b2):
    n_b1 = numpy.frombuffer(b1, dtype='uint8')
    b2 = bytes(bytearray(islice(cycle(b2), len(b1))))
    n_b2 = numpy.frombuffer(b2, dtype='uint8')

    return (n_b1 ^ n_b2).tostring()

def bxor_numpy_v2(b1, b2):
    n_b1 = numpy.frombuffer(b1, dtype='uint8')
    b2 = bytes((ceil(len(b1) / len(b2)) * b2))[:len(b1)]
    n_b2 = numpy.frombuffer(b2, dtype='uint8')

    return (n_b1 ^ n_b2).tostring()

#>>> 

from os import urandom
from timeit import Timer
from functools import partial

first_random = urandom(2000000)
second_random = urandom(2000000)

#o = Timer(partial(bxor_add, first_random, second_random)).timeit(1)
#print(o)
#o = Timer(partial(bxor_inplace, first_random, second_random)).timeit(1)
#print(o)
#o = Timer(partial(bxor_join, first_random, second_random)).timeit(1)
#print(o)
o = Timer(partial(bxor_append, first_random, second_random)).timeit(10)
print(o)
o = Timer(partial(bxor_crypto, first_random, second_random)).timeit(10)
print(o)
o = Timer(partial(bxor_crypto_v2, first_random, second_random)).timeit(10)
print(bxor_crypto(first_random, second_random) == bxor_crypto_v2(first_random, second_random))
print(o)
o = Timer(partial(bxor_numpy, first_random, second_random)).timeit(10)
print(o)
o = Timer(partial(bxor_numpy_v2, first_random, second_random)).timeit(10)
print(o)
