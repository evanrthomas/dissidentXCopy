# http://pypi.python.org/pypi/pycrypto
# http://pypi.python.org/pypi/pysha3/

import hashlib
import sha3
from Crypto.Cipher import AES
import pdb
from math import log as ln
import random
"""
mcs: message chunk size
"""
AES_BLOCK_SIZE = 16
key = None #h(password)[:AES_BLOCK_SIZE]
params = {"default mcs": 12,
          "mac size": 4,
          "window size": 16,
          "window spacing": 1}
params["chunk size"] = params["mac size"] + params["default mcs"]
assert params["window size"] > params["window spacing"]
assert params["window size"] >= params["chunk size"]

def h(message):
  """
    Returns the hash of message
    message: bytes (ie b'this string')
  """
  return hashlib.sha3_256(message).digest()

hdebug = h
def xorBitfield(a, b):
  assert len(a) == len(b)
  return [x^y for x,y in zip(a,b)]

def xor(m1, m2):
  """
    Returns m1 xor m2
    m1: bytes
    m2: bytes
  """
  assert type(m1) is bytes
  assert type(m2) is bytes
  return (int.from_bytes(m1, 'big') ^ int.from_bytes(m2, 'big')).to_bytes(max(len(m1),len(m2)), 'big')

def solve(vectors, goal):
  active = [x + [0] * len(vectors) for x in vectors]
  for i in range(len(active)):
    active[i][len(goal) + i] = 1
  for i in range(len(goal)):
    p = i
    while p < len(active) and active[p][i] == 0:
      p += 1
    if p == len(vectors):
      return None
    active[p], active[i] = active[i], active[p]
    for j in range(len(active)):
      if j != i and active[j][i]:
        active[j] = xorBitfield(active[j], active[i])
  r = [0] * len(active)
  for i in range(len(goal)):
    if goal[i]:
      r = xorBitfield(r, active[i][len(goal):])
  return r

def encrypt(key, plaintext, iv=None):
  """
  encrypts a message in AES (ofb mode)
  key: bytes
  iv: bytes
  plaintext: bytes
  """
  global params
  if iv == None:
    iv = bytes([0]*(params["default mcs"] +params["mac size"]))

  assert len(iv) == params["default mcs"] + params["mac size"], iv
  key = h(key)[:AES_BLOCK_SIZE]
  return AES.new(key, AES.MODE_OFB, iv).encrypt(plaintext +
      b'a' * (-len(plaintext) % AES_BLOCK_SIZE) #padding because block size is 16
      )

def remove_too_short(plaintext):
  """
  Takes an array of type [a, [b, c], d],
  returns [a', [b', c'], d'] where
  a' = a + pre(b,c),
  d' = d + suf(b,c),
  b' = b - pre(b,c) - suf(b,c)
  c' = c - pre(b,c) - suf(b,c)
  and pre,suf are funcitons that return the longest common prefix/suffix or their arguments
  """
  p2 = [b'']
  for i in range(0, len(plaintext)-1, 2):
    assert((type(plaintext[i]) is bytes) and (type(plaintext[i+1])  is list)) #alternates [text, [alt0, alt1], text ...]
    p2[-1] += plaintext[i]
    if len(p2) > 1 and len(p2[-1]) < 15:
      p2[-1] += plaintext[i+1][0]
    else:
      a, b = plaintext[i+1]
      j = 0
      while j < len(a) and j < len(b) and a[j] == b[j]:
        j += 1
      if j:
        p2[-1] += a[:j]
        a = a[j:]
        b = b[j:]
      j = 0
      while j < len(a) and j < len(b) and a[-j-1] == b[-j-1]:
        j += 1
      if j:
        excess = a[-j:]
        a = a[:-j]
        b = b[:-j]
      else:
        excess = b''
      p2.append([a, b])
      p2.append(excess)
  p2[-1] += plaintext[-1]
  return p2

def enforceAltSpacing(preparedText, windowSize):
  global params
  i = 2
  while i < len(preparedText):
    while len(preparedText[i]) < windowSize and i != (len(preparedText) - 1):
      preparedText[i] += preparedText[i+1][0] + preparedText[i+2]
      preparedText.pop(i+1)
      preparedText.pop(i+1)
    i += 2
  return preparedText

def genProblem(preparedText):
  assert type(preparedText[0]) is bytes
  deltaVectors = []
  current = bytes([0])
  ws = params["window size"]
  for i in range(0, len(preparedText), 2): #go through "alt absent" text
    current = xor(current,
        slideAndXor(preparedText[i], 0))
  for i in range(1, len(preparedText), 2): #go through "alt present text"
    before = preparedText[i-1][-(ws-1):]
    after = preparedText[i+1][:ws-1] if i + 1 <len(preparedText) else b''
    alt0 = before + preparedText[i][0] +  after
    alt1 = before + preparedText[i][1] +  after
    alt0 = slideAndXor(alt0, 0)
    alt1 = slideAndXor(alt1, 1)

    current = xor(current, alt0)
    deltaVectors.append(xor(alt0, alt1))
  return current, deltaVectors

def altsNeeded(numBytes):
  bits = 8*numBytes
  return bits + int(ln(bits))

def to_bitfield(m):
  r = []
  for v in m:
    for i in range(8):
      r.append((v >> i) & 1)
  return r

def slideAndXorUntil(text, begin, constraint):
  global key
  assert begin < len(text)
  chunk = bytes([0])
  ws = params["window size"]
  i = 0
  while begin + i + ws < len(text):
    chunk = xor(chunk, h(key + text[begin + i:begin + i+ws])[:params["chunk size"]])
    if constraint(chunk):
      return chunk, i+ws
    i += 1

collections = dict((i,[]) for i in range(50))
def slideAndXor(text, bucket):
  global key
  a = bytes([0])
  ws = params["window size"]
  for i in range(0, len(text) - ws + 1):
    collections[bucket].append(text[i:i+ws])
    a = xor(a, h(key + text[i:i+ws])[:params["chunk size"]])
  return a

def encodeChunk(key, messageChunk, preparedText, preparedTextIndex):
  print('preparedTextIndex', preparedTextIndex, preparedText[preparedTextIndex])
  assert len(messageChunk) <= params["default mcs"], messageChunk
  an = altsNeeded(params["chunk size"])
  goal = h(key + preparedText[preparedTextIndex][:params["mac size"]])[:params["mac size"]] \
      + messageChunk
  goal += bytes([0]*(params["chunk size"] - len(goal))) #add padding to goal
  print('goal', goal)

  toflips = None
  while toflips == None:
    current, deltaVectors = genProblem(preparedText[preparedTextIndex: preparedTextIndex + 2*an])
    toflips = solve([to_bitfield(x) for x in deltaVectors],
        to_bitfield(xor(goal, current)))
    an += 1
    if preparedTextIndex + 2*an >= len(preparedText):
      return None
  an -= 1
  print('thinks it workd')
  encodedText = flatten(preparedText, preparedTextIndex,
      preparedTextIndex + 2*an, lambda i: toflips[i])

  return encodedText, preparedTextIndex + 2*an

def flatten(pt, begin, end, altChoice):
  ans = b''
  for i in range(begin, end, 2):
    ithAlt = int((i-begin)/2)
    ans += pt[i] + (pt[i+1][altChoice(ithAlt)] if i+1 < end else b'')
  return ans

def encode(key, message, preparedText):
  """
  k bytes
  message bytes
  preparedText arr:[text, [alt0, alt1], text, [alt0, alt1] ...]
  """
  #message = encrypt(key, message)
  preparedText = remove_too_short(preparedText)
  preparedText = enforceAltSpacing(preparedText, params["window size"])
  mcs = params["default mcs"]
  messageIndex = 0
  preparedTextIndex = 0
  encoded = b''
  for messageIndex in range(0,len(message), mcs):
    a = encodeChunk(key, message[messageIndex: messageIndex+mcs],
        preparedText, preparedTextIndex)
    if a == None:
      return None
    encoded += a[0]
    preparedTextIndex = a[1]
  return encoded + flatten(preparedText,
      preparedTextIndex, len(preparedText), lambda x: 0)

def decode(plaintext):
  ans = b''
  macSize = params["mac size"]
  index = 0
  while index < len(plaintext):
    a = slideAndXorUntil(plaintext, index,
        lambda x: x[:macSize] == h(key + plaintext[index:index+macSize])[:macSize])
    if a == None:
      return ans if ans != b'' else None
    ans += a[0][macSize:]
    index = a[1]
    print(a[0][macSize:], len(a[0][macSize:]))
  return ans


def test_remove_too_short():
  assert remove_too_short([b'', [b'abc', b'aqc'], b'y']) == [b'a', [b'b', b'q'], b'cy']
  assert remove_too_short([b'x', [b'abc', b'abcd'], b'y']) == [b'xabc', [b'', b'd'], b'y']
  assert remove_too_short([b'x', [b'abc', b'dabc'], b'y']) == [b'x', [b'', b'd'], b'abcy']
  assert remove_too_short([b'x', [b'ac', b'aqc'], b'y']) == [b'xa', [b'', b'q'], b'cy']

def testEnforceAltSpacing():
  a = ['a', ['0', '1'], 'abcd', ['0','1'], 'abc', ['0','1'], 'ab', ['0', '1']]
  b = ['a', ['0', '1'], 'abcd', ['0', '1'], 'abc0ab', ['0', '1']]
  assert enforceAltSpacing(a, 4) == b

def test_solve():
  from random import randrange
  from math import log as ln
  vectors = [[randrange(2) for j in range(128)] for i in range(int(128+ln(128)))]
  goal = [randrange(2) for i in range(128)]
  solution = solve(vectors, goal)
  assert solution != None
  t = [0] * 128
  for i in range(len(solution)):
    if solution[i]:
      t = xorBitfield(t, vectors[i])
  assert t == goal

def testFlatten():
  arr = [b'a', [b'b', b'c'], b'd', [b'e', 'f'], b'g']
  toflip = [1, 0]
  flat = b'acdeg'
  assert flatten(arr, 0, len(arr), lambda x: toflip[x]) == flat

def diff(arr1, arr2):
  justArr1, justArr2 = [], []
  for x in arr1:
    if not(x in arr2):
      justArr1.append(x)
  for x in arr2:
    if not(x in arr1):
      justArr2.append(x)
  return justArr1, justArr2


def testGenProblem():
  from line_endings_encode import endings_encode
  prepared =  endings_encode(open('genesis.txt', 'rb').read())
  origFlat = flatten(prepared, 0, 6, lambda x: 0) #3 alts
  current, deltaVectors = genProblem(prepared[0:6])

  assert slideAndXor(origFlat, 2) == current

  for i in range(len(deltaVectors)):
    ithFlat = flatten(prepared, 0, 6, lambda x: int(i == x))
    assert xor(current, slideAndXor(ithFlat, 40)) == deltaVectors[i]

def testAll():
  test_remove_too_short()
  print('success: test remove too short')
  testEnforceAltSpacing()
  print('success: test enforce alt spacing')
  test_solve()
  print('success: test solve')
  testFlatten()
  print('sucess: test flatten')
  testGenProblem()
  print('success: gen problem')

if __name__ == "__main__":
  from line_endings_encode import endings_encode
  global key
  password = b'password'
  key = h(password)[:AES_BLOCK_SIZE]
  #testAll()
  covertext = open('genesis.txt', 'rb').read()
  plaintextMessage = b'this is a very long sentence eeeeeeeeeeeee'

  stegotext = encode(key, plaintextMessage, endings_encode(covertext))
  print(decode(stegotext))
