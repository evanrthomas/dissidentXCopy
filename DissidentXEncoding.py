# http://pypi.python.org/pypi/pycrypto
# http://pypi.python.org/pypi/pysha3/

import hashlib
import sha3
from Crypto.Cipher import AES

def h(message):
  """
    Returns the hash of message
    message: bytes (ie b'this string')
  """
  return hashlib.sha3_256(message).digest()

def x(m1, m2):
  """
    Returns m1 xor m2
    m1: bytes
    m2: bytes
  """
  assert type(m1) is bytes
  assert type(m2) is bytes
  return (int.from_bytes(m1, 'big') ^ int.from_bytes(m2, 'big')).to_bytes(len(m1), 'big')

assert x(x(b'abc', b'def'), b'def') == b'abc'

def encrypt_ofb(key, iv, plaintext):
  """
  encrypts a message in AES (ofb mode)
  key: bytes
  iv: bytes
  plaintext: bytes
  """
  assert len(key) == 16, key
  assert len(iv) == 16, iv
  return AES.new(key, AES.MODE_OFB, iv).encrypt(plaintext +
      b'a' * (-len(plaintext) % 16) #padding because block size is 16
      )[:len(plaintext)] # strip the padding

assert encrypt_ofb(b'abcd' * 4, b'iv' * 8, encrypt_ofb(b'abcd' * 4, b'iv' * 8, b'plaintext')) == b'plaintext'

def encrypt_message(key, plaintext):
  """
  encrypts a message in AES (ofb mode)
  key: bytes
  plaintext: bytes
  """
  mac = h(key + plaintext)[:4]
  return mac + encrypt_ofb(key, mac + bytes([0] * 12), plaintext)

def prepare_message(key, plaintext):
  """
  hash the plaintext key to 16 bytes and encrypt the message with the hashed key
  """
  key = h(key)[:16]
  return h(key)[:16], encrypt_message(key, plaintext)

def decrypt_message(key, ciphertext):
  """
  decrypt the message and return it iff the mac of the message is correct,
  because we're in ofb mode decryption is the same as encryption, ie x = encrypt(encrypt(x))
  """
  mac = ciphertext[:4]
  r = encrypt_ofb(key, mac + bytes([0] * 12), ciphertext[4:])
  return (r if mac == h(key + r)[:4] else None)

def test_encrypt():
	key = b'abcd' * 4
	fullstr = bytes(list(range(256)))
	for i in range(256):
		mystr = fullstr[:i]
		assert decrypt_message(key, encrypt_message(key, mystr)) == mystr

test_encrypt()

def pack_message(message):
	assert len(message) >= 4, message
	r = message[:4]
	v = len(message) - 4
	lb = bytes([v] if v < 128 else [128 | v >> 8, v & 0xFF])
	r += x(lb, h(r)[:len(lb)])
	r += h(r)[:2]
	return r + message[4:]

def begin_unpack_message(message):
	prefix = x(h(message[:4])[:2], message[4:6])
	if prefix[0] < 128:
		mlen = prefix[0] + 4
		mbegin = 5
	else:
		mlen = (((prefix[0] - 128) << 8) | prefix[1]) + 4
		mbegin = 6
	if message[mbegin:mbegin + 2] != h(message[:mbegin])[:2]:
		return None
	return mlen + mbegin - 2

def unpack_message(message):
	prefix = x(h(message[:4])[:2], message[4:6])
	if prefix[0] < 128:
		mlen = prefix[0] + 4
		mbegin = 5
	else:
		mlen = (((prefix[0] - 128) << 8) | prefix[1]) + 4
		mbegin = 6
	assert len(message) == mlen + mbegin - 2
	return message[:4] + message[mbegin + 2:]

def test_pack():
	fullstr = bytes(list(range(256)))
	for i in range(4, 256):
		mystr = fullstr[:i]
		packed = pack_message(mystr)
		assert begin_unpack_message(packed) == len(packed)
		assert unpack_message(packed) == mystr

test_pack()

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

assert remove_too_short([b'', [b'abc', b'aqc'], b'y']) == [b'a', [b'b', b'q'], b'cy']
assert remove_too_short([b'x', [b'abc', b'abcd'], b'y']) == [b'xabc', [b'', b'd'], b'y']
assert remove_too_short([b'x', [b'abc', b'dabc'], b'y']) == [b'x', [b'', b'd'], b'abcy']
assert remove_too_short([b'x', [b'ac', b'aqc'], b'y']) == [b'xa', [b'', b'q'], b'cy']

def to_bitfield(m):
	r = []
	for v in m:
		for i in range(8):
			r.append((v >> i) & 1)
	return r

def encode_messages(messages, plaintext):
	plaintext = remove_too_short(plaintext)
	base = [plaintext[0]]
	for i in range(1, len(plaintext), 2):
		base.append(plaintext[i][0])
		base.append(plaintext[i+1])
	goal = to_bitfield(x(b''.join([message for key, message in messages]), pdms(messages, b''.join(base))))
	vectors = []
	for i in range(1, len(plaintext), 2):
		vectors.append(to_bitfield(x(pdms(messages, plaintext[i-1][-15:] + plaintext[i][0] + plaintext[i+1][:15]),
			pdms(messages, plaintext[i-1][-15:] + plaintext[i][1] + plaintext[i+1][:15]))))
	toflips = solve(vectors, goal)
	if toflips is None:
		return None
	r = [plaintext[0]]
	for p, i in enumerate(range(1, len(plaintext), 2)):
		r.append(plaintext[i][toflips[p]])
		r.append(plaintext[i+1])
	return b''.join(r)

def pack_and_encode_messages(messages, plaintext):
  """
  messages: array of messages each encrypted with it's own secret key
  plaintext: plaintext that has been run through a preparefunc, ie it looks like [b'abc', [a1, a1'], b'def', [a2, a2'] ...]
  """
  return encode_messages([(key, pack_message(message)) for key, message in messages], plaintext)

def pdms(messages, text):
	return b''.join([partial_decode_message(key, text, len(message)) for (key, message) in messages])

def partial_decode_message(key, message, mylen):
	assert type(key) is bytes
	assert type(message) is bytes
	r = bytes([0] * mylen)
	for i in range(len(message) - 15):
		r = x(r, encrypt_ofb(key, message[i:i+16], bytes([0] * mylen)))
	return r

def decode_and_decrypt_message(key, message):
	key = h(key)[:16]
	key2 = h(key)[:16]
	mystr = partial_decode_message(key2, message, 16)
	mylen = begin_unpack_message(mystr)
	if mylen is None:
		return None
	mystr = partial_decode_message(key2, message, mylen)
	if mystr is None:
		return None
	mystr = unpack_message(mystr)
	if mystr is None:
		return None
	mystr = decrypt_message(key, mystr)
	if mystr is None:
		return None
	return mystr

def xor(a, b):
	assert type(a) is list
	assert type(b) is list
	return [x^y for x, y in zip(a, b)]

assert xor([0, 0, 1, 1], [0, 1, 0, 1]) == [0, 1, 1, 0]

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
				active[j] = xor(active[j], active[i])
	r = [0] * len(active)
	for i in range(len(goal)):
		if goal[i]:
			r = xor(r, active[i][len(goal):])
	return r

# -------------- testing ------------------
from random import randrange

def test_solve():
	vectors = [[randrange(2) for j in range(5)] for i in range(10)]
	goal = [randrange(2) for i in range(5)]
	solution = solve(vectors, goal)
	t = [0] * 5
	for i in range(len(solution)):
		if solution[i]:
			t = xor(t, vectors[i])
	assert t == goal

test_solve()

def test_encode():
	key = bytes([7] * 16)
	plaintext = [b'abc', [b'', b'pqr']]
	for i in range(50):
		plaintext.append(bytes([randrange(256) for j in range(15)]))
		plaintext.append([b'ab', b'cde'])
	plaintext.append(b'stuv')
	message = b'hey'
	assert partial_decode_message(key, encode_messages([(key, message)], plaintext), len(message)) == message

test_encode()

def test_crypt():
	key = b'key'
	message = b'abc'
	key2, message2 = prepare_message(key, message)
	plaintext = [b'abc', [b'', b'pqr']]
	for i in range(100):
		plaintext.append(bytes([randrange(256) for j in range(15)]))
		plaintext.append([b'ab', b'cde'])
	plaintext.append(b'stuv')
	assert decode_and_decrypt_message(key, pack_and_encode_messages([(key2, message2)], plaintext)) == message

test_crypt()

