from sys import argv
from DissidentXEncoding import prepare_message, pack_and_encode_messages
import pdb

def endings_encode(p):
  r = []
  for s in p.split(b'\n'):
    if r:
      r.append([b'\n', b' \n'])
    r.append(s.rstrip())
  return r

def encode(preparefunc, fileBytes, keyMessagePairs):
  """
  prepareFunc :a function from the bytes of plaintext
  to an array wwhere every alternate ai is replaced with an array
  [ai, ai']. So a text xxxa1yyyya2zzz becomes
  [b'xxx',[a1, a1'], b'yyy', [a2, a2'], b'zzz']

  fileBytes: dump of the bytes of the file to be encoded
  keyMessagePairs: array of [(key1, message1), (key2, message2)]
  """
  messages = [prepare_message(
    key.encode('utf-8'), message.encode('utf-8'))
      for key, message in keyMessagePairs] #h(key), encrypted(message) pairs
  return encode(messages[0][0], messages[0][1], preparefunc(fileBytes))

if __name__ == '__main__':

  filename = argv[1]
  f = open(filename, 'br')
  fileBytes = f.read()
  f.close()


  m = encode(endings_encode, fileBytes,
      [(argv[i], argv[i+1]) for i in range(2, len(argv), 2)] )

  if m is None:
    print('Error')
  else:
    print('Success')
    f = open(filename+'.encoded', 'bw')
    f.write(m)
    f.close()
