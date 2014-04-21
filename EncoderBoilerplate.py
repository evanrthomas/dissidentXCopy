from DissidentXEncoding import prepare_message, pack_and_encode_messages
from sys import argv

def encode(preparefunc):
  """
  prepareFunc is a function from the bytes of plaintext
  to an array wwhere every alternate ai is replaced with an array
  [ai, ai']. So a text xxxa1yyyya2zzz becomes
  [b'xxx',[a1, a1'], b'yyy', [a2, a2'], b'zzz']
  """
  f = open(argv[1], 'br')
  p = f.read()
  f.close()
  messages = [prepare_message(
    argv[i].encode('utf-8'), argv[i+1].encode('utf-8'))
      for i in range(2, len(argv), 2)]
  m = pack_and_encode_messages(messages, preparefunc(p))
  if m is None:
    print('Error')
  else:
    f = open(argv[1], 'bw')
    f.write(m)
    f.close()
