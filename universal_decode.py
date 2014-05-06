from DissidentXEncoding import decode_and_decrypt_message
from sys import argv

filename = argv[1]
key = argv[2].encode('utf-8')
f = open(filename+'.encoded', 'br')
p = f.read()
f.close()
m = decode_and_decrypt_message(key, p)
if m is not None:
  print(m.decode('utf-8'))
else:
  print("couldn't decode")
