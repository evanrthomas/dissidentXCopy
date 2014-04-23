from EncoderBoilerplate import encode
from sys import argv

def endings_encode(p):
  r = []
  for s in p.split(b'\n'):
    if r:
      r.append([b'\n', b' \n'])
    r.append(s.rstrip())
  return r

if __name__ == '__main__':

  f = open(argv[1], 'br')
  fileBytes = f.read()
  f.close()

  m = encode(endings_encode, fileBytes,
      [(argv[i], argv[i+1]) for i in range(2, len(argv), 2)] )

  if m is None:
    print('Error')
  else:
    f = open(argv[1], 'bw')
    f.write(m)
    f.close()
