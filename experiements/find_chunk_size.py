import sys
sys.path.insert(0, '../')
from line_endings_encode import endings_encode
import EncoderBoilerplate, random, bisect, cProfile, json, string

letterPmf = list(map(lambda x: x/100.0,
  [8.167,1.492,2.782,4.253,12.702,2.228,2.015,6.094,6.966,0.153,0.772,
4.025,2.406,6.749,7.507,1.929,0.095,5.987,6.327, 9.056,2.758,0.978,2.360,0.150,1.974,0.074]))
wordLenPmf = list(map(lambda x: x/100.0,
    [0, .6, 2.6, 5.2, 8.5, 12.2, 14, 14, 12.6, 10.1, 7.5, 5.2, 3.2, 2.0, 1.0, 0.6, 0.3, 0.2, 0.1, 0.1]))

def cmf(pmf):
  cmf = [pmf[0]]
  for i in range(1, len(pmf)):
    cmf.append(cmf[i-1] + pmf[i])
  return cmf

def sample(pmf):
  return bisect.bisect(cmf(pmf), random.random())

def genWord():
  return ''.join([chr(sample(letterPmf) + 97) for x in range(int(sample(wordLenPmf)))])

def genText(textSize, avgLineLength = 50,  varLineLength = 5):
  p = ''
  for x in range(textSize):
    thisLineLength = random.gauss(avgLineLength, varLineLength)
    thisLine = ''
    while len(thisLine) < thisLineLength:
      thisLine += genWord() +  ' '
    thisLine = thisLine[:-1]
    p += thisLine + '\n'
  return p

def encodeInRandomText(key, message, textSize=50):
  return EncoderBoilerplate.encode(endings_encode, bytes(genText(textSize).encode('utf-8')), [(key, message)])

def profile():
  prof =  cProfile.Profile()
  val = prof.runcall(encode, key, message)
  prof.print_stats()

def findEncodingLimit(plaintextSize):
  """
    for a given plainTextSize, generate a distribution f(m) -> p
      where m is a message size and p is "the probability that encoding a message of
      size m into a plaintext of size plainTextSize will fail"
  """
  randString = lambda size: ''.join([random.choice(string.ascii_lowercase) for _ in range(size)])

  keySize = 10
  messageSize = 1
  f = dict()
  for messageSize in range(plaintextSize): #control messageSize
    f[messageSize] = 0
    print('encoding')
    for x in range(50):
      if encodeInRandomText(randString(keySize), randString(messageSize), plaintextSize) != None:
        f[messageSize] += 1
    f[messageSize] /= 50.0
    print('messageSize', messageSize)
  return f






if __name__ == "__main__":
  #profile()
  data = {} #hash of {plainTextSize -> encodingLimitDist}
  for plaintextSize in range(100, 200):
    data[plaintextSize] = findEncodingLimit(plaintextSize)
    print(plaintextSize)
  json.dump(data, open('encodingLimit', 'w'))

