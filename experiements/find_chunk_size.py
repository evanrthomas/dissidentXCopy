import sys
sys.path.insert(0, '../')
import line_endings_encode, DissidentXEncoding, EncoderBoilerplate
import random, bisect, cProfile

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

def genText():
  avgLineLength = 50
  varLineLength = 5
  avgTextLines = 20
  varTextLines = 10

  textSize = int(random.gauss(avgTextLines, varTextLines))
  p = ''
  for x in range(textSize):
    thisLineLength = random.gauss(avgLineLength, varLineLength)
    thisLine = ''
    while len(thisLine) < thisLineLength:
      thisLine += genWord() +  ' '
    thisLine = thisLine[:-1]
    p += thisLine + '\n'
  return bytes(p.encode('utf-8'))



