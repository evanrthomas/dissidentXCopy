import pylab as pl
import json

data = json.load(open('encodingLimit', 'r'))

plainTextSize = "105"
f =  data[plainTextSize]
f = dict((int(k), f[k]) for k in f.keys())

fig = pl.figure()
ax =pl.subplot(111)
ax.bar(f.keys(), [f[k] for k in f.keys()])
pl.show()
