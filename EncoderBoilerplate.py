from DissidentXEncoding import prepare_message, pack_and_encode_messages

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
      for key, message in keyMessagePairs]

  return pack_and_encode_messages(messages, preparefunc(fileBytes))
