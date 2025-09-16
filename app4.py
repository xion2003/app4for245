from hashlib import sha256
from Crypto.Cipher import AES
import secrets
key = secrets.token_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)
inp = input('Please input a phrase to encrypt:')
inp = inp.encode(encoding = 'UTF-8', errors = 'strict')
hash = sha256(inp)
hx = hash.hexdigest()
ciphertext, tag = cipher.encrypt_and_digest(inp)
cipher = AES.new(key, AES.MODE_EAX, nonce = cipher.nonce)
plaintext = cipher.decrypt(ciphertext)
print('hx: ', hx)
try:

    cipher.verify(tag)

    print("The message is authentic:", plaintext)

except ValueError:

    print("Key incorrect or message corrupted")