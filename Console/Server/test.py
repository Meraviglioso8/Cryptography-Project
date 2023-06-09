from cfg import AES_KEY
from Crypto.Cipher import AES
from binascii import unhexlify

def encrypt(in_str):
    enc = AES.new(unhexlify(AES_KEY), AES.MODE_GCM)
    ciphertext, tag = enc.encrypt_and_digest(in_str.encode())
    nonce = enc.nonce
    return ciphertext.hex(), tag.hex(),nonce.hex()
def decrypt (in_str,tag,nonce):
    in_str = unhexlify(in_str)
    decrypt_cipher = AES.new(unhexlify(AES_KEY), AES.MODE_GCM,nonce=unhexlify(nonce))
    plain_text = decrypt_cipher.decrypt_and_verify(in_str, unhexlify(tag))
    return plain_text

test_str = encrypt("Vailozluon")
print(len(''))
print(test_str)
print(decrypt(test_str[0],test_str[1],test_str[2]))