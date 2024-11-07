from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import binascii

def pad_key(key):
    """Ensure the key is 16 bytes long (128 bits)."""
    if len(key) > 16:
        return key[:16]
    else:
        return key.ljust(16, b'\0')

def encrypt_aes128_cfb(plaintext, key):
    key = pad_key(key)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return binascii.hexlify(iv + ciphertext).decode('utf-8')

def decrypt_aes128_cfb(ciphertext_with_iv_hex, key):
    key = pad_key(key)
    ciphertext_with_iv = binascii.unhexlify(ciphertext_with_iv_hex)
    iv = ciphertext_with_iv[:AES.block_size]
    ciphertext = ciphertext_with_iv[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')
    return plaintext