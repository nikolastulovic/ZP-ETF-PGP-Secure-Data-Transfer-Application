from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
import binascii

def pad_key(key):
    """Ensure the key is 24 bytes long (192 bits)."""
    if len(key) > 24:
        return key[:24]
    else:
        return key.ljust(24, b'\0')

def encrypt_3des_cfb(plaintext, key):
    key = pad_key(key)
    iv = get_random_bytes(DES3.block_size)
    cipher = DES3.new(key, DES3.MODE_CFB, iv=iv)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return binascii.hexlify(iv + ciphertext).decode('utf-8')

def decrypt_3des_cfb(ciphertext_with_iv_hex, key):
    key = pad_key(key)
    ciphertext_with_iv = binascii.unhexlify(ciphertext_with_iv_hex)
    iv = ciphertext_with_iv[:DES3.block_size]
    ciphertext = ciphertext_with_iv[DES3.block_size:]
    cipher = DES3.new(key, DES3.MODE_CFB, iv=iv)
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')
    return plaintext