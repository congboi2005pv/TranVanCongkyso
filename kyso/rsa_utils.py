from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

def sign_data(data: bytes, private_key: bytes):
    key = RSA.import_key(private_key)
    h = SHA512.new(data)
    signature = pkcs1_15.new(key).sign(h)
    return signature

def verify_signature(data: bytes, signature: bytes, public_key: bytes):
    key = RSA.import_key(public_key)
    h = SHA512.new(data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
