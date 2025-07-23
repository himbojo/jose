# Simulated ECDH-ES using a shared secret between client and server
# In real-world, the shared secret is derived via ECDH key agreement
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json
import os
import sys
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, base_dir)
from helpers import b64url_encode, b64url_decode, json_dumps

# Client encrypts payload using a shared secret derived from ECDH key exchange
def encrypt_ecdh_es_a256gcm(payload: dict, shared_secret: bytes):
    header = {"alg": "ECDH-ES", "enc": "A256GCM"}
    header_b64 = b64url_encode(json.dumps(header).encode())

    iv = get_random_bytes(12)
    cipher = AES.new(shared_secret, AES.MODE_GCM, nonce=iv)
    cipher.update(header_b64.encode())

    plaintext = json.dumps(payload).encode()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        "protected": header_b64,
        "iv": b64url_encode(iv),
        "ciphertext": b64url_encode(ciphertext),
        "tag": b64url_encode(tag)
    }

# Server decrypts payload using the same shared secret
def decrypt_ecdh_es_a256gcm(jwe: dict, shared_secret: bytes):
    iv = b64url_decode(jwe["iv"])
    ciphertext = b64url_decode(jwe["ciphertext"])
    tag = b64url_decode(jwe["tag"])
    aad = jwe["protected"].encode()

    cipher = AES.new(shared_secret, AES.MODE_GCM, nonce=iv)
    cipher.update(aad)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(plaintext)
