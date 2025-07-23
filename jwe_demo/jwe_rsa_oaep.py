from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import json
import os
import sys
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, base_dir)
from helpers import b64url_encode, b64url_decode, json_dumps

# Client encrypts the payload using a randomly generated CEK (content encryption key)
# The CEK is then encrypted using the recipient's (server's) RSA public key (RSA-OAEP)
def encrypt_rsa_oaep_a256gcm(payload: dict, rsa_pub_key):
    cek = get_random_bytes(32)  # AES-256 key
    iv = get_random_bytes(12)
    header = {"alg": "RSA-OAEP", "enc": "A256GCM"}
    header_b64 = b64url_encode(json.dumps(header).encode())

    # Encrypt the CEK using recipient's RSA public key
    rsa_cipher = PKCS1_OAEP.new(rsa_pub_key)
    encrypted_key = rsa_cipher.encrypt(cek)

    # Encrypt the payload using AES-GCM with the CEK
    cipher = AES.new(cek, AES.MODE_GCM, nonce=iv)
    aad = header_b64.encode()
    cipher.update(aad)
    plaintext = json.dumps(payload).encode()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        "protected": header_b64,
        "encrypted_key": b64url_encode(encrypted_key),
        "iv": b64url_encode(iv),
        "ciphertext": b64url_encode(ciphertext),
        "tag": b64url_encode(tag)
    }

# Server decrypts the JWE using its private RSA key to unwrap CEK and then decrypts the payload
def decrypt_rsa_oaep_a256gcm(jwe: dict, rsa_priv_key):
    encrypted_key = b64url_decode(jwe["encrypted_key"])
    iv = b64url_decode(jwe["iv"])
    ciphertext = b64url_decode(jwe["ciphertext"])
    tag = b64url_decode(jwe["tag"])
    aad = jwe["protected"].encode()

    # Decrypt the CEK using the private RSA key
    rsa_cipher = PKCS1_OAEP.new(rsa_priv_key)
    cek = rsa_cipher.decrypt(encrypted_key)

    # Use the CEK to decrypt the payload
    cipher = AES.new(cek, AES.MODE_GCM, nonce=iv)
    cipher.update(aad)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(plaintext)
