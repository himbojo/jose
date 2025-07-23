from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json
from jwe_helpers import b64url_encode, b64url_decode

# Symmetric encryption using direct mode ("alg": "dir") and A256GCM
# Typically used when both client and server share the same symmetric key (e.g., internal microservices)
def encrypt_direct_a256gcm(payload: dict, key: bytes):
    # Step 1: Create JWE header specifying algorithms
    header = {"alg": "dir", "enc": "A256GCM"}  # 'dir' means the key is used directly
    header_b64 = b64url_encode(json.dumps(header).encode())

    # Step 2: Encrypt the payload using AES-GCM
    iv = get_random_bytes(12)  # 96-bit IV for AES-GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    aad = header_b64.encode()
    cipher.update(aad)  # Authenticated Additional Data

    plaintext = json.dumps(payload).encode()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # Step 3: Return JWE components (no 'encrypted_key' needed since alg=dir)
    return {
        "protected": header_b64,
        "iv": b64url_encode(iv),
        "ciphertext": b64url_encode(ciphertext),
        "tag": b64url_encode(tag),
        "cek": key.hex()  # shown for demonstration; normally not exposed
    }

# Server decrypts JWE using the shared symmetric key
def decrypt_direct_a256gcm(jwe: dict, key: bytes):
    iv = b64url_decode(jwe["iv"])
    ciphertext = b64url_decode(jwe["ciphertext"])
    tag = b64url_decode(jwe["tag"])
    aad = jwe["protected"].encode()

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    cipher.update(aad)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(plaintext)
