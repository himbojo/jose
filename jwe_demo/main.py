from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from jwe_aes_gcm import encrypt_direct_a256gcm, decrypt_direct_a256gcm
from jwe_rsa_oaep import encrypt_rsa_oaep_a256gcm, decrypt_rsa_oaep_a256gcm
from jwe_ecdh_es import encrypt_ecdh_es_a256gcm, decrypt_ecdh_es_a256gcm

def create_payload():
    return {"sub": "user123", "msg": "Confidential data."}

if __name__ == "__main__":
    payload = create_payload()

    print("=== Direct AES-GCM (dir + A256GCM) ===")
    # Shared key known by both client and server
    key = get_random_bytes(32)
    jwe1 = encrypt_direct_a256gcm(payload, key)  # Client encrypts
    print("Encrypted:", jwe1)
    print("Decrypted:", decrypt_direct_a256gcm(jwe1, key))  # Server decrypts

    print("\n=== RSA-OAEP + A256GCM ===")
    # Server provides RSA public key to client
    rsa_key = RSA.generate(2048)
    jwe2 = encrypt_rsa_oaep_a256gcm(payload, rsa_key.publickey())  # Client encrypts
    print("Encrypted:", jwe2)
    print("Decrypted:", decrypt_rsa_oaep_a256gcm(jwe2, rsa_key))  # Server decrypts

    print("\n=== ECDH-ES (simulated shared secret) ===")
    # Shared secret derived from ECDH key exchange
    shared_secret = get_random_bytes(32)
    jwe3 = encrypt_ecdh_es_a256gcm(payload, shared_secret)  # Client encrypts
    print("Encrypted:", jwe3)
    print("Decrypted:", decrypt_ecdh_es_a256gcm(jwe3, shared_secret))  # Server decrypts
