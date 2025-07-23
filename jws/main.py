import datetime
from jwt_hs256 import encode_hs256, decode_hs256
from jwt_rs256 import encode_rs256, decode_rs256
from jwt_es256 import encode_es256, decode_es256
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def create_payload():
    now = datetime.datetime.now(datetime.timezone.utc)
    return {
        "sub": "user123",
        "name": "Alice Example",
        "admin": True,
        "iat": int(now.timestamp()),
        "exp": int((now + datetime.timedelta(hours=1)).timestamp())
    }

if __name__ == "__main__":
    payload = create_payload()

    # HS256
    secret = "supersecret"
    token_hs = encode_hs256(payload, secret)
    print("HS256 Token:", token_hs)
    print("HS256 Decoded:", decode_hs256(token_hs, secret))

    # RS256
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_public = rsa_private.public_key()
    token_rs = encode_rs256(payload, rsa_private)
    print("\nRS256 Token:", token_rs)
    print("RS256 Decoded:", decode_rs256(token_rs, rsa_public))

    # ES256
    ec_private = ec.generate_private_key(ec.SECP256R1())
    ec_public = ec_private.public_key()
    token_es = encode_es256(payload, ec_private)
    print("\nES256 Token:", token_es)
    print("ES256 Decoded:", decode_es256(token_es, ec_public))
