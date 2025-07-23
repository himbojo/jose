from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from jwt_helpers import b64url_encode, b64url_decode, json_dumps
import json

# Client or token issuer signs with their private RSA key
def encode_rs256(payload: dict, private_key) -> str:
    header = {"alg": "RS256", "typ": "JWT"}
    header_b64 = b64url_encode(json_dumps(header).encode())
    payload_b64 = b64url_encode(json_dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}"

    # Sign using RSA-PKCS#1 v1.5 + SHA-256
    signature = private_key.sign(
        signing_input.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    signature_b64 = b64url_encode(signature)
    return f"{signing_input}.{signature_b64}"

# Server or verifier checks signature using the public RSA key
def decode_rs256(token: str, public_key) -> dict:
    header_b64, payload_b64, signature_b64 = token.split('.')
    signing_input = f"{header_b64}.{payload_b64}"
    signature = b64url_decode(signature_b64)

    public_key.verify(
        signature,
        signing_input.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    return json.loads(b64url_decode(payload_b64))
