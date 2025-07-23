from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from jwt_helpers import b64url_encode, b64url_decode, json_dumps
import json

# Sign payload using EC private key (P-256 curve + SHA-256)
# Used when compact size and compliance (FIPS, etc.) are important
def encode_es256(payload: dict, private_key) -> str:
    header = {"alg": "ES256", "typ": "JWT"}
    header_b64 = b64url_encode(json_dumps(header).encode())
    payload_b64 = b64url_encode(json_dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}"

    # Create DER signature (r, s) tuple
    signature = private_key.sign(
        signing_input.encode(),
        ec.ECDSA(hashes.SHA256())
    )

    # Convert (r, s) to raw format
    r, s = decode_dss_signature(signature)
    raw_signature = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    signature_b64 = b64url_encode(raw_signature)
    return f"{signing_input}.{signature_b64}"

# Server verifies signature using EC public key
def decode_es256(token: str, public_key) -> dict:
    header_b64, payload_b64, signature_b64 = token.split('.')
    signing_input = f"{header_b64}.{payload_b64}"
    raw = b64url_decode(signature_b64)

    r = int.from_bytes(raw[:32], 'big')
    s = int.from_bytes(raw[32:], 'big')
    der_sig = encode_dss_signature(r, s)

    public_key.verify(
        der_sig,
        signing_input.encode(),
        ec.ECDSA(hashes.SHA256())
    )

    return json.loads(b64url_decode(payload_b64))
