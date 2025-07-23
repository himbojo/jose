import hmac
import hashlib
import json
from jwt_helpers import b64url_encode, b64url_decode, json_dumps

def encode_hs256(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json_dumps(header).encode())
    payload_b64 = b64url_encode(json_dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}"

    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    signature_b64 = b64url_encode(signature)

    return f"{signing_input}.{signature_b64}"

def decode_hs256(token: str, secret: str) -> dict:
    header_b64, payload_b64, signature_b64 = token.split('.')
    signing_input = f"{header_b64}.{payload_b64}"

    expected_sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(b64url_encode(expected_sig), signature_b64):
        raise ValueError("Invalid signature")

    return json.loads(b64url_decode(payload_b64))
