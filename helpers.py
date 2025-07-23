import base64
import json

# Base64url encoding (URL-safe Base64 without padding)
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

# Base64url decoding (adds padding if missing)
def b64url_decode(data: str) -> bytes:
    padding = '=' * (4 - len(data) % 4) if len(data) % 4 != 0 else ''
    return base64.urlsafe_b64decode(data + padding)

# Canonical JSON encoding: compact and key-sorted
def json_dumps(data) -> str:
    return json.dumps(data, separators=(',', ':'), sort_keys=True)
