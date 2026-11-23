"""Safe Python fixture that must produce ZERO critical/warning findings."""

import hashlib
import ssl

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CustomRSA:
    """User-defined class with same method names as cryptography, but no crypto import."""

    @staticmethod
    def generate_private_key(key_size: int = 2048) -> str:
        return f"mock-{key_size}"


def safe_operations() -> None:
    # Comments and strings mentioning vulnerable algorithms must NOT trigger AST rules:
    # rsa.generate_private_key(public_exponent=65537, key_size=1024)
    # hashlib.md5(b"never executed")
    note = "We migrated away from hashlib.sha1 and RSA-2048 to ML-KEM-768"
    _unused = note

    # Unrelated local function with colliding name (no cryptography.rsa imported)
    _fake = CustomRSA.generate_private_key(key_size=1024)

    # Safe hashing (SHA-384) and safe TLS 1.3
    _digest = hashlib.sha384(b"quantum-resilient").hexdigest()
    _dynamic_safe = hashlib.new("sha512", b"quantum-resilient").hexdigest()
    _ctx = ssl.create_default_context()
    _ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    # Safe AES-256-GCM (triggers only INFO rule PY-SAFE-001, zero warnings/criticals)
    key = AESGCM.generate_key(bit_length=256)
    _aes = AESGCM(key)
