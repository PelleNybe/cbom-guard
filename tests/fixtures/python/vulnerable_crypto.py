"""Intentionally vulnerable Python cryptography fixture for cbom-guard testing."""

import hashlib
import ssl

import ecdsa
import rsa as py_rsa
from Crypto.Cipher import DES3
from Crypto.PublicKey import RSA as PyCryptoRSA
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec
from cryptography.hazmat.primitives.asymmetric import rsa as cg_rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_keys() -> None:
    # Shor-vulnerable RSA-2048 via alias
    _rsa_key = cg_rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Weak RSA-1024 (triggers both PY-CRYPTO-001 and PY-CRYPTO-002)
    _weak_rsa = cg_rsa.generate_private_key(public_exponent=65537, key_size=1024)

    # Shor-vulnerable ECDSA, DSA, DH, Ed25519
    _ec_key = ec.generate_private_key(ec.SECP256R1())
    _dsa_key = dsa.generate_private_key(key_size=2048)
    _dh_params = dh.generate_parameters(generator=2, key_size=2048)
    _ed_key = Ed25519PrivateKey.generate()

    # PyCryptodome, python-rsa, python-ecdsa
    _pc_rsa = PyCryptoRSA.generate(2048)
    _des3 = DES3.new(b"1234567890123456", DES3.MODE_ECB)
    _pub, _priv = py_rsa.newkeys(2048)
    _sk = ecdsa.SigningKey.generate()


def legacy_hashes_and_tls() -> None:
    _h1 = hashlib.md5(b"legacy")
    _h2 = hashlib.sha1(b"legacy")
    _h3 = hashlib.new("md5", b"legacy")
    _h4 = hashes.Hash(hashes.SHA1())
    _ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
