from pathlib import Path
from typing import TypeAlias

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

PublicKeyInput: TypeAlias = (
    RSAPublicKey
    | x509.Certificate
    | bytes
    | bytearray
    | memoryview
    | str
    | Path
)

PrivateKeyInput: TypeAlias = (
    RSAPrivateKey
    | bytes
    | bytearray
    | memoryview
    | str
    | Path
)


def _load_public_key_bytes(
    public_key_input: bytes | bytearray | memoryview | str | Path,
) -> bytes:
    if isinstance(public_key_input, (bytes, bytearray, memoryview)):
        return bytes(public_key_input)
    public_key_path = Path(public_key_input)
    if not public_key_path.is_file():
        raise FileNotFoundError(
            f"Public key/certificate file not found: {public_key_path}")
    return public_key_path.read_bytes()


def _public_key_from_cert(cert: x509.Certificate) -> RSAPublicKey:
    public_key = cert.public_key()
    if not isinstance(public_key, RSAPublicKey):
        raise TypeError("Certificate does not contain an RSA public key")
    
    print(f"[Cert] Certificate loaded")
    return public_key


def resolve_public_key(public_key_input: PublicKeyInput) -> RSAPublicKey:
    if isinstance(public_key_input, RSAPublicKey):
        return public_key_input
    if isinstance(public_key_input, x509.Certificate):
        return _public_key_from_cert(public_key_input)

    key_data = _load_public_key_bytes(public_key_input)
    if b"BEGIN CERTIFICATE" in key_data:
        cert = x509.load_pem_x509_certificate(key_data)
        return _public_key_from_cert(cert)
    if b"BEGIN PUBLIC KEY" in key_data or b"BEGIN RSA PUBLIC KEY" in key_data:
        public_key = serialization.load_pem_public_key(key_data)
        if not isinstance(public_key, RSAPublicKey):
            raise TypeError("Provided file is not an RSA public key")
        return public_key

    try:
        cert = x509.load_der_x509_certificate(key_data)
    except ValueError:
        public_key = serialization.load_der_public_key(key_data)
        if not isinstance(public_key, RSAPublicKey):
            raise TypeError("Provided file is not an RSA public key")
        return public_key

    return _public_key_from_cert(cert)


def _load_private_key_bytes(
    private_key_input: bytes | bytearray | memoryview | str | Path,
) -> bytes:
    if isinstance(private_key_input, (bytes, bytearray, memoryview)):
        return bytes(private_key_input)
    private_key_path = Path(private_key_input)
    if not private_key_path.is_file():
        raise FileNotFoundError(
            f"Private key file not found: {private_key_path}")
    return private_key_path.read_bytes()


def resolve_private_key(private_key_input: PrivateKeyInput) -> RSAPrivateKey:
    if isinstance(private_key_input, RSAPrivateKey):
        return private_key_input

    key_data = _load_private_key_bytes(private_key_input)
    if b"BEGIN" in key_data:
        if b"PRIVATE KEY" not in key_data:
            raise ValueError("Provided file does not contain a private key")
        if b"ENCRYPTED PRIVATE KEY" in key_data:
            raise ValueError("Encrypted private keys require a password")
        private_key = serialization.load_pem_private_key(key_data, password=None)
    else:
        private_key = serialization.load_der_private_key(key_data, password=None)

    if not isinstance(private_key, RSAPrivateKey):
        raise TypeError("Provided file is not an RSA private key")
    return private_key
