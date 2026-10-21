
import base64
import os

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def derive_key(key_text: str, key_length: int) -> bytes:
    """
    Convert key text into a 128-bit or 256-bit AES key using SHA-256.
    """

    if key_length not in (128, 256):
        raise ValueError(
            f"key_length must be 128 or 256, got {key_length}"
        )

    data = key_text.encode("utf-8")

    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    result = digest.finalize()

    if key_length == 128:
        result = result[:16]

    return result


def encrypt_aes(
    plaintext: str,
    key_text: str,
    key_mode: str = "derived",
    iv: bytes | None = None,
) -> dict[str, str]:
    """
    Encrypt text using AES-256-CBC with PKCS7 padding.

    key_mode:
        "raw"     - use the UTF-8 key bytes directly
        "derived" - derive a 256-bit key using SHA-256

    Returns Base64-encoded ciphertext and IV separately.
    """

    if key_mode == "raw":
        key = key_text.encode("utf-8")

        if len(key) != 32:
            raise ValueError("Raw AES-256 key must be exactly 32 bytes")

    elif key_mode == "derived":
        key = derive_key(key_text, 256)

    else:
        raise ValueError("key_mode must be 'raw' or 'derived'")

    if iv is None:
        iv = os.urandom(16)
    elif not isinstance(iv, bytes) or len(iv) != 16:
        raise ValueError("IV must be exactly 16 bytes")

    padder = padding.PKCS7(128).padder()
    padded_text = padder.update(plaintext.encode("utf-8"))
    padded_text += padder.finalize()

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    )

    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_text) + encryptor.finalize()

    return {
        "ciphertext": base64.b64encode(encrypted).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
    }
