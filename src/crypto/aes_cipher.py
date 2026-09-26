import os
# Used to generate cryptographically secure random bytes — needed for
# the IV (Initialization Vector) in AES-CBC mode.

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# Cipher     → the main object used to actually perform encryption/decryption
# algorithms → specifies which cipher algorithm to use (we'll use algorithms.AES)
# modes      → specifies the mode of operation (we'll use modes.CBC, with our IV)

from cryptography.hazmat.primitives import padding
# AES encrypts data in fixed-size 16-byte blocks. If our plaintext isn't
# an exact multiple of 16 bytes, we need to pad it before encrypting.
# padding.PKCS7 is the standard, widely-used padding scheme for this.

from cryptography.hazmat.primitives import hashes
# Used for SHA-256 hashing — this is how we derive a fixed-size AES key
# (16 or 32 bytes) from the user's arbitrary-length typed key text.
# https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/#sha-1

from dataclasses import dataclass
# Used to define a clean, named structure (AESResult) to return from
# our encryption function — instead of returning a plain unlabeled tuple.


def derive_key(key_text: str, key_length: int) -> bytes:
    """
    Converts a user-typed key (any length text) into a fixed-size
    byte key suitable for AES, using SHA-256.

    Args:
        key_text: the raw key string typed by the user
        key_length: desired AES key size in bits (128 or 256)

    Returns:
        bytes: 32 bytes for a 256-bit key, or 16 bytes for a 128-bit key
    """

    # --- Step 1: Validate the requested key length ---
    # AES only supports specific key sizes. We only support 128 and 256
    # here (matches what the PRD scoped for this project).
    if key_length == 128 or key_length == 256:
        print("Valid length")
    else:
        print("Invalid length")
        return

    # --- Step 2: Convert text to bytes ---
    # SHA-256 (and all crypto operations) work on raw bytes, not Python
    # strings, so we encode the text using UTF-8.
    data = key_text.encode("utf-8")

    # --- Step 3: Hash the key text using SHA-256 ---
    # This is the "create → feed → finalize" pattern used throughout
    # the cryptography library:
    #
    #   hashes.Hash(hashes.SHA256())  → CREATE a new hash object,
    #                                    telling it which algorithm to use
    #   digest.update(data)           → FEED the input bytes into the hash.
    #                                    Can be called multiple times if data
    #                                    arrives in chunks — here it's just once.
    #   digest.finalize()             → FINALIZE the hash and return the
    #                                    actual result as bytes. SHA-256
    #                                    always produces exactly 32 bytes,
    #                                    no matter how long the input was.
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    result = digest.finalize()

    # --- Step 4: Truncate if a 128-bit key was requested ---
    # SHA-256 always gives 32 bytes. For a 128-bit AES key, we only
    # need the first 16 of those bytes.
    if key_length == 128:
        result = result[:16]

    # --- Step 5: Return the derived key bytes ---
    return result