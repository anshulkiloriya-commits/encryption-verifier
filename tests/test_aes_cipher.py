
import base64
import pytest
from src.crypto.aes_cipher import derive_key, encrypt_aes



def test_encrypt_returns_ciphertext_and_iv():
    result = encrypt_aes("hello world", "my secret")

    assert "ciphertext" in result
    assert "iv" in result


def test_encrypt_returns_valid_base64():
    result = encrypt_aes("hello world", "my secret")

    ciphertext = base64.b64decode(result["ciphertext"], validate=True)
    iv = base64.b64decode(result["iv"], validate=True)

    assert len(ciphertext) > 0
    assert len(iv) == 16


def test_encrypt_uses_given_iv():
    iv = bytes(16)

    result = encrypt_aes("hello world", "my secret", iv=iv)

    assert base64.b64decode(result["iv"]) == iv


def test_raw_key_must_be_32_bytes():
    with pytest.raises(ValueError):
        encrypt_aes("hello world", "short", key_mode="raw")


def test_iv_must_be_16_bytes():
    with pytest.raises(ValueError):
        encrypt_aes("hello world", "my secret", iv=b"short")


def test_same_input_and_iv_give_same_ciphertext():
    iv = bytes(16)

    first = encrypt_aes("hello world", "my secret", iv=iv)
    second = encrypt_aes("hello world", "my secret", iv=iv)

    assert first["ciphertext"] == second["ciphertext"]


def test_derive_key_256_returns_32_bytes():
    result = derive_key("hello world", 256)
    assert isinstance(result, bytes)
    assert len(result) == 32


def test_derive_key_128_returns_16_bytes():
    result = derive_key("hello world", 128)
    assert isinstance(result, bytes)
    assert len(result) == 16


def test_invalid_key_length_raises_value_error():
    with pytest.raises(ValueError):
        derive_key("testing_phasing", 512)


def test_derive_key_is_deterministic():
    result1 = derive_key("raj", 256)
    result2 = derive_key("raj", 256)
    assert result1 == result2


def test_empty_string_key():
    result = derive_key("", 256)
    assert isinstance(result, bytes)
    assert len(result) == 32