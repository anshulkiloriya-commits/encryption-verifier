import pytest
from src.crypto.aes_cipher import derive_key



def test_derive_key_256_returns_32_bytes ():
    
    result = derive_key("hello world",256)
    
    assert isinstance(result,bytes)
    assert len(result) == 32
    
def test_derive_key_128_return_16_bytes ():
    
    result = derive_key("hello world",128)
    
    assert isinstance(result, bytes)
    assert len(result) == 16

def test_invalid_key_length_raises_value_error ():
    with pytest.raises(ValueError):
        derive_key("testing_phasing",512)
        
def test_determinism ():
    result1 = derive_key("raj",256)
    result2 = derive_key("raj",256)
    
    assert  result1 == result2

def test_empty_string_key ():
    result = derive_key("",256)
    
    assert isinstance(result,bytes)
    assert len(result) == 32