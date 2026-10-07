Entry 1

What: Created src/crypto/aes_cipher.py with one function, derive_key. It takes the key text and the wanted size (128 or 256 bits) and returns key bytes.
How: First it checks that the size is 128 or 256. Then it turns the text into bytes, hashes them with SHA-256 (always 32 bytes), and cuts the result to 16 bytes if 128 bits was asked.
Why: Hashing makes any typed key fit the exact length AES needs (16 or 32 bytes).
Result: The function exists but has no tests. If the size is wrong (like 192), it prints a message and returns nothing instead of raising an error.
Next: Fix derive_key to raise an error on a bad size.

