# Entry 1

What: Created src/crypto/aes_cipher.py with one function, derive_key. It takes the key text and the wanted size (128 or 256 bits) and returns key bytes.
How: First it checks that the size is 128 or 256. Then it turns the text into bytes, hashes them with SHA-256 (always 32 bytes), and cuts the result to 16 bytes if 128 bits was asked.
Why: Hashing makes any typed key fit the exact length AES needs (16 or 32 bytes).
Result: The function exists but has no tests. If the size is wrong (like 192), it prints a message and returns nothing instead of raising an error.
Next: Fix derive_key to raise an error on a bad size.


# Entry 2

What: Fixed derive_key and wrote the first pytest tests for it.
How: Removed the two print() calls and the unused imports (os, dataclass). Replaced the silent return on a bad key size with raise ValueError so the caller gets a real error message instead of None. Added pytest to requirements.txt because it was missing. Wrote five tests: 256-bit key returns 32 bytes, 128-bit key returns 16 bytes, invalid size raises ValueError, same input always gives same output, empty string key does not crash.
Why: A library function must be silent when it works and loud when it fails. Returning None on a bad input is dangerous — the caller gets a value and does not know something went wrong. Tests exist so that if I change the function later I know immediately if I broke it.
Result: All 5 tests pass. PR #1 merged into develop.
Next: Write the actual AES encrypt and decrypt functions, and make the client sample test pass.

