
# Quantum-Safe HMAC with SHA3

This repository provides a Python implementation of a **Hash-based Message Authentication Code (HMAC)** algorithm using the **SHA3 family of hash functions**. The class ensures **quantum-safe** message integrity and authenticity, leveraging modern cryptographic standards.

## Features

- Supports SHA3 hash functions:
  - `SHA3_224`
  - `SHA3_256`
  - `SHA3_384`
  - `SHA3_512` (default)
- Prepares keys for HMAC securely with hashing and padding.
- Implements constant-time comparison to prevent timing attacks.
- Provides methods to generate and verify HMAC tags for given data.
- Suitable for applications requiring quantum-resistant cryptographic techniques.

## Requirements

- Python 3.6 or later

## Installation

No external libraries are required. Clone the repository and use the `HMAC` class directly in your project.

```bash
git clone https://github.com/Vrexira/hmac.git
```

## Usage

### Example: Generating and Verifying HMAC

```python
from hmac import HMAC, SHA3_512

# Key and message
key = b'supersecretkey'
message = b'This is a quantum-safe message.'

# Initialize HMAC with SHA3-512
hmac = HMAC(SHA3_512)

# Generate HMAC
hmac_tag = hmac.new(key, message)
print("SHA3-512 HMAC:", hmac_tag.hex())

# Verify HMAC
is_valid = hmac.verify(key, message, hmac_tag)
print("Is the HMAC valid?", is_valid)

# Tampered message
tampered_message = b'This message has been tampered with.'
is_valid = hmac.verify(key, tampered_message, hmac_tag)
print("Is the HMAC valid after tampering?", is_valid)
```

### Output

```
SHA3-512 HMAC: 64 bytes (hexadecimal string)
Is the HMAC valid? True
Is the HMAC valid after tampering? False
```

## API Reference

### Init: `HMAC(hash_func)`
Initializes the HMAC class with the specified SHA3 hash function.

- `hash_func` (str): The hash function to use (`SHA3_224`, `SHA3_256`, `SHA3_384`, `SHA3_512`). Defaults to `SHA3_512`.

### New: `new(key, data)`
Generates an HMAC tag for the given data.

- `key` (bytes): The secret key.
- `data` (bytes): The message to authenticate.

**Returns:** HMAC tag as bytes.

### Verify: `verify(key, data, tag)`
Verifies the HMAC tag for the given data.

- `key` (bytes): The secret key.
- `data` (bytes): The message to authenticate.
- `tag` (bytes): The expected HMAC tag.

**Returns:** `True` if the tag is valid, `False` otherwise.

## Key Validation
Keys longer than the hash block size are hashed. Keys shorter than the block size are padded with zero bytes.

## Security Features
- Inner and outer padding (`ipad`, `opad`) are securely prepared.
- HMAC comparison is performed in constant time to mitigate timing attacks.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

1. Fork the repository.
2. Create a new feature branch.
3. Commit your changes.
4. Submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.