import hashlib

SHA3_224 = 'sha3_224'
SHA3_256 = 'sha3_256'
SHA3_384 = 'sha3_384'
SHA3_512 = 'sha3_512'


class HMAC:
    def __init__(self, hash_func = SHA3_512):
        """
        Hash-based message authentication code (HMAC) class for
        generating and verifying quantum-safe HMAC using SHA3 hash
        functions.

        This class implements the HMAC algorithm, utilizing SHA3
        family hash functions to provide message integrity and
        authenticity. It allows for the computation and verification
        of HMAC tags using various SHA3 hash functions.

        Possible hash functions:
            - 'sha3_224'
            - 'sha3_256'
            - 'sha3_384'
            - 'sha3_512'

        Args:
            hash_func (str): Hash function to use (default is 'sha3_512').

        Raises:
            ValueError: If an unsupported hash function identifier is provided.
        """
        self.hash_func = self._set_hash_function(hash_func)
        self.block_size = self.hash_func().block_size
    
    def _prepare_key(self, key):
        """
        Prepare the key for HMAC, hashing if too long and padding if too short.

        Args:
            key (bytes): The secret key.

        Returns:
            tuple: Prepared key, ipad, and opad for HMAC computation.
        """
        if len(key) > self.block_size:
            key = self.hash_func(key).digest()
            
        if len(key) < self.block_size:
            key = key + b'\x00' * (self.block_size - len(key))
        
        ipad = bytes((x ^ 0x36) for x in key)
        opad = bytes((x ^ 0x5c) for x in key)
        
        return ipad, opad
    
    @staticmethod
    def _set_hash_function(hash_func):
        """
        Select and return the appropriate hash function based on the specified identifier.

        This method maps the given hash function identifier (e.g., 'sha3_224',
        'sha3_256', etc.) to the corresponding hashing function from the
        `hashlib` module. It raises an exception if an unsupported hash function
        identifier is provided.

        Args:
            hash_func (str): The identifier of the hash function to select.

        Returns:
            callable: The corresponding hash function from the `hashlib` module.

        Raises:
            ValueError: If the provided hash function identifier is not supported.
        """
        if hash_func == SHA3_224:
            return hashlib.sha3_224
        
        elif hash_func == SHA3_256:
            return hashlib.sha3_256
        
        elif hash_func == SHA3_384:
            return hashlib.sha3_384
        
        elif hash_func == SHA3_512:
            return hashlib.sha3_512
        
        else:
            raise ValueError(f"Unsupported hash bit size: {hash_func.split('_')[-1]} | {hash_func}")
    
    @staticmethod
    def _check_input(key, data, tag = None):
        """
        Validate the types of the provided key, data, and tag.

        Args:
            key (bytes): The secret key for HMAC.
            data (bytes): The message to authenticate.
            tag (bytes, optional): The expected HMAC tag to verify against. Defaults to None.

        Raises:
            TypeError: If the key or data is not of type bytes, or if tag is provided and is not of type bytes.

        Returns:
            bool: Always returns True if all checks pass.
        """
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes. {type(key)}")
        
        if not isinstance(data, bytes):
            raise TypeError(f"Data must be bytes. {type(data)}")
        
        if tag is not None and not isinstance(tag, bytes):
            raise TypeError(f"Tag must be bytes. {type(tag)}")
        
        return True
    
    @staticmethod
    def _constant_time_compare(val1, val2):
        """
        Compare two byte sequences in constant time to avoid timing attacks.

        Args:
            val1 (bytes): First byte sequence.
            val2 (bytes): Second byte sequence.

        Returns:
            bool: True if both are equal, False otherwise.
        """
        if len(val1) != len(val2):
            return False
        
        result = 0
        for x, y in zip(val1, val2):
            result |= x ^ y
            
        return result == 0
    
    def _compute(self, key, data):
        """
        Compute the HMAC for the given data.

        Args:
            key (bytes): The secret key.
            data (bytes): The message to authenticate.

        Returns:
            bytes: The computed HMAC.
        """
        ipad, opad = self._prepare_key(key)
        inner = self.hash_func(ipad + data).digest()
        
        return self.hash_func(opad + inner).digest()
    
    def new(self, key, data):
        """
        Generate a new HMAC for the given data using the provided key.

        This method computes the HMAC of the input data by first
        verifying the types of the key and data and then computes
        the HMAC tag.

        Args:
            key (bytes): The secret key used for HMAC computation.
            data (bytes): The message for which the HMAC is being generated.

        Returns:
            bytes: The computed HMAC tag for the provided data.

        Raises:
            TypeError: If the key or data is not of type `bytes`.
        """
        self._check_input(key, data)
        return self._compute(key, data)
    
    def verify(self, key, data, tag):
        """
        Verify the HMAC tag for the given data.

        This method computes the HMAC for the provided data using the
        given key and compares it with the expected HMAC tag. The
        comparison is performed in constant time to prevent timing attacks.

        Args:
            key (bytes): The secret key used for HMAC computation.
            data (bytes): The message to authenticate.
            tag (bytes): The expected HMAC tag to verify against.

        Returns:
            bool: True if the computed HMAC matches the expected tag; False otherwise.

        Raises:
            TypeError: If the key, data, or tag is not of type `bytes`.
        """
        self._check_input(key, data, tag)
        computed_tag = self._compute(key, data)
        return self._constant_time_compare(computed_tag, tag)


if __name__ == "__main__":
    # Example: input
    _key = b'supersecretkey'
    _message = b'This is a quantum-safe message.'
    
    print("*" * 50)
    
    # Example: initialization
    _hmac = HMAC(SHA3_512)
    
    # Example: computing HMAC
    _value = _hmac.new(_key, _message)
    print("SHA3-512 HMAC:", len(_value), _value.hex())
    
    # Example: verifying HMAC
    is_valid = _hmac.verify(_key, _message, _value)
    print("Is the HMAC valid?", is_valid)
    
    # Example: verifying HMAC
    _message = b'This is a quantum-safe message but edited.'
    is_valid = _hmac.verify(_key, _message, _value)
    print("Is the HMAC valid?", is_valid)
    
    print("*" * 50)
