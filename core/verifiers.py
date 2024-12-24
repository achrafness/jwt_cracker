from abc import ABC, abstractmethod
import base64
import hmac
import hashlib
import logging
from functools import lru_cache
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key

logger = logging.getLogger(__name__)

class BaseVerifier(ABC):
    """Base class for signature verification"""
    
    def __init__(self, jwt_components):
        self.components = jwt_components
        self.message = f"{jwt_components.header}.{jwt_components.payload}".encode()

    @abstractmethod
    def verify(self, secret: str) -> bool:
        """Verify signature with given secret"""
        pass

    @staticmethod
    def base64_url_decode(data: str) -> bytes:
        """Decode base64url-encoded string"""
        padding = '=' * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding)

class HMACVerifier(BaseVerifier):
    """HMAC signature verification"""
    
    HASH_ALGORITHMS = {
        'HS256': hashlib.sha256,
        'HS384': hashlib.sha384,
        'HS512': hashlib.sha512
    }

    @lru_cache(maxsize=1024)
    def verify(self, secret: str) -> bool:
        try:
            hash_func = self.HASH_ALGORITHMS[self.components.algorithm]
            signature = hmac.new(
                secret.encode(),
                self.message,
                hash_func
            ).digest()
            return base64.urlsafe_b64encode(signature).rstrip(b'=').decode() == self.components.signature
        except Exception:
            return False

class RSAVerifier(BaseVerifier):
    """RSA signature verification"""
    
    HASH_ALGORITHMS = {
        'RS256': hashes.SHA256(),
        'RS384': hashes.SHA384(),
        'RS512': hashes.SHA512(),
        'PS256': hashes.SHA256(),
        'PS384': hashes.SHA384(),
        'PS512': hashes.SHA512()
    }

    def verify(self, public_key_pem: str) -> bool:
        try:
            key = load_pem_public_key(public_key_pem.encode())
            signature = self.base64_url_decode(self.components.signature)

            pad = padding.PSS(
                mgf=padding.MGF1(self.HASH_ALGORITHMS[self.components.algorithm]),
                salt_length=padding.PSS.MAX_LENGTH
            ) if self.components.algorithm.startswith('PS') else padding.PKCS1v15()

            key.verify(
                signature,
                self.message,
                pad,
                self.HASH_ALGORITHMS[self.components.algorithm]
            )
            return True
        except Exception as e:
            logger.debug(f"RSA verification failed: {str(e)}")
            return False

class ECDSAVerifier(BaseVerifier):
    """ECDSA signature verification"""
    
    HASH_ALGORITHMS = {
        'ES256': hashes.SHA256(),
        'ES384': hashes.SHA384(),
        'ES512': hashes.SHA512()
    }

    def verify(self, public_key_pem: str) -> bool:
        try:
            key = load_pem_public_key(public_key_pem.encode())
            signature = self.base64_url_decode(self.components.signature)

            key.verify(
                signature,
                self.message,
                ec.ECDSA(self.HASH_ALGORITHMS[self.components.algorithm])
            )
            return True
        except Exception as e:
            logger.debug(f"ECDSA verification failed: {str(e)}")
            return False

class SignatureVerifier:
    """Factory class for signature verification"""
    
    @staticmethod
    def create(jwt_components) -> BaseVerifier:
        """Create appropriate verifier based on algorithm"""
        if jwt_components.algorithm.startswith('HS'):
            return HMACVerifier(jwt_components)
        elif jwt_components.algorithm.startswith(('RS', 'PS')):
            return RSAVerifier(jwt_components)
        elif jwt_components.algorithm.startswith('ES'):
            return ECDSAVerifier(jwt_components)
        raise ValueError(f"Unsupported algorithm: {jwt_components.algorithm}")