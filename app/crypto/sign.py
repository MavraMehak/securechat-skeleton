"""RSA PKCS#1 v1.5 SHA-256 sign/verify.""" 
#!/usr/bin/env python3
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asympadding

def sign_bytes_rsa(private_key, message_bytes: bytes) -> str:
    """
    Sign message_bytes using RSA PKCS#1 v1.5 with SHA-256.
    Return base64 signature string.
    """
    sig = private_key.sign(
        message_bytes,
        asympadding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode()

def verify_sig_rsa(public_key, message_bytes: bytes, sig_b64: str) -> bool:
    import base64
    sig = base64.b64decode(sig_b64)
    try:
        public_key.verify(sig, message_bytes, asympadding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
