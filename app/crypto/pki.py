"""X.509 validation: signed-by-CA, validity window, CN/SAN.""" 
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone

def load_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()

def verify_cert_chain(cert: x509.Certificate, ca_cert: x509.Certificate, expected_cn: str = None) -> str:
    # Verify signature
    ca_pub = ca_cert.public_key()
    ca_pub.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding=serialization.PKCS1v15(),
        algorithm=cert.signature_hash_algorithm
    )

    # Check validity
    now = datetime.now(timezone.utc)
    if cert.not_valid_before_utc > now:
        raise ValueError("Certificate not yet valid")
    if cert.not_valid_after_utc < now:
        raise ValueError("Certificate expired")

    # Extract CN
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    if expected_cn and cn != expected_cn:
        raise ValueError(f"CN mismatch: expected {expected_cn}, got {cn}")

    return cn