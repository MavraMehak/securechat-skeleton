"""Create Root CA (RSA + self-signed X.509) using cryptography.""" 

#!/usr/bin/env python3
import os
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa


CERTS_DIR = os.path.join(os.path.dirname(__file__), "..", "certs")
CA_KEY_PATH = os.path.join(CERTS_DIR, "ca.key.pem")
CA_CERT_PATH = os.path.join(CERTS_DIR, "ca.cert.pem")


def main():
    os.makedirs(CERTS_DIR, exist_ok=True)

    if os.path.exists(CA_KEY_PATH) or os.path.exists(CA_CERT_PATH):
        print("CA already exists.")
        return

    print("Generating CA private key (RSA 2048-bit)...")
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    print("Creating self-signed CA certificate...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
    ])
    
    now = datetime.now(timezone.utc)

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(
            now + timedelta(days=3650)
        )  # ~10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    print(f"Saving CA key -> {CA_KEY_PATH}")
    with open(CA_KEY_PATH, "wb") as f:
        f.write(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    print(f"Saving CA certificate -> {CA_CERT_PATH}")
    with open(CA_CERT_PATH, "wb") as f:
        f.write(
            ca_cert.public_bytes(
                encoding=serialization.Encoding.PEM
            )
        )

    print("\nCA generation complete!")
    print("Files created:")
    print(f"  - {CA_KEY_PATH}")
    print(f"  - {CA_CERT_PATH}")

    print("\nCertificate:")
    print(f"    Subject: {ca_cert.subject.rfc4514_string()}")
    print(f"    Issuer: {ca_cert.issuer.rfc4514_string()}")
    print(f"    Serial: {ca_cert.serial_number}")
    print(f"    Valid Until: {ca_cert.not_valid_after_utc.isoformat()}")


if __name__ == "__main__":
    main()
