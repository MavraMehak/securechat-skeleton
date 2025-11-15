"""Issue server/client cert signed by Root CA (SAN=DNSName(CN)).""" 

#!/usr/bin/env python3
import os
import argparse
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa


BASE_DIR = os.path.dirname(__file__)
CERTS_DIR = os.path.join(BASE_DIR, "..", "certs")

CA_KEY_PATH = os.path.join(CERTS_DIR, "ca.key.pem")
CA_CERT_PATH = os.path.join(CERTS_DIR, "ca.cert.pem")


def load_ca():
    if not (os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH)):
        print("CA not found.")
        exit(1)

    # Load CA private key
    with open(CA_KEY_PATH, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # Load CA certificate
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    return ca_key, ca_cert


def generate_cert(cn):
    os.makedirs(CERTS_DIR, exist_ok=True)

    key_path = os.path.join(CERTS_DIR, f"{cn}.key.pem")
    cert_path = os.path.join(CERTS_DIR, f"{cn}.cert.pem")

    # Safety check
    if os.path.exists(key_path) or os.path.exists(cert_path):
        print(f"Certificate for '{cn}' already exists.")
        return

    print(f"Generating RSA private key for '{cn}'...")
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    ca_key, ca_cert = load_ca()

    print(f"Creating certificate for '{cn}' signed by CA...")

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650)) # ~10 years
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256()) # hash
    )

    print(f"Saving private key -> {key_path}")
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    print(f"Saving certificate -> {cert_path}")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("\nCertificate generation complete!")
    print("Files created:")
    print(f"  - {key_path}")
    print(f"  - {cert_path}")

    print("\nCertificate:")
    print(f"    Subject: {cert.subject.rfc4514_string()}")
    print(f"    Issuer: {cert.issuer.rfc4514_string()}")
    print(f"    Serial: {cert.serial_number}")
    print(f"    Valid From: {cert.not_valid_before_utc.isoformat()}")
    print(f"    Valid Until: {cert.not_valid_after_utc.isoformat()}")

def main():
    parser = argparse.ArgumentParser(description="Generate an end-entity certificate.")
    parser.add_argument("--cn", required=True, help="Common Name for certificate (e.g., 'server', 'client1')")
    args = parser.parse_args()

    generate_cert(args.cn)


if __name__ == "__main__":
    main()
