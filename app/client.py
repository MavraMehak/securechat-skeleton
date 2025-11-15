"""Client skeleton — plain TCP; no TLS. See assignment spec."""

#!/usr/bin/env python3
"""
Client: certificate exchange, verification, and DH session-key establishment.

Usage:
  python3 client/client.py --host 127.0.0.1 --port 12345 --expect-server-cn server

Environment:
  CA_CERT, CLIENT_CERT, CLIENT_KEY loaded from .env via python-dotenv
"""
import os
import socket
import json
import struct
import argparse
from datetime import datetime, timezone
from dotenv import load_dotenv

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asympadding

# use same DH group as server
MODP_2048_HEX = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08
8A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576
625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFF
FFFFFFFF
""".replace("\n", "").replace(" ", "")

P = int(MODP_2048_HEX, 16)
G = 2

load_dotenv()
CA_CERT_PATH = os.getenv("CA_CERT")
CLIENT_CERT_PATH = os.getenv("CLIENT_CERT")
CLIENT_KEY_PATH = os.getenv("CLIENT_KEY")

if not (CA_CERT_PATH and CLIENT_CERT_PATH and CLIENT_KEY_PATH):
    raise RuntimeError("Please set CA_CERT, CLIENT_CERT, CLIENT_KEY in your .env")

# Wire helpers (length-prefix JSON)
def send_msg(conn: socket.socket, obj: dict):
    data = json.dumps(obj).encode("utf-8")
    conn.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(conn: socket.socket) -> dict:
    hdr = conn.recv(4)
    if not hdr or len(hdr) < 4:
        raise ConnectionError("Connection closed while reading length prefix")
    (l,) = struct.unpack(">I", hdr)
    data = b""
    while len(data) < l:
        chunk = conn.recv(l - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while reading payload")
        data += chunk
    return json.loads(data.decode("utf-8"))

# Cert utilities
def load_pem_cert(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_pem_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def pem_from_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

def verify_cert_signed_by_ca(cert_pem: str, ca_cert: x509.Certificate, expected_cn: str = None):
    """
    Verify cert signature (was signed by CA), validity period, and CN match (if expected_cn provided).
    Raises ValueError on verification failure.
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

    # 1) signature
    ca_pub = ca_cert.public_key()
    try:
        ca_pub.verify(cert.signature, cert.tbs_certificate_bytes, asympadding.PKCS1v15(), cert.signature_hash_algorithm)
    except Exception as e:
        raise ValueError(f"certificate signature verification failed: {e}")

    # 2) validity
    now = datetime.now(timezone.utc)
    if cert.not_valid_before.replace(tzinfo=timezone.utc) > now:
        raise ValueError("certificate not valid yet")
    if cert.not_valid_after.replace(tzinfo=timezone.utc) < now:
        raise ValueError("certificate expired")

    # 3) CN
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = None
    if expected_cn is not None:
        if cn != expected_cn:
            raise ValueError(f"common name mismatch: expected='{expected_cn}' got='{cn}'")

    return cert, cn

# DH utilities
def dh_generate_private_int():
    import secrets
    return secrets.randbelow(P - 2) + 2

def dh_public_from_private(a: int):
    return pow(G, a, P)

def derive_aes_key_from_ks(ks_int: int) -> bytes:
    import hashlib
    ks_bytes = ks_int.to_bytes((ks_int.bit_length() + 7) // 8, "big")
    h = hashlib.sha256(ks_bytes).digest()
    return h[:16]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=12345)
    parser.add_argument("--expect-server-cn", default="server",
                        help="expected server certificate CN (optional)")
    args = parser.parse_args()

    ca_cert = load_pem_cert(CA_CERT_PATH)
    client_cert = load_pem_cert(CLIENT_CERT_PATH)
    client_key = load_pem_private_key(CLIENT_KEY_PATH)

    with socket.create_connection((args.host, args.port)) as sock:
        # 1) send hello with client cert
        send_msg(sock, {"type": "hello", "cert": pem_from_cert(client_cert)})

        # 2) receive server hello
        try:
            msg = recv_msg(sock)
        except Exception as e:
            print(" failed to receive server hello:", e)
            return

        if msg.get("type") != "hello" or "cert" not in msg:
            print(" bad server hello")
            return

        server_cert_pem = msg["cert"]

        # 3) verify server cert
        try:
            server_cert_obj, server_cn = verify_cert_signed_by_ca(server_cert_pem, ca_cert, expected_cn=args.expect_server_cn)
        except ValueError as e:
            print(" BAD CERT from server:", e)
            # politely inform server? but server may have already closed
            return

        print(f"Server certificate OK. CN={server_cn}")

        # 4) DH: generate a, compute A and send
        a = dh_generate_private_int()
        A = dh_public_from_private(a)
        send_msg(sock, {"type": "dh", "A": str(A)})

        # receive B
        dh_msg = recv_msg(sock)
        if dh_msg.get("type") != "dh" or "B" not in dh_msg:
            print("bad DH response")
            return
        try:
            B = int(dh_msg["B"])
        except Exception:
            print("invalid DH B value")
            return

        Ks = pow(B, a, P)
        key = derive_aes_key_from_ks(Ks)
        print(f"Derived AES-128 session key (hex): {key.hex()}")

        # expect final ok
        final = recv_msg(sock)
        if final.get("type") == "ok":
            print("Handshake completed successfully.")
        else:
            print("Handshake ended unexpectedly:", final)

if __name__ == "__main__":
    main()
