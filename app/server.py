"""Server skeleton — plain TCP; no TLS. See assignment spec."""

#!/usr/bin/env python3
"""
Server: certificate exchange, verification, and DH session-key establishment.

Usage:
  python3 server/server.py --bind 0.0.0.0 --port 12345 --expect-client-cn client1

Environment:
  CA_CERT, SERVER_CERT, SERVER_KEY loaded from .env via python-dotenv
"""
import os
import socket
import json
import struct
import argparse
import base64
from datetime import datetime, timezone
from dotenv import load_dotenv

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asympadding
from cryptography.hazmat.primitives.asymmetric import rsa

# RFC 3526 group 14 (2048-bit MODP) as integer (hex trimmed for readability)
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
SERVER_CERT_PATH = os.getenv("SERVER_CERT")
SERVER_KEY_PATH = os.getenv("SERVER_KEY")

if not (CA_CERT_PATH and SERVER_CERT_PATH and SERVER_KEY_PATH):
    raise RuntimeError("Please set CA_CERT, SERVER_CERT, SERVER_KEY in your .env")


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

    # 1) signature: verify cert.signature over cert.tbs_certificate_bytes using CA public key
    ca_pub = ca_cert.public_key()
    sig = cert.signature
    tbs = cert.tbs_certificate_bytes
    sig_hash_alg = cert.signature_hash_algorithm
    try:
        ca_pub.verify(sig, tbs, asympadding.PKCS1v15(), sig_hash_alg)
    except Exception as e:
        raise ValueError(f"certificate signature verification failed: {e}")

    # 2) validity period
    now = datetime.now(timezone.utc)
    if cert.not_valid_before.replace(tzinfo=timezone.utc) > now:
        raise ValueError("certificate not valid yet")
    if cert.not_valid_after.replace(tzinfo=timezone.utc) < now:
        raise ValueError("certificate expired")

    # 3) CN check if expected provided
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = None

    if expected_cn is not None:
        if cn != expected_cn:
            raise ValueError(f"common name mismatch: expected='{expected_cn}' got='{cn}'")

    # success, return parsed cert and CN
    return cert, cn

def generate_dh_private(p=P):
    # pick a random private in [2, p-2]
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)  # placeholder RNG not used below

def dh_generate_private_int():
    # use secrets.randbelow for private exponent
    import secrets
    return secrets.randbelow(P - 2) + 2

def dh_public_from_private(a: int):
    return pow(G, a, P)

def derive_aes_key_from_ks(ks_int: int) -> bytes:
    import hashlib
    ks_bytes = ks_int.to_bytes((ks_int.bit_length() + 7) // 8, "big")
    h = hashlib.sha256(ks_bytes).digest()
    return h[:16]

# Server main
def handle_connection(conn: socket.socket, addr, expect_client_cn: str):
    print(f"connection from {addr}")

    # 1) Receive client's hello (contains client's cert)
    try:
        msg = recv_msg(conn)
    except Exception as e:
        print("failed to receive hello:", e)
        conn.close()
        return

    if msg.get("type") != "hello" or "cert" not in msg:
        print("bad hello from client")
        send_msg(conn, {"type": "error", "reason": "bad hello"})
        conn.close()
        return

    client_cert_pem = msg["cert"]
    # load CA and server certs
    ca_cert = load_pem_cert(CA_CERT_PATH)
    server_cert = load_pem_cert(SERVER_CERT_PATH)
    server_key = load_pem_private_key(SERVER_KEY_PATH)

    # 2) Send server hello (server cert)
    send_msg(conn, {"type": "hello", "cert": pem_from_cert(server_cert)})

    # 3) Verify client cert
    try:
        client_cert_obj, client_cn = verify_cert_signed_by_ca(client_cert_pem, ca_cert, expected_cn=expect_client_cn)
    except ValueError as e:
        print("BAD CERT from client:", e)
        send_msg(conn, {"type": "BAD_CERT", "reason": str(e)})
        conn.close()
        return

    print(f"Client certificate OK. CN={client_cn}")

    # 4) DH: receive A from client, send B
    try:
        dh_msg = recv_msg(conn)
    except Exception as e:
        print("failed to receive DH A:", e)
        conn.close()
        return

    if dh_msg.get("type") != "dh" or "A" not in dh_msg:
        print("bad dh message")
        conn.close()
        return

    A_str = dh_msg["A"]
    try:
        A = int(A_str)
    except Exception:
        print("invalid client DH public value")
        conn.close()
        return

    # server picks b
    b = dh_generate_private_int()
    B = dh_public_from_private(b)

    # send B
    send_msg(conn, {"type": "dh", "B": str(B)})

    # compute shared secret ks = A^b mod p
    Ks = pow(A, b, P)
    key = derive_aes_key_from_ks(Ks)
    print(f"Derived AES-128 session key (hex): {key.hex()}")

    # handshake complete
    send_msg(conn, {"type": "ok", "msg": "handshake complete"})
    conn.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=12345)
    parser.add_argument("--expect-client-cn", default="client1",
                        help="expected client certificate CN (optional)")
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((args.bind, args.port))
        s.listen(1)
        print(f"Listening on {args.bind}:{args.port} ...")
        while True:
            conn, addr = s.accept()
            handle_connection(conn, addr, expect_client_cn=args.expect_client_cn)


if __name__ == "__main__":
    main()