"""Client skeleton — plain TCP; no TLS. See assignment spec."""

#!/usr/bin/env python3
"""
Client: certificate exchange, verification, DH session-key establishment,
encrypted registration/login, encrypted chat with RSA signatures, and transcript receipts.

Usage:
  python -m app.client --host 127.0.0.1 --port 12345 --expect-server-cn server
"""

import os
import socket
import json
import struct
import argparse
import base64
import threading
import time
import secrets
from datetime import datetime, timezone
from dotenv import load_dotenv

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympadding

# local modules
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import sign_bytes_rsa, verify_sig_rsa
from app.crypto.dh import generate_private, compute_public, compute_shared, derive_aes_key
from app.storage import transcript
        

# DH group (2048-bit MODP) from RFC 3526 (group 14)
MODP_2048_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431"
    "B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42"
    "E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1"
    "FE649286651ECE45FFFFFFFFFFFFFFFF"
)

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
    cert = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

    # verify signature
    ca_pub = ca_cert.public_key()
    try:
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asympadding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except Exception as e:
        raise ValueError(f"certificate signature verification failed: {e}")

    # validity (use UTC properties)
    now = datetime.now(timezone.utc)
    if cert.not_valid_before_utc > now:
        raise ValueError("certificate not valid yet")
    if cert.not_valid_after_utc < now:
        raise ValueError("certificate expired")

    # CN
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = None
    if expected_cn is not None and cn != expected_cn:
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


# Client main

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
        # === 1. HELLO + NONCE ===
        nonce_client = secrets.token_bytes(16).hex()
        send_msg(sock, {
            "type": "hello",
            "client_cert": pem_from_cert(client_cert),
            "nonce": nonce_client
        })

        msg = recv_msg(sock)
        if msg.get("type") != "server_hello":
            print("Expected server_hello")
            return
        server_cert_pem = msg["cert"]
        nonce_server = msg.get("nonce")
        if not nonce_server:
            print("Missing server nonce")
            return

        try:
            server_cert_obj, server_cn = verify_cert_signed_by_ca(server_cert_pem, ca_cert, args.expect_server_cn)
        except ValueError as e:
            print("BAD CERT:", e)
            return
        print(f"Server cert OK: CN={server_cn}")

        # === 2. CONTROL PLANE DH ===
        a_ctrl = generate_private()
        A_ctrl = compute_public(a_ctrl)
        send_msg(sock, {
            "type": "dh_client",
            "g": G,
            "p": P,
            "A": A_ctrl
        })

        resp = recv_msg(sock)
        if resp.get("type") != "dh_server":
            print("Bad DH response")
            return
        B_ctrl = resp["B"]
        Ks_ctrl = compute_shared(a_ctrl, B_ctrl)
        control_key = derive_aes_key(Ks_ctrl)
        print(f"Control key: {control_key.hex()}")

        # === 3. REGISTER / LOGIN ===
        mode = input("register or login? ").strip().lower()
        if mode not in ("register", "login"):
            return

        if mode == "register":
            email = input("Email: ")
            username = input("Username: ")
            password = input("Password: ")
            payload = {"type": "register", "email": email, "username": username, "password": password}
        else:
            identifier = input("Username/Email: ")
            password = input("Password: ")
            payload = {"type": "login", "identifier": identifier, "password": password}

        pt = json.dumps(payload).encode()
        iv_b64, ct_b64 = aes_encrypt(control_key, pt)
        send_msg(sock, {"type": mode, "iv": iv_b64, "ct": ct_b64})

        resp = recv_msg(sock)
        if resp.get("status") != "ok":
            print("Auth failed:", resp)
            return
        print("Auth success!")

        # === 4. SESSION DH ===
        a_sess = generate_private()
        A_sess = compute_public(a_sess)
        send_msg(sock, {"type": "dh_client", "g": G, "p": P, "A": A_sess})

        resp = recv_msg(sock)
        if resp.get("type") != "dh_server":
            return
        B_sess = resp["B"]
        Ks_sess = compute_shared(a_sess, B_sess)
        session_key = derive_aes_key(Ks_sess)
        print(f"Session key: {session_key.hex()}")

         
         # Prepare chat context
        our_cert_bytes = client_cert.public_bytes(serialization.Encoding.PEM)
        peer_cert_bytes = server_cert_obj.public_bytes(serialization.Encoding.PEM)
        peer_cert_obj = server_cert_obj
        our_private_key = client_key

        # session transcript name
        def _safe_name(x: str) -> str:
            return x.replace("=", "_").replace(",", "_").replace(" ", "_")

        session_name = f"client_with_{_safe_name(peer_cert_obj.subject.rfc4514_string())}"

        # sequence counters
        send_seq = 0
        last_recv_seq = -1

        # nested helpers
        def send_chat(plaintext_str: str):
            nonlocal send_seq
            ts = int(time.time() * 1000)
            iv_b64, ct_b64 = aes_encrypt(session_key, plaintext_str.encode("utf-8"))
            seq_bytes = send_seq.to_bytes(8, "big")
            ts_bytes = int(ts).to_bytes(8, "big")
            ct_bytes = base64.b64decode(ct_b64)
            msg_bytes = seq_bytes + ts_bytes + ct_bytes
            sig_b64 = sign_bytes_rsa(our_private_key, msg_bytes)
            send_msg(sock, {
                "type": "msg",
                "seqno": send_seq,
                "ts": ts,
                "iv": iv_b64,
                "ct": ct_b64,
                "sig": sig_b64
            })
            # for sent messages store SENDER fingerprint (our cert)
            transcript.append_line(session_name, send_seq, ts, ct_b64, sig_b64, our_cert_bytes)
            send_seq += 1

        def recv_loop():
            nonlocal last_recv_seq
            try:
                while True:
                    m = recv_msg(sock)
                    if m.get("type") == "msg":
                        seq = int(m["seqno"])
                        ts = int(m["ts"])
                        iv_b64 = m.get("iv")
                        ct_b64 = m["ct"]
                        sig_b64 = m["sig"]

                        if seq <= last_recv_seq:
                            print(" REPLAY DETECTED: seq", seq)
                            continue

                        ct_bytes = base64.b64decode(ct_b64)
                        seq_bytes = seq.to_bytes(8, "big")
                        ts_bytes = int(ts).to_bytes(8, "big")
                        msg_bytes = seq_bytes + ts_bytes + ct_bytes

                        pub = peer_cert_obj.public_key()
                        ok = verify_sig_rsa(pub, msg_bytes, sig_b64)
                        if not ok:
                            print(" SIG FAIL for incoming message")
                            continue

                        try:
                            plaintext = aes_decrypt(session_key, iv_b64, ct_b64)
                        except Exception as e:
                            print(" AES decrypt failed:", e)
                            continue

                        # for received messages store SENDER fingerprint (peer cert)
                        transcript.append_line(session_name, seq, ts, ct_b64, sig_b64, peer_cert_bytes)
                        last_recv_seq = seq

                        try:
                            print(f"[server @ {ts}] {plaintext.decode('utf-8')}")
                        except Exception:
                            print("[server] (non-text message)")

                    elif m.get("type") == "receipt":
                        print(" Received receipt from server:", m)
                    else:
                        # ignore control messages
                        pass

            except ConnectionError:
                print(" Connection closed by server.")
            except Exception as e:
                print(" receive loop ended:", e)

        # start receiver thread
        recv_thread = threading.Thread(target=recv_loop, daemon=True)
        recv_thread.start()

        print(" You can now chat. Type messages and press Enter. Type '/quit' to exit.")
        try:
            while True:
                try:
                    line = input()
                except EOFError:
                    break
                if not line:
                    continue
                if line.strip() == "/quit":
                    break
                send_chat(line)
        finally:
            # create and send receipt on exit
            first_seq = 0
            last_seq_val = send_seq - 1 if send_seq > 0 else 0
            receipt = transcript.create_receipt(session_name, "client", first_seq, last_seq_val, our_private_key)
            send_msg(sock, receipt)
            print(" SessionReceipt sent. Closing.")
            try:
                sock.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
