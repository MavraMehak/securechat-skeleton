"""Server skeleton — plain TCP; no TLS. See assignment spec."""

#!/usr/bin/env python3
"""
Server: certificate exchange, verification, and DH session-key establishment.

Usage:
  python -m app.server --bind 0.0.0.0 --port 12345 --expect-client-cn client1

Environment:
  CA_CERT, SERVER_CERT, SERVER_KEY loaded from .env via python-dotenv
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
import hmac
import hashlib
from datetime import datetime, timezone
from dotenv import load_dotenv

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asympadding

# local modules
from app.storage import db as db_mod
from app.storage import transcript
from app.crypto.aes import aes_encrypt, aes_decrypt
from app.crypto.sign import sign_bytes_rsa, verify_sig_rsa
from app.crypto.dh import generate_private, compute_public, compute_shared, derive_aes_key

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
SERVER_CERT_PATH = os.getenv("SERVER_CERT")
SERVER_KEY_PATH = os.getenv("SERVER_KEY")

if not (CA_CERT_PATH and SERVER_CERT_PATH and SERVER_KEY_PATH):
    raise RuntimeError("Please set CA_CERT, SERVER_CERT, SERVER_KEY in your .env")

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

    # validity 
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

# Connection handler
def handle_connection(conn: socket.socket, addr, expect_client_cn: str):
    """
    Full connection lifecycle: cert exchange+validation, DH, encrypted auth (register/login),
    then encrypted chat with signatures and transcript receipt.
    """
    print(f" connection from {addr}")
    try:
        # 1. Receive hello
        msg = recv_msg(conn)
        if msg.get("type") != "hello" or "client_cert" not in msg:
            send_msg(conn, {"type": "error", "reason": "bad hello"})
            return
        client_cert_pem = msg["client_cert"]

        ca_cert = load_pem_cert(CA_CERT_PATH)
        server_cert = load_pem_cert(SERVER_CERT_PATH)
        server_key = load_pem_private_key(SERVER_KEY_PATH)

        # 2. Send server_hello
        nonce_server = secrets.token_bytes(16).hex()
        send_msg(conn, {
            "type": "server_hello",
            "cert": pem_from_cert(server_cert),
            "nonce": nonce_server
        })

        # 3. Verify client cert
        try:
            client_cert_obj, client_cn = verify_cert_signed_by_ca(client_cert_pem, ca_cert, expect_client_cn)
        except ValueError as e:
            send_msg(conn, {"type": "BAD_CERT", "reason": str(e)})
            return
        print(f"Client OK: {client_cn}")

        # 4. Control DH
        dh_msg = recv_msg(conn)
        if dh_msg.get("type") != "dh_client":
            return
        A_ctrl = dh_msg["A"]
        b_ctrl = generate_private()
        B_ctrl = compute_public(b_ctrl)
        send_msg(conn, {"type": "dh_server", "B": B_ctrl})
        control_key = derive_aes_key(compute_shared(b_ctrl, A_ctrl))

        # 5. Receive auth
        auth_msg = recv_msg(conn)
        mode = auth_msg["type"]
        if mode not in ("register", "login"):
            send_msg(conn, {"status": "error", "reason": "invalid auth type"})
            return

        try:
            pt = aes_decrypt(control_key, auth_msg["iv"], auth_msg["ct"])
            payload = json.loads(pt.decode())
        except:
            send_msg(conn, {"status": "error", "reason": "decrypt failed"})
            return

        db_mod.init_db()
        if mode == "register":
            salt = secrets.token_bytes(16)
            pwd_hash = hashlib.sha256(salt + payload["password"].encode()).hexdigest()
            if not db_mod.register_user(payload["email"], payload["username"], pwd_hash, salt):
                send_msg(conn, {"status": "error", "reason": "user exists"})
                return
        else:  # login
            user = db_mod.get_user_by_username_or_email(payload["identifier"])
            if not user or not hmac.compare_digest(
                user["pwd_hash"],
                hashlib.sha256(user["salt"] + payload["password"].encode()).hexdigest()
            ):
                send_msg(conn, {"status": "error", "reason": "invalid creds"})
                return

        send_msg(conn, {"status": "ok", "msg": f"{mode} success"})

        # 6. Session DH
        dh_msg = recv_msg(conn)
        if dh_msg.get("type") != "dh_client":
            return
        A_sess = dh_msg["A"]
        b_sess = generate_private()
        B_sess = compute_public(b_sess)
        send_msg(conn, {"type": "dh_server", "B": B_sess})
        session_key = derive_aes_key(compute_shared(b_sess, A_sess))
        
        # Prepare chat context 
        
        # our and peer cert bytes
        our_cert_bytes = server_cert.public_bytes(serialization.Encoding.PEM)
        peer_cert_bytes = client_cert_obj.public_bytes(serialization.Encoding.PEM)

        peer_cert_obj = client_cert_obj
        our_private_key = server_key

        # session transcript name
        def _safe_name(x: str) -> str:
            return x.replace("=", "_").replace(",", "_").replace(" ", "_")
        session_name = f"server_with_{_safe_name(peer_cert_obj.subject.rfc4514_string())}"

        # sequence counters (per-connection)
        send_seq = 0
        last_recv_seq = -1  # accept first incoming seq == 0

        def send_chat_server(plaintext_str: str):
            nonlocal send_seq
            ts = int(time.time() * 1000) # timestamp in ms
            iv_b64, ct_b64 = aes_encrypt(session_key, plaintext_str.encode("utf-8"))
            seq_bytes = send_seq.to_bytes(8, "big")
            ts_bytes = int(ts).to_bytes(8, "big")
            ct_bytes = base64.b64decode(ct_b64)
            msg_bytes = seq_bytes + ts_bytes + ct_bytes
            sig_b64 = sign_bytes_rsa(our_private_key, msg_bytes)
            send_msg(conn, {
                "type": "msg",
                "seqno": send_seq,
                "ts": ts,
                "iv": iv_b64,
                "ct": ct_b64,
                "sig": sig_b64
            })
            # append transcript: for sent messages, record SENDER fingerprint (our cert)
            transcript.append_line(session_name, send_seq, ts, ct_b64, sig_b64, our_cert_bytes)
            send_seq += 1

        def recv_loop_server():
            nonlocal last_recv_seq
            try:
                while True:
                    m = recv_msg(conn)
                    if m.get("type") == "msg":
                        seq = int(m["seqno"])
                        ts = int(m["ts"])
                        iv_b64 = m.get("iv")
                        ct_b64 = m.get("ct")
                        sig_b64 = m.get("sig")

                        # enforce strictly increasing seqno (reject replay or duplicate)
                        if seq <= last_recv_seq:
                            print("[!] REPLAY DETECTED from client seq", seq)
                            continue

                        # verify signature: sign input seq||ts||ct (ct raw bytes)
                        ct_bytes = base64.b64decode(ct_b64)
                        seq_bytes = seq.to_bytes(8, "big")
                        ts_bytes = int(ts).to_bytes(8, "big")
                        msg_bytes = seq_bytes + ts_bytes + ct_bytes

                        pub = peer_cert_obj.public_key()
                        try:
                            sig_bytes = base64.b64decode(sig_b64)
                            sig_bytes = sig_bytes[:-1] + b'\xFF'  # corrupt last byte
                            sig_b64_corrupted = base64.b64encode(sig_bytes).decode()
                        except:
                            sig_b64_corrupted = sig_b64 + "A"  # fallback

                        ok = verify_sig_rsa(pub, msg_bytes, sig_b64_corrupted)
                        if not ok:
                            print("[!] SIG FAIL for incoming message")
                            continue

                        # decrypt using iv
                        try:
                            plaintext = aes_decrypt(session_key, iv_b64, ct_b64)
                        except Exception as e:
                            print("[!] AES decrypt failed:", e)
                            continue

                        # append transcript: for received messages, record SENDER fingerprint (peer cert)
                        transcript.append_line(session_name, seq, ts, ct_b64, sig_b64, peer_cert_bytes)
                        last_recv_seq = seq

                        # print message to console
                        try:
                            print(f"[client @ {ts}] {plaintext.decode('utf-8')}")
                        except Exception:
                            print("[client] (non-text message)")

                    elif m.get("type") == "receipt":
                        print(" Received receipt from client:", m)
                    else:
                        # quiet about control messages
                        pass

            except ConnectionError:
                print(" Connection closed by client.")
            except Exception as e:
                print(" receive loop ended:", e)

        # start receiver thread
        recv_thread = threading.Thread(target=recv_loop_server, daemon=True)
        recv_thread.start()

        print(" Chat ready. Type messages to send to client. Type '/quit' to close session.")
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
                send_chat_server(line)
        finally:
            # create and send receipt on exit
            first_seq = 0
            last_seq_val = send_seq - 1 if send_seq > 0 else 0
            receipt = transcript.create_receipt(session_name, "server", first_seq, last_seq_val, our_private_key)
            send_msg(conn, receipt)
            print(" SessionReceipt sent. Closing connection.")
            try:
                conn.close()
            except Exception:
                pass

    except Exception as e:
        print(" connection handler error:", e)
        try:
            conn.close()
        except Exception:
            pass


# Server main loop
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=12345)
    parser.add_argument("--expect-client-cn", default="client1",
                        help="expected client certificate CN (optional)")
    args = parser.parse_args()

    # ensure DB is ready
    try:
        db_mod.init_db()
    except Exception:
        pass

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((args.bind, args.port))
        s.listen(1)
        print(f" Listening on {args.bind}:{args.port} ...")
        while True:
            conn, addr = s.accept()
            # handle one connection at a time
            handle_connection(conn, addr, expect_client_cn=args.expect_client_cn)


if __name__ == "__main__":
    main()
