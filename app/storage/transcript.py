"""Append-only transcript + TranscriptHash helpers.""" 
#!/usr/bin/env python3
import os
import hashlib
import json
from typing import Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asympadding

TRANSCRIPTS_DIR = os.getenv("TRANSCRIPTS_DIR", "transcripts")
os.makedirs(TRANSCRIPTS_DIR, exist_ok=True)


def _transcript_path(session_name: str) -> str:
    # session_name could be server_peer or client_peer + timestamp
    return os.path.join(TRANSCRIPTS_DIR, f"{session_name}.log")


def append_line(session_name: str, seqno: int, ts: int, ct_b64: str, sig_b64: str, peer_cert_bytes: bytes):
    """
    Append a single line to transcript file.
    """
    path = _transcript_path(session_name)
    fp_hex = hashlib.sha256(peer_cert_bytes).hexdigest()
    line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{fp_hex}\n"
    # append-only write
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)


def read_transcript_bytes(session_name: str) -> bytes:
    path = _transcript_path(session_name)
    with open(path, "rb") as f:
        return f.read()


def compute_transcript_hash(session_name: str) -> str:
    """
    Returns hex string of SHA256(transcript bytes)
    """
    data = read_transcript_bytes(session_name)
    return hashlib.sha256(data).hexdigest()


def sign_transcript_hash(session_name: str, signing_private_key) -> bytes:
    """
    Signs the transcript hash and returns raw signature bytes.
    signing_private_key: cryptography private key object (RSA)
    """
    th = compute_transcript_hash(session_name)
    th_bytes = bytes.fromhex(th)
    sig = signing_private_key.sign(
        th_bytes,
        asympadding.PKCS1v15(),
        hashes.SHA256()
    )
    return sig


def create_receipt(session_name: str, peer_role: str, first_seq: int, last_seq: int, signing_private_key) -> dict:
    """
    Build a SessionReceipt dict (not yet JSON-encoded). The signature is base64 in caller.
    """
    th = compute_transcript_hash(session_name)
    sig = sign_transcript_hash(session_name, signing_private_key)
    import base64
    receipt = {
        "type": "receipt",
        "peer": peer_role,             # "client" or "server" for who creates this receipt
        "first_seq": first_seq,
        "last_seq": last_seq,
        "transcript_sha256": th,
        "sig": base64.b64encode(sig).decode()
    }
    return receipt


def verify_transcript_receipt(session_name: str, receipt: dict, signer_cert) -> bool:
    """
    Verify receipt signature against transcript hash using signer's cert.
    signer_cert: cryptography.x509.Certificate loaded from the signer (the one who signed the transcript)
    """
    import base64
    sig_bytes = base64.b64decode(receipt["sig"])
    th_hex = receipt["transcript_sha256"]
    th_bytes = bytes.fromhex(th_hex)
    pub = signer_cert.public_key()
    try:
        pub.verify(sig_bytes, th_bytes, asympadding.PKCS1v15(), hashes.SHA256())
        # also verify that computed transcript hash matches
        computed = compute_transcript_hash(session_name)
        return computed == th_hex
    except Exception:
        return False
