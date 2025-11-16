"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation.""" 
from typing import Tuple
import secrets

# RFC 3526 Group 14 (2048-bit)
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45FFFFFFFFFFFFFFFF", 16)
G = 2

def generate_private() -> int:
    import secrets
    return secrets.randbelow(P - 2) + 2

def compute_public(priv: int) -> int:
    return pow(G, priv, P)

def compute_shared(priv: int, peer_pub: int) -> int:
    return pow(peer_pub, priv, P)

def derive_aes_key(shared: int) -> bytes:
    import hashlib
    shared_bytes = shared.to_bytes((shared.bit_length() + 7) // 8, "big")
    return hashlib.sha256(shared_bytes).digest()[:16]


