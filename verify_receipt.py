import base64
import hashlib
from app.crypto.sign import verify_sig_rsa
from cryptography import x509
import os

TRANSCRIPT_FILE = "transcripts/client_with_CN_server_O_FAST_L_Islamabad_ST_Punjab_C_PK.log"  # ← CHANGE IF NEEDED
CERT_FILE = "certs/client1.cert.pem"

# paste from terminal
transcript_hash = "b277dc0ef89fff95e3a2f659378d7d2fd3c786b35d4ef7ad1ceaeb7bdd886288"
sig_b64 = "HeBnT3rS1l2CEteJSoQy5xKOKbaYzSMzHYGBpRRolhf0+wKz0CY22Vhe7e97yxuNoBp+IYM9jPtraXXPVkTH9z+plihj35wRmNfVG9INwujsd+d6Wf9OdDRwcpQ6cdT893CWl9jGUcCG1lgWtnslyaCQyuVuXSAtKMc8u8VBK8oxWZ5f3CbaiTbg6ahUXLTXnvPndmHUte8siVRvwlUyxgmljhCifgECK5znksGePOkUwThZm5CN/BkQPrNqHgsW4HxFLY9HGdxLfdSguHa7s0xQGm5RNq5/fPinj0qk4IiVXOVOD/i8Ij1BJKWg09MgoLF0bbfsVIY/f5K4LNyfyQ=="
first_seq = 0
last_seq = 2

# compute sha256 and match
if not os.path.exists(TRANSCRIPT_FILE):
    print(f"ERROR: Transcript file not found: {TRANSCRIPT_FILE}")
    exit(1)

with open(TRANSCRIPT_FILE, "rb") as f:
    computed_hash = hashlib.sha256(f.read()).hexdigest()

print(f"Computed SHA-256:   {computed_hash}")
print(f"Receipt SHA-256:    {transcript_hash}")

sha_match = computed_hash == transcript_hash
print(f"SHA-256 Match:      {'YES' if sha_match else 'NO'}")

if not sha_match:
    print("TRANSCRIPT TAMPERED OR MISMATCH!")
    exit(1)

# cert check
if not os.path.exists(CERT_FILE):
    print(f"ERROR: Cert not found: {CERT_FILE}")
    exit(1)

with open(CERT_FILE, "rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())
pub = cert.public_key()

# verify
msg = (
    bytes.fromhex(transcript_hash)
)
verified = verify_sig_rsa(pub, msg, sig_b64)  
print(f"Signature Valid:    {verified}")

if sha_match and verified:
    print("\nNON-REPUDIATION VERIFIED: Transcript is authentic and untampered!")
else:
    print("\nVERIFICATION FAILED!")